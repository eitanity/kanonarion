package tinylower

import (
	"go/token"
	"go/types"

	"golang.org/x/tools/go/ssa"
)

// runtimeInvokes are the ops TinyGo lowers with createRuntimeInvoke, the calls
// a panic can unwind through (map.go:179, map.go:198, map.go:207, map.go:232,
// channel.go:51, channel.go:82, channel.go:108, compiler.go:1620,
// compiler.go:2200, compiler.go:3467, interface.go:1194, asserts.go:278 at
// 0.44.0).
var runtimeInvokes = map[Op]bool{
	OpMapGetGeneric: true, OpMapSetString: true, OpMapSetBinary: true, OpMapSetGeneric: true,
	OpMapDeleteGeneric: true, OpChanSend: true, OpChanClose: true, OpChanTrySend: true,
	OpPanic: true, OpInterfaceEqual: true, OpTypeAssertPanic: true,
	OpLookupPanic: true, OpSlicePanic: true, OpSliceToArrayPanic: true, OpUnsafeSlicePanic: true,
	OpChanMakePanic: true, OpNilPanic: true, OpNegativeShiftPanic: true, OpDivideByZeroPanic: true,
}

// invoked is createInvokeWithAnalysis (calls.go:116 at 0.43.0) for a call that
// may unwind: under asyncify a defer frame wraps it in a catcher, whose runtime
// calls are attributed here, and a function body checks for an unwind after it.
func (w *walker) invoked(pos token.Pos, mayUnwind bool) {
	if !mayUnwind || !w.cfg.returnUnwind() {
		return
	}
	asyncify := w.cfg.Unwind == "asyncify"
	if asyncify && w.deferFrame() {
		w.sites = append(w.sites, Site{Pos: pos, Op: OpAsyncifyCatch})
	}
	if w.body && !w.runningDefers && (!asyncify || w.deferFrame()) {
		w.sites = append(w.sites, Site{Pos: pos, Op: OpUnwindCheck})
	}
}

// runDefers is createRunDefers (defer.go:565 at 0.43.0): each deferred call is
// invoked from the run-defers loop, and each clears a pending unwind after it.
func (w *walker) runDefers(pos token.Pos) {
	if !w.cfg.returnUnwind() {
		return
	}
	w.add(pos, OpUnwindClear)
	for _, b := range w.fn.Blocks {
		for _, in := range b.Instrs {
			d, ok := in.(*ssa.Defer)
			if !ok {
				continue
			}
			if _, builtin := d.Call.Value.(*ssa.Builtin); builtin {
				continue // lowered at the defer statement, see deferStmt
			}
			w.runningDefers = true
			w.invoked(d.Pos(), w.low.callMayUnwind(d.Common()))
			w.runningDefers = false
		}
	}
}

// isUnwindRuntime is the runtime's own unwind machinery, which gets no unwind
// checks (calls.go:537 at 0.43.0).
func isUnwindRuntime(fn *ssa.Function, cfg Config) bool {
	if !cfg.returnUnwind() || fn.Pkg == nil || fn.Pkg.Pkg.Path() != "runtime" {
		return false
	}
	switch fn.Name() {
	case "startUnwind", "currentDeferFrame", "unwindPending", "clearUnwind",
		"getUnwindSignal", "setUnwindSignal", "savePanicReplay",
		"panicRewindData", "panicRewindStackPointer",
		"setPanicRewindStackPointer", "rewindPanic":
		return true
	}
	return false
}

type callProps uint8

const (
	maySuspend callProps = 1 << iota
	mayUnwind
	propsVisiting
	propsDone
	mayBoth = maySuspend | mayUnwind
)

// callMayUnwind is callPropertiesFor (calls.go:439 at 0.43.0).
func (l *Lowering) callMayUnwind(c *ssa.CallCommon) bool {
	callee := c.StaticCallee()
	if callee == nil {
		return true
	}
	return l.functionProps(callee)&mayUnwind != 0
}

// functionProps is functionCallProperties (calls.go:386 at 0.43.0), which
// answers conservatively for a function on the path being analysed.
func (l *Lowering) functionProps(fn *ssa.Function) callProps {
	a := l.props[fn]
	if a&propsDone != 0 {
		return a & mayBoth
	}
	if a&propsVisiting != 0 || len(fn.Blocks) == 0 {
		return mayBoth
	}
	l.props[fn] = propsVisiting
	var p callProps
	if fn.Pkg != nil && fn.Pkg.Pkg.Path() == "internal/task" && fn.Name() == "Pause" {
		p |= maySuspend
	}
	for _, b := range fn.Blocks {
		for _, in := range b.Instrs {
			p |= l.instructionProps(in)
			call, ok := in.(ssa.CallInstruction)
			if !ok {
				continue
			}
			common := call.Common()
			if bi, ok := common.Value.(*ssa.Builtin); ok {
				switch bi.Name() {
				case "close", "delete", "panic":
					p |= mayUnwind
				}
				continue
			}
			if callee := common.StaticCallee(); callee == nil {
				p |= mayBoth
			} else {
				p |= l.functionProps(callee)
			}
			if p == mayBoth {
				break
			}
		}
	}
	l.props[fn] = p | propsDone
	return p
}

// instructionProps is instructionCallProperties (calls.go:455 at 0.43.0). At
// 0.43.0 a BinOp that cannot unwind falls through to the conservative default;
// 0.44.0 returns 0 for it (calls.go:476).
func (l *Lowering) instructionProps(in ssa.Instruction) callProps {
	switch v := in.(type) {
	case *ssa.Alloc, *ssa.Call, *ssa.ChangeInterface, *ssa.ChangeType,
		*ssa.Convert, *ssa.DebugRef, *ssa.Defer, *ssa.Extract, *ssa.Field,
		*ssa.Go, *ssa.If, *ssa.Jump, *ssa.MakeClosure, *ssa.MakeInterface,
		*ssa.MakeMap, *ssa.Phi, *ssa.Range, *ssa.Return, *ssa.RunDefers:
		return 0
	case *ssa.Send, *ssa.Select:
		return mayBoth
	case *ssa.Next:
		return maySuspend
	case *ssa.FieldAddr, *ssa.Index, *ssa.IndexAddr, *ssa.Lookup,
		*ssa.MakeChan, *ssa.MakeSlice, *ssa.MapUpdate, *ssa.Panic,
		*ssa.Slice, *ssa.SliceToArrayPointer, *ssa.Store, *ssa.TypeAssert:
		return mayUnwind
	case *ssa.BinOp:
		if binOpMayUnwind(v) {
			return mayUnwind
		}
		if !l.table.binOpFallsThrough {
			return 0
		}
	case *ssa.UnOp:
		var p callProps
		if v.Op == token.ARROW {
			p |= maySuspend
		}
		if v.Op == token.MUL {
			p |= mayUnwind
		}
		return p
	}
	return mayBoth
}

func binOpMayUnwind(v *ssa.BinOp) bool {
	switch v.Op {
	case token.QUO, token.REM:
		return isInteger(v.X.Type())
	case token.SHL, token.SHR:
		b, ok := v.Y.Type().Underlying().(*types.Basic)
		return ok && b.Info()&types.IsUnsigned == 0
	case token.EQL, token.NEQ:
		return mayPanicOnCompare(v.X.Type())
	}
	return false
}

func mayPanicOnCompare(t types.Type) bool {
	switch u := t.Underlying().(type) {
	case *types.Interface:
		return true
	case *types.Array:
		return mayPanicOnCompare(u.Elem())
	case *types.Struct:
		for i := range u.NumFields() {
			if mayPanicOnCompare(u.Field(i).Type()) {
				return true
			}
		}
	}
	return false
}
