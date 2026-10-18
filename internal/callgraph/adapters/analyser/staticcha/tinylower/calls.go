package tinylower

import (
	"go/token"
	"go/types"

	"golang.org/x/tools/go/ssa"
)

// call lowers a call instruction: a builtin is createBuiltin (compiler.go:1836),
// a call through a func value carries a nil check (compiler.go:2323).
func (w *walker) call(pos token.Pos, c *ssa.CallCommon) {
	if b, ok := c.Value.(*ssa.Builtin); ok {
		w.builtin(pos, b.Name(), c.Args)
		return
	}
	if c.IsInvoke() || c.StaticCallee() != nil {
		return
	}
	w.nilCheck(pos, c.Value)
}

func (w *walker) builtin(pos token.Pos, name string, args []ssa.Value) {
	if w.containerBuiltin(pos, name, args) {
		return
	}
	switch name {
	case "append":
		w.add(pos, OpAppend)
	case "min", "max":
		if b, ok := args[0].Type().Underlying().(*types.Basic); ok && b.Info()&types.IsString != 0 && len(args) > 1 {
			w.add(pos, OpStringLess)
		}
	case "panic":
		w.add(pos, OpPanic)
	case "recover":
		w.add(pos, OpRecover)
	case "print", "println":
		w.print(pos, name == "println", args)
	case "Slice", "String": // unsafe.Slice, unsafe.String: compiler.go:2178
		w.add(pos, OpUnsafeSlicePanic)
	}
}

// containerBuiltin lowers the builtins that act on a map or channel, reporting
// whether name was one.
func (w *walker) containerBuiltin(pos token.Pos, name string, args []ssa.Value) bool {
	switch name {
	case "cap":
		if isChan(args[0].Type()) {
			w.add(pos, OpChanCap)
		}
	case "len":
		switch args[0].Type().Underlying().(type) {
		case *types.Chan:
			w.add(pos, OpChanLen)
		case *types.Map:
			w.add(pos, OpMapLen)
		}
	case "close":
		w.add(pos, OpChanClose)
	case "clear":
		if keyOf(args[0].Type()) != nil {
			w.add(pos, OpMapClear)
		}
	case "delete":
		w.add(pos, mapOp(mapKey(args[0].Type()), OpMapDeleteString, OpMapDeleteBinary, OpMapDeleteGeneric))
	default:
		return false
	}
	return true
}

func isChan(t types.Type) bool {
	_, ok := t.Underlying().(*types.Chan)
	return ok
}

// print is the print and println case of createBuiltin (compiler.go:2059).
func (w *walker) print(pos token.Pos, ln bool, args []ssa.Value) {
	w.add(pos, OpPrintLock)
	for i, a := range args {
		if i > 0 && ln {
			w.add(pos, OpPrintSpace)
		}
		if op, ok := w.printOp(types.Default(a.Type())); ok {
			w.add(pos, op)
		}
	}
	if ln {
		w.add(pos, OpPrintNewline)
	}
	w.add(pos, OpPrintUnlock)
}

var printInts = map[bool]map[int64]Op{
	false: {1: OpPrintInt8, 2: OpPrintInt16, 4: OpPrintInt32, 8: OpPrintInt64},
	true:  {1: OpPrintUint8, 2: OpPrintUint16, 4: OpPrintUint32, 8: OpPrintUint64},
}

func (w *walker) printOp(t types.Type) (Op, bool) {
	switch u := t.Underlying().(type) {
	case *types.Basic:
		switch {
		case u.Info()&types.IsString != 0:
			return OpPrintString, true
		case u.Kind() == types.Uintptr || u.Kind() == types.UnsafePointer:
			return OpPrintPointer, true
		case u.Info()&types.IsInteger != 0:
			op, ok := printInts[u.Info()&types.IsUnsigned != 0][w.sizeof(u)]
			return op, ok
		case u.Info()&types.IsBoolean != 0:
			return OpPrintBool, true
		case u.Kind() == types.Float32:
			return OpPrintFloat32, true
		case u.Kind() == types.Float64:
			return OpPrintFloat64, true
		case u.Kind() == types.Complex64:
			return OpPrintComplex64, true
		case u.Kind() == types.Complex128:
			return OpPrintComplex128, true
		}
	case *types.Interface:
		return OpPrintInterface, true
	case *types.Map:
		return OpPrintMap, true
	case *types.Pointer:
		return OpPrintPointer, true
	case *types.Slice:
		return OpPrintSlice, true
	}
	return "", false
}

// goStmt is createGo (goroutine.go:16). The goroutine's own function is already
// a call edge; what TinyGo adds is the task start, the packed arguments and,
// under asyncify, the wrapper's exit (goroutine.go:315).
func (w *walker) goStmt(v *ssa.Go) {
	c := v.Common()
	if b, ok := c.Value.(*ssa.Builtin); ok {
		if b.Name() != "recover" {
			w.builtin(v.Pos(), b.Name(), c.Args)
		}
		return
	}
	params := valueTypes(c.Args)
	ptr := types.Typ[types.UnsafePointer]
	switch {
	case c.IsInvoke():
		params = append(params, ptr, ptr)
	case c.StaticCallee() == nil:
		params = append(params, ptr, ptr)
	default:
		if _, ok := c.Value.(*ssa.MakeClosure); ok {
			params = append(params, ptr)
		}
	}
	w.pack(v.Pos(), params, allConst(c.Args) && len(params) == len(c.Args))
	w.add(v.Pos(), OpGoStart)
	if w.cfg.Scheduler == "asyncify" {
		w.add(v.Pos(), OpGoExit)
	}
}

func allConst(vs []ssa.Value) bool {
	for _, v := range vs {
		if !isConst(v) {
			return false
		}
	}
	return true
}

// deferStmt is createDefer (defer.go:410): a deferred builtin is lowered when
// the defers run, and a defer inside a loop allocates its record on the heap
// (defer.go:542).
func (w *walker) deferStmt(v *ssa.Defer, inLoop bool) {
	c := v.Common()
	if b, ok := c.Value.(*ssa.Builtin); ok {
		w.builtin(v.Pos(), b.Name(), c.Args)
	}
	if inLoop {
		w.heapAlloc(v.Pos(), false)
	}
}

// blocksInLoops reports, by block index, whether a block can reach itself.
func blocksInLoops(fn *ssa.Function) []bool {
	out := make([]bool, len(fn.Blocks))
	for _, b := range fn.Blocks {
		seen := make([]bool, len(fn.Blocks))
		stack := append([]*ssa.BasicBlock(nil), b.Succs...)
		for len(stack) > 0 {
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if n == b {
				out[b.Index] = true
				break
			}
			if seen[n.Index] {
				continue
			}
			seen[n.Index] = true
			stack = append(stack, n.Succs...)
		}
	}
	return out
}
