package tinylower

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// Site is one runtime call the compiler emits inside a function: the operation
// and the position of the instruction it lowers.
type Site struct {
	Pos token.Pos
	Op  Op
}

// Config is what TinyGo's lowering reads from the build rather than the source.
type Config struct {
	// Sizes are the target's type sizes. Heap allocation and print depend on them.
	Sizes types.Sizes
	// Scheduler is the value of the frame's scheduler.* build tag.
	Scheduler string
	// Recover is whether the target supports recover, which decides whether a
	// function with a recover point builds a defer frame (defer.go:28).
	Recover bool
	// Unwind is the value of the frame's tinygo.unwind.* build tag: how a panic
	// unwinds. A release that sets no such tag leaves it empty.
	Unwind string
}

// returnUnwind is usesReturnUnwind (defer.go:39 at 0.43.0): a panic returns
// through each frame instead of jumping to the landing pad.
func (c Config) returnUnwind() bool { return c.Unwind == "asyncify" || c.Unwind == "explicit" }

// maxStackAlloc is the smaller of TinyGo's two stack-allocation limits
// (compileopts/config.go:226); a target with a larger stack is over-approximated.
const maxStackAlloc = 256

// Lowering is one release's lowering under one build. It holds what TinyGo
// works out once per program: which functions a call can unwind through.
type Lowering struct {
	table *Table
	cfg   Config
	props map[*ssa.Function]callProps
}

// Lowering returns the release's lowering under cfg.
func (t *Table) Lowering(cfg Config) *Lowering {
	return &Lowering{table: t, cfg: cfg, props: make(map[*ssa.Function]callProps)}
}

// Sites returns the runtime calls TinyGo emits for fn's instructions, in
// instruction order. A function without a body has none.
func (l *Lowering) Sites(fn *ssa.Function) []Site {
	w := &walker{cfg: l.cfg, fn: fn, low: l}
	w.readPragmas()
	if w.wasmExport != "" {
		w.add(fn.Pos(), OpWasmExportCheckRun)
		if l.cfg.Scheduler != "none" {
			w.add(fn.Pos(), OpWasmExportRun, OpWasmExportExit)
		}
	}
	if w.deferFrame() {
		w.add(fn.Pos(), OpDeferSetup)
		if l.cfg.returnUnwind() {
			w.add(fn.Pos(), OpUnwindClear) // the landing pad, defer.go:95 at 0.43.0
		}
	}
	w.body = fn.Blocks != nil && !isUnwindRuntime(fn, l.cfg)
	loops := blocksInLoops(fn)
	for _, b := range fn.Blocks {
		for _, in := range b.Instrs {
			w.instr(in, loops[b.Index])
		}
	}
	return w.sites
}

type walker struct {
	cfg        Config
	fn         *ssa.Function
	low        *Lowering
	sites      []Site
	noBounds   bool
	noHeap     bool
	wasmExport string
	// body is whether an invoke here gets the post-call unwind check; the
	// runtime's own unwind helpers do not (calls.go:527 at 0.43.0).
	body bool
	// runningDefers is set while a deferred call is lowered, which runs inside
	// createRunDefers and so gets no post-call check.
	runningDefers bool
}

func (w *walker) add(pos token.Pos, ops ...Op) {
	for _, op := range ops {
		w.sites = append(w.sites, Site{Pos: pos, Op: op})
		if runtimeInvokes[op] {
			w.invoked(pos, true)
		}
	}
}

// readPragmas reads the directives TinyGo's parsePragmas acts on (symbol.go:375)
// that change what it emits. An instantiation reads its origin's, as TinyGo does.
func (w *walker) readPragmas() {
	fn := w.fn
	if o := fn.Origin(); o != nil {
		fn = o
	}
	decl, ok := fn.Syntax().(*ast.FuncDecl)
	if !ok || decl.Doc == nil || fn.Blocks == nil {
		return
	}
	for _, c := range decl.Doc.List {
		// A comment's text keeps its // or /*, so fields is never empty.
		fields := strings.Fields(c.Text)
		switch fields[0] {
		case "//go:nobounds":
			w.noBounds = true
		case "//go:noheap":
			w.noHeap = true
		case "//go:wasmexport":
			if len(fields) == 2 {
				w.wasmExport = fields[1]
			}
		}
	}
}

func (w *walker) deferFrame() bool { return w.fn.Recover != nil && w.cfg.Recover }

func (w *walker) instr(in ssa.Instruction, inLoop bool) {
	if w.value(in) {
		return
	}
	switch v := in.(type) {
	case *ssa.Store:
		if w.sizeof(v.Val.Type()) != 0 {
			w.nilCheck(v.Pos(), v.Addr)
		}
	case *ssa.MapUpdate:
		w.add(v.Pos(), mapOp(mapKey(v.Map.Type()), OpMapSetString, OpMapSetBinary, OpMapSetGeneric))
	case *ssa.Panic:
		w.add(v.Pos(), OpPanic)
	case *ssa.Send:
		w.add(v.Pos(), OpChanSend)
	case *ssa.Return:
		if w.deferFrame() {
			w.add(v.Pos(), OpDeferDestroy)
			if w.cfg.returnUnwind() {
				w.add(v.Pos(), OpUnwindCheck) // compiler.go:1619 at 0.43.0
			}
		}
	case *ssa.RunDefers:
		w.runDefers(v.Pos())
	case *ssa.Go:
		w.goStmt(v)
	case *ssa.Defer:
		w.deferStmt(v, inLoop)
	}
}

// value lowers the instructions that are also values, reporting whether in was one.
func (w *walker) value(in ssa.Instruction) bool {
	switch v := in.(type) {
	case *ssa.Alloc:
		w.alloc(v)
	case *ssa.Call:
		w.call(v.Pos(), v.Common())
	case *ssa.BinOp:
		w.binOp(v)
	case *ssa.UnOp:
		w.unOp(v)
	case *ssa.Convert:
		w.convert(v)
	case *ssa.FieldAddr:
		w.nilCheck(v.Pos(), v.X)
	case *ssa.Index:
		w.index(v)
	case *ssa.IndexAddr:
		w.indexAddr(v)
	case *ssa.Lookup:
		w.lookup(v)
	default:
		return w.makeValue(in)
	}
	return true
}

// makeValue lowers the instructions that make or select a value.
func (w *walker) makeValue(in ssa.Instruction) bool {
	switch v := in.(type) {
	case *ssa.MakeChan:
		w.add(v.Pos(), OpChanMake)
		if _, ok := v.Size.(*ssa.Const); !ok && !w.noBounds {
			w.add(v.Pos(), OpChanMakePanic)
		}
	case *ssa.MakeClosure:
		w.pack(v.Pos(), valueTypes(v.Bindings), false)
	case *ssa.MakeInterface:
		_, isConst := v.X.(*ssa.Const)
		w.pack(v.Pos(), []types.Type{v.X.Type()}, isConst)
	case *ssa.MakeMap:
		w.makeMap(v)
	case *ssa.MakeSlice:
		w.makeSlice(v)
	case *ssa.Next:
		if v.IsString {
			w.add(v.Pos(), OpStringNext)
		} else {
			w.add(v.Pos(), OpMapNext)
		}
	case *ssa.Select:
		w.selectStmt(v)
	case *ssa.Slice:
		w.slice(v)
	case *ssa.SliceToArrayPointer:
		w.add(v.Pos(), OpSliceToArrayPanic)
	case *ssa.TypeAssert:
		w.typeAssert(v)
	default:
		return false
	}
	return true
}

// Callees is the release's Callees.
func (l *Lowering) Callees(op Op) []Callee { return l.table.Callees(op) }
