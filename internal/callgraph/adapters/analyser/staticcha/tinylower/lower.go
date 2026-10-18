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
}

// maxStackAlloc is the smaller of TinyGo's two stack-allocation limits
// (compileopts/config.go:226); a target with a larger stack is over-approximated.
const maxStackAlloc = 256

// Sites returns the runtime calls TinyGo emits for fn's instructions, in
// instruction order. A function without a body has none.
func Sites(fn *ssa.Function, cfg Config) []Site {
	w := &walker{cfg: cfg, fn: fn}
	w.readPragmas()
	if w.wasmExport != "" {
		w.add(fn.Pos(), OpWasmExportCheckRun)
		if cfg.Scheduler != "none" {
			w.add(fn.Pos(), OpWasmExportRun, OpWasmExportExit)
		}
	}
	if w.deferFrame() {
		w.add(fn.Pos(), OpDeferSetup)
	}
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
	sites      []Site
	noBounds   bool
	noHeap     bool
	wasmExport string
}

func (w *walker) add(pos token.Pos, ops ...Op) {
	for _, op := range ops {
		w.sites = append(w.sites, Site{Pos: pos, Op: op})
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
		}
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
