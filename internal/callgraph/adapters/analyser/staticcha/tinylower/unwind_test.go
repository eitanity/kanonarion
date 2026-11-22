package tinylower_test

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"slices"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/adapters/analyser/staticcha/tinylower"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

const releaseFixture = `package fx

type withArray struct{ n int; b [8]byte }

func arrayLong(a, b [5]int) bool       { return a == b }
func arrayShort(a, b [4]int) bool      { return a == b }
func arrayInStruct(a, b withArray) bool { return a == b }
func bytesBoth(a, b []byte) bool       { return string(a) == string(b) }
func bytesOne(a []byte) bool           { return string(a) < "x" }
func bytesKept(a []byte) (string, bool) { s := string(a); return s, s == "x" }
func trySend(c chan int)               { select { case c <- 1: default: } }
func tryRecv(c chan int)               { select { case <-c: default: } }
func selectTwo(a, b chan int)          { select { case <-a: case <-b: default: } }

func doPanic()               { panic("x") }
func add(a, b int) int       { return a + b }
func doRecover()             { defer func() { _ = recover() }() }
func deferPanic()            { defer panic("x") }
func deferCall()             { defer println(); doPanic() }
func deferAdd(a int) int     { defer println(); return add(a, 1) }
func deferMethod(e error)    { defer e.Error() }
func noDefer()               { doPanic() }
`

func buildSrc(t *testing.T, path, src string) map[string]*ssa.Function {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fx.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	conf := &types.Config{Importer: importer.Default(), Sizes: thumb}
	pkg, _, err := ssautil.BuildPackage(conf, fset, types.NewPackage(path, path), []*ast.File{f}, ssa.InstantiateGenerics)
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]*ssa.Function)
	for name, m := range pkg.Members {
		if fn, ok := m.(*ssa.Function); ok {
			out[name] = fn
		}
	}
	return out
}

func lowered(t *testing.T, version string, cfg tinylower.Config, fn *ssa.Function) []tinylower.Op {
	t.Helper()
	table, ok := tinylower.ForVersion(version)
	if !ok {
		t.Fatalf("no table for %s", version)
	}
	return sorted(ops(table.Lowering(cfg).Sites(fn)))
}

// Constructs 0.43.0 lowered anew are named as their own ops, so each table
// decides what they call.
func TestSites_ConstructsLoweredAnewAt043(t *testing.T) {
	fns := buildSrc(t, "fx", releaseFixture)
	cfg := tinylower.Config{Sizes: thumb, Scheduler: "tasks", Recover: true}
	tests := map[string][]tinylower.Op{
		"arrayLong":     {tinylower.OpArrayEqual},
		"arrayShort":    nil,
		"arrayInStruct": {tinylower.OpArrayEqual},
		"bytesBoth":     {tinylower.OpStringFromBytesComparedTo, tinylower.OpStringFromBytesComparedTo, tinylower.OpStringEqual},
		"bytesOne":      {tinylower.OpStringFromBytesCompared, tinylower.OpStringLess},
		"bytesKept":     {tinylower.OpStringFromBytes, tinylower.OpStringEqual},
		"trySend":       {tinylower.OpChanTrySend},
		"tryRecv":       {tinylower.OpChanTryRecv},
		"selectTwo":     {tinylower.OpChanSelect},
	}
	for name, want := range tests {
		if got := lowered(t, "0.44.0", cfg, fns[name]); !slices.Equal(got, sorted(want)) {
			t.Errorf("%s: Sites = %v, want %v\n%s", name, got, want, dump(fns[name]))
		}
	}
}

// Under asyncify a function with a defer frame clears and checks for a pending
// unwind, and wraps each call that may unwind in a catcher; whether a BinOp may
// unwind is the release's answer.
func TestSites_AsyncifyUnwind(t *testing.T) {
	fns := buildSrc(t, "fx", releaseFixture)
	cfg := tinylower.Config{Sizes: thumb, Scheduler: "asyncify", Recover: true, Unwind: "asyncify"}
	frame := []tinylower.Op{tinylower.OpDeferSetup, tinylower.OpUnwindClear, tinylower.OpUnwindClear,
		tinylower.OpDeferDestroy, tinylower.OpUnwindCheck, tinylower.OpDeferDestroy, tinylower.OpUnwindCheck}
	with := func(extra ...tinylower.Op) []tinylower.Op { return sorted(append(slices.Clone(frame), extra...)) }
	print := []tinylower.Op{tinylower.OpPrintLock, tinylower.OpPrintNewline, tinylower.OpPrintUnlock}
	catch := []tinylower.Op{tinylower.OpAsyncifyCatch, tinylower.OpUnwindCheck}
	tests := []struct {
		version, fn string
		want        []tinylower.Op
	}{
		{"0.44.0", "doRecover", with()},
		{"0.44.0", "deferPanic", with(tinylower.OpPanic, tinylower.OpAsyncifyCatch)},
		{"0.44.0", "deferCall", with(append(print, catch...)...)},
		{"0.44.0", "deferMethod", with(tinylower.OpAsyncifyCatch)},
		{"0.44.0", "deferAdd", with(print...)},
		{"0.43.0", "deferAdd", with(append(print, catch...)...)},
		{"0.44.0", "noDefer", nil},
	}
	for _, tc := range tests {
		if got := lowered(t, tc.version, cfg, fns[tc.fn]); !slices.Equal(got, tc.want) {
			t.Errorf("%s %s: Sites = %v, want %v\n%s", tc.version, tc.fn, got, tc.want, dump(fns[tc.fn]))
		}
	}
	// A frame without the unwind tag, as 0.42.0's, keeps setjmp: no unwind ops.
	legacy := tinylower.Config{Sizes: thumb, Scheduler: "tasks", Recover: true}
	if got := lowered(t, "0.42.0", legacy, fns["deferCall"]); slices.Contains(got, tinylower.OpUnwindCheck) {
		t.Errorf("deferCall without the unwind tag = %v", got)
	}
}

// Explicit unwinding checks after every call that may unwind, in every function,
// except in the runtime's own unwind helpers.
func TestSites_ExplicitUnwind(t *testing.T) {
	fns := buildSrc(t, "fx", releaseFixture)
	cfg := tinylower.Config{Sizes: thumb, Scheduler: "tasks", Recover: true, Unwind: "explicit"}
	if got := lowered(t, "0.44.0", cfg, fns["noDefer"]); !slices.Equal(got, []tinylower.Op{tinylower.OpUnwindCheck}) {
		t.Errorf("noDefer under explicit = %v, want the post-call check", got)
	}
	rtFns := buildSrc(t, "runtime", `package runtime
func doPanic() { panic("x") }
func savePanicReplay() { doPanic() }
func other() { doPanic() }
`)
	if got := lowered(t, "0.44.0", cfg, rtFns["savePanicReplay"]); len(got) != 0 {
		t.Errorf("runtime.savePanicReplay under explicit = %v, want no check", got)
	}
	if got := lowered(t, "0.44.0", cfg, rtFns["other"]); !slices.Equal(got, []tinylower.Op{tinylower.OpUnwindCheck}) {
		t.Errorf("runtime.other under explicit = %v, want the check", got)
	}
}
