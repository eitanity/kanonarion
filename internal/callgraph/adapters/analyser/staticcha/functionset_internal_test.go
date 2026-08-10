package staticcha

import (
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// aliasModule reproduces the shape the standard library has around
// os.FileMode: a named type with a String method on the value receiver,
// declared in one package and re-exported as an alias from another, with both
// packages converting it to an interface. The two spellings are one type, so
// the enumeration that de-duplicates on type identity can consume the entry for
// one spelling and then never derive the pointer type from the other.
var aliasModule = map[string]string{
	"go.mod": "module example.com/aliasmod\n\ngo 1.22\n",
	"base/base.go": `package base

type Mode uint32

func (m Mode) String() string { return "mode" }

type Stringish interface{ String() string }

func UseBase(m Mode) Stringish { return m }
`,
	"reexport/reexport.go": `package reexport

import "example.com/aliasmod/base"

type Mode = base.Mode

func UseAlias(m Mode) base.Stringish { return m }
`,
	"app/app.go": `package app

import (
	"example.com/aliasmod/base"
	"example.com/aliasmod/reexport"
)

func Run(m base.Mode, n reexport.Mode) string {
	return base.UseBase(m).String() + reexport.UseAlias(n).String()
}
`,
}

func buildAliasProg(t *testing.T) *ssa.Program {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range aliasModule {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedSyntax | packages.NeedTypes |
			packages.NeedTypesInfo | packages.NeedFiles | packages.NeedImports | packages.NeedDeps,
		Dir:  dir,
		Fset: fset,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		t.Skipf("packages.Load failed (no Go env?): %v", err)
	}
	if len(pkgs) == 0 {
		t.Skip("no packages loaded")
	}

	prog := ssa.NewProgram(fset, ssa.BuilderMode(0))
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.Types == nil || len(p.Errors) > 0 {
			return
		}
		if prog.Package(p.Types) != nil {
			return
		}
		ssaPkg := prog.CreatePackage(p.Types, p.Syntax, p.TypesInfo, true)
		ssaPkg.Build()
	})
	return prog
}

// TestRuntimeTypeClosure_DerivesPointerThroughAnAlias is the property the
// analyser's reproducibility rests on. A named type re-exported under an alias
// is one type under two spellings; the pointer to it carries its own method set
// and is only ever derived from the named spelling. Losing that derivation loses
// the pointer-receiver method wrapper, and with it every interface call site the
// class hierarchy would have resolved to the wrapper.
func TestRuntimeTypeClosure_DerivesPointerThroughAnAlias(t *testing.T) {
	prog := buildAliasProg(t)

	var found bool
	for _, T := range runtimeTypeClosure(prog) {
		ptr, ok := T.(*types.Pointer)
		if !ok {
			continue
		}
		named, ok := types.Unalias(ptr.Elem()).(*types.Named)
		if ok && named.Obj().Name() == "Mode" && strings.HasSuffix(named.Obj().Pkg().Path(), "/base") {
			found = true
		}
	}
	if !found {
		t.Fatal("the closure does not contain *base.Mode: the pointer type was not derived through the alias")
	}
}

// TestRuntimeTypeClosure_IsTheSameSetEveryCall pins the whole point of
// re-deriving the closure: one unchanged program answers once. The library
// enumeration this replaces returns a different set on successive calls to one
// program.
func TestRuntimeTypeClosure_IsTheSameSetEveryCall(t *testing.T) {
	prog := buildAliasProg(t)

	first := typeStrings(runtimeTypeClosure(prog))
	for i := range 5 {
		got := typeStrings(runtimeTypeClosure(prog))
		if len(got) != len(first) {
			t.Fatalf("call %d returned %d types, the first returned %d", i+2, len(got), len(first))
		}
		for k := range first {
			if !got[k] {
				t.Fatalf("call %d dropped %s", i+2, k)
			}
		}
	}
}

// TestClosedFunctionSet_IsTheSameSetEveryCall states the same property one
// level up: the functions an analysis may see are a function of the program.
func TestClosedFunctionSet_IsTheSameSetEveryCall(t *testing.T) {
	prog := buildAliasProg(t)

	first := closedFunctionSet(prog)
	for i := range 5 {
		got := closedFunctionSet(prog)
		if len(got) != len(first) {
			t.Fatalf("call %d returned %d functions, the first returned %d", i+2, len(got), len(first))
		}
		for fn := range first {
			if !got[fn] {
				t.Fatalf("call %d dropped %s", i+2, fn)
			}
		}
	}
}

// TestClosedFunctionSet_HoldsThePointerReceiverWrapper checks the function the
// closure exists to reach is really materialised: the wrapper that adapts the
// value-receiver method to the pointer type.
func TestClosedFunctionSet_HoldsThePointerReceiverWrapper(t *testing.T) {
	prog := buildAliasProg(t)

	var found bool
	for fn := range closedFunctionSet(prog) {
		if strings.HasSuffix(fn.String(), "base.Mode).String") && strings.Contains(fn.String(), "*") {
			found = true
		}
	}
	if !found {
		t.Fatal("the closed function set has no (*base.Mode).String wrapper")
	}
}

// TestOrderedFunctions_IsAFixedSequence checks the sweep order is decided by
// the functions themselves rather than by map iteration.
func TestOrderedFunctions_IsAFixedSequence(t *testing.T) {
	prog := buildAliasProg(t)
	funcs := closedFunctionSet(prog)

	first := orderedFunctions(funcs)
	for i := range 5 {
		got := orderedFunctions(funcs)
		if len(got) != len(first) {
			t.Fatalf("call %d returned %d functions, the first returned %d", i+2, len(got), len(first))
		}
		for j := range first {
			if got[j] != first[j] {
				t.Fatalf("call %d differs at position %d: %s, want %s", i+2, j, got[j], first[j])
			}
		}
	}
}

func typeStrings(ts []types.Type) map[string]bool {
	out := make(map[string]bool, len(ts))
	for _, t := range ts {
		out[t.String()] = true
	}
	return out
}
