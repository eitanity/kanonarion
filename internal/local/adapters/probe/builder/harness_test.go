package builder

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	localdomain "github.com/eitanity/kanonarion/internal/local/domain"
)

const goMod127 = "module example.com/probe\n\ngo 1.27\n"

// loadExports lists a module written from files with export data, as the
// library probe does, and returns the workspace packages and an importer.
func loadExports(t *testing.T, files map[string]string) ([]goListPackage, []goListPackage, types.Importer) {
	t.Helper()
	root := writeModule(t, files)
	all, err := listWorkspaceExports(context.Background(), goenv.NewToolchains(), root, "go")
	if err != nil {
		t.Fatalf("listWorkspaceExports: %v", err)
	}
	var work []goListPackage
	for _, p := range all {
		if !p.DepOnly {
			work = append(work, p)
		}
	}
	return all, work, exportImporter(all)
}

func enumerate(t *testing.T, src string) ([]exportedFunc, []localdomain.HarnessOmission) {
	t.Helper()
	_, work, imp := loadExports(t, map[string]string{"go.mod": goMod127, "lib/lib.go": src})
	exports, omitted, err := enumerateExportedFuncs(work, imp)
	if err != nil {
		t.Fatalf("enumerateExportedFuncs: %v", err)
	}
	return exports["example.com/probe/lib"], omitted
}

func byName(funcs []exportedFunc) map[string]exportedFunc {
	m := make(map[string]exportedFunc, len(funcs))
	for _, f := range funcs {
		m[f.name] = f
	}
	return m
}

// -- enumerateExportedFuncs --

func TestEnumerateExportedFuncs_SkipsUnexportedFuncs(t *testing.T) {
	funcs, _ := enumerate(t, "package lib\n\nfunc Exported() {}\nfunc unexported() {}\n")
	if len(funcs) != 1 || funcs[0].name != "Exported" {
		t.Fatalf("funcs = %+v, want Exported alone", funcs)
	}
}

func TestEnumerateExportedFuncs_SkipsMethodsOnUnexportedTypes(t *testing.T) {
	funcs, _ := enumerate(t, `package lib

type Exported struct{}
type unexported struct{}

func (e Exported) Method() {}
func (u unexported) Method() {}
`)
	if len(funcs) != 1 || funcs[0].receiver != "Exported" || funcs[0].name != "Method" {
		t.Fatalf("funcs = %+v, want the method on Exported alone", funcs)
	}
}

func TestEnumerateExportedFuncs_PointerReceiverPreserved(t *testing.T) {
	funcs, _ := enumerate(t, `package lib

type MyType struct{}

func (m *MyType) PtrMethod() {}
func (m MyType) ValMethod() {}
`)
	got := byName(funcs)
	if len(funcs) != 2 || got["PtrMethod"].receiver != "*MyType" || got["ValMethod"].receiver != "MyType" {
		t.Fatalf("funcs = %+v, want *MyType.PtrMethod and MyType.ValMethod", funcs)
	}
}

func TestEnumerateExportedFuncs_SkipsTestFiles(t *testing.T) {
	_, work, imp := loadExports(t, map[string]string{
		"go.mod":          goMod127,
		"lib/lib.go":      "package lib\n\nfunc Real() {}\n",
		"lib/lib_test.go": "package lib\n\nfunc TestOnly() {}\n",
	})
	exports, _, err := enumerateExportedFuncs(work, imp)
	if err != nil {
		t.Fatalf("enumerateExportedFuncs: %v", err)
	}
	if _, ok := byName(exports["example.com/probe/lib"])["TestOnly"]; ok {
		t.Error("TestOnly from a _test.go file should have been skipped")
	}
}

func TestEnumerateExportedFuncs_EmptyPackage(t *testing.T) {
	funcs, omitted := enumerate(t, "package lib\n")
	if len(funcs) != 0 || len(omitted) != 0 {
		t.Errorf("funcs = %+v, omitted = %+v, want neither", funcs, omitted)
	}
}

// Every generic shape is enumerated with type arguments: the parser-based
// enumeration skipped *Box[T] methods and left the others uninstantiated.
func TestEnumerateExportedFuncs_GenericShapes(t *testing.T) {
	funcs, omitted := enumerate(t, `package lib

type Box[T any] struct{ V T }
type Pair[K comparable, V ~string | ~int] struct{ k K; v V }
type Parser struct{}

func Accept[T any](x T) T { return x }
func (b Box[T]) ValAccept() {}
func (b *Box[T]) PtrAccept() {}
func (p *Pair[K, V]) Pair2() {}
func (Parser) Map[T ~string](x T) T { return x }
`)
	if len(omitted) != 0 {
		t.Errorf("omitted = %+v, want none", omitted)
	}
	want := map[string]string{
		"Accept":    "p0.Accept[int]",
		"ValAccept": "(p0.Box[int]).ValAccept",
		"PtrAccept": "(*p0.Box[int]).PtrAccept",
		"Pair2":     "(*p0.Pair[int, string]).Pair2",
		"Map":       "(p0.Parser).Map[string]",
	}
	got := byName(funcs)
	for name, ref := range want {
		ef, ok := got[name]
		if !ok {
			t.Errorf("%s not enumerated", name)
			continue
		}
		if expr := refExpr("p0", ef, nil); expr != ref {
			t.Errorf("%s spelled %q, want %q", name, expr, ref)
		}
	}
}

// The method sets of T and *T include promoted methods; an interface's and an
// alias's methods are not the harness's to keep.
func TestEnumerateExportedFuncs_MethodSetsInterfacesAndAliases(t *testing.T) {
	funcs, _ := enumerate(t, `package lib

type inner struct{}

func (inner) Promoted() {}
func (inner) quiet()    {}

const Limit = 3

var Default = Outer{}

type Outer struct{ inner }
type Iface interface{ Do() }
type Alias = Outer
`)
	if len(funcs) != 1 || funcs[0].receiver != "Outer" || funcs[0].name != "Promoted" {
		t.Fatalf("funcs = %+v, want Outer.Promoted alone", funcs)
	}
}

// A constraint no candidate satisfies names the declaration and the reason.
func TestEnumerateExportedFuncs_MethodBearingConstraintIsNamed(t *testing.T) {
	funcs, omitted := enumerate(t, `package lib

func F[T interface{ M() }](x T) {}

type Box[T interface{ M() }] struct{}

func (Box[T]) Get()  {}
func (*Box[T]) Put() {}
func (Box[T]) hidden() {}

type Parser struct{}

func (Parser) Each[T interface{ M() }](x T) {}
func (Parser) Plain() {}
`)
	got := make(map[string]string, len(omitted))
	for _, o := range omitted {
		got[o.Symbol] = o.Reason
	}
	for _, sym := range []string{
		"example.com/probe/lib.F",
		"example.com/probe/lib.Box.Get",
		"example.com/probe/lib.(*Box).Put",
		"example.com/probe/lib.Parser.Each",
	} {
		if !strings.Contains(got[sym], "no type argument satisfies T interface{M()}") {
			t.Errorf("%s: reason %q, want the unsatisfied constraint named", sym, got[sym])
		}
	}
	if len(omitted) != 4 {
		t.Errorf("omitted = %+v, want 4", omitted)
	}
	if len(funcs) != 1 || funcs[0].name != "Plain" {
		t.Errorf("funcs = %+v, want Parser.Plain alone", funcs)
	}
}

func TestEnumerateExportedFuncs_UnreadableExportDataIsAnError(t *testing.T) {
	bogus := filepath.Join(t.TempDir(), "bogus")
	if err := os.WriteFile(bogus, []byte("not export data"), 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs := []goListPackage{{ImportPath: "example.com/lib", Export: bogus}}
	if _, _, err := enumerateExportedFuncs(pkgs, exportImporter(pkgs)); err == nil {
		t.Fatal("expected an error for unreadable export data")
	}
	missing := []goListPackage{{ImportPath: "example.com/lib", Export: filepath.Join(t.TempDir(), "gone")}}
	if _, _, err := enumerateExportedFuncs(missing, exportImporter(missing)); err == nil {
		t.Fatal("expected an error for a missing export file")
	}
}

// -- chooseTypeArgs --

// typeParams type-checks src and returns the signature of the function F.
func typeParams(t *testing.T, src string) *types.Signature {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", "package p\n\n"+src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	conf := types.Config{Importer: importer.Default()}
	pkg, err := conf.Check("p", fset, []*ast.File{f}, nil)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	fn, ok := pkg.Scope().Lookup("F").(*types.Func)
	if !ok {
		t.Fatal("no func F")
	}
	return fn.Signature()
}

func TestChooseTypeArgs_Shapes(t *testing.T) {
	cases := []struct{ src, want string }{
		{"func F[T any]() {}", "int"},
		{"func F[T comparable, U any]() {}", "int, int"},
		{"func F[T ~int64]() {}", "int64"},
		{"func F[T ~string | ~int]() {}", "string"},
		{"type MyInt int\ntype MyInt2 int\nfunc F[T MyInt | MyInt2]() {}", "p.MyInt"},
		{"type MyInt int\nfunc F[T int | MyInt]() {}", "int"},
		{"func F[S ~[]E, E any]() {}", "[]int, int"},
		{"func F[M ~map[K]V, K comparable, V ~string]() {}", "map[int]string, int, string"},
		{"func F[P ~*T, T any]() {}", "*int, int"},
		{"func F[A ~[2]T, T any]() {}", "[2]int, int"},
		{"func F[C ~chan T, T any]() {}", "chan int, int"},
		{"type Box[T any] struct{}\nfunc F[N ~*Box[T], T any]() {}", "*p.Box[int], int"},
		{"type C interface{ ~int8 }\nfunc F[T interface{ C; comparable }]() {}", "int8"},
		{"func F[T interface{ ~struct{} }]() {}", "struct{}"},
		{"func F[T interface{ int64 }]() {}", "int64"},
		{"type A = int64\nfunc F[T interface{ A }]() {}", "int64"},
		{"func F[T interface{ comparable; ~string }]() {}", "string"},
		{"type Float interface{ ~float32 | ~float64 }\nfunc F[T Float]() {}", "float32"},
		{"func F[T ~float64]() {}", "float64"},
		{"func F[T ~int8 | ~uint16]() {}", "int8"},
		{"type MyFloat float64\nfunc F[T MyFloat | float32]() {}", "p.MyFloat"},
	}
	for _, c := range cases {
		sig := typeParams(t, c.src)
		args, err := chooseTypeArgs(sig.TypeParams(), instantiator(sig))
		if err != nil {
			t.Errorf("%s: %v", c.src, err)
			continue
		}
		if got := typeList(args); got != c.want {
			t.Errorf("%s: args = %s, want %s", c.src, got, c.want)
		}
	}
}

// These are the declarations the rule cannot instantiate. Each is an error that
// names the parameter and what was tried, so the caller can name it.
func TestChooseTypeArgs_Unsatisfiable(t *testing.T) {
	cases := []struct{ src, want string }{
		{"func F[T interface{ M() }]() {}", "no type argument satisfies T interface{M()} (tried int, string, struct{})"},
		{"func F[T interface{ ~int | ~string; M() }]() {}", "no type argument satisfies T interface{M(); ~int | ~string} (tried int, string, struct{})"},
		{"func F[G ~func(T), T any]() {}", "no type argument satisfies G"},
		{"func F[T interface{ ~float64; M() }]() {}", "no type argument satisfies T interface{M(); ~float64} (tried float64, int, string, struct{})"},
	}
	for _, c := range cases {
		sig := typeParams(t, c.src)
		_, err := chooseTypeArgs(sig.TypeParams(), instantiator(sig))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.src, err, c.want)
		}
	}
}

func TestChooseTypeArgs_NonArgumentErrorIsReturned(t *testing.T) {
	sig := typeParams(t, "func F[T any]() {}")
	boom := errors.New("boom")
	_, err := chooseTypeArgs(sig.TypeParams(), func([]types.Type) error { return boom })
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want the validator's own error wrapped", err)
	}
	if args, err := chooseTypeArgs(typeParams(t, "func F() {}").TypeParams(), nil); args != nil || err != nil {
		t.Errorf("a non-generic declaration chose %v, %v", args, err)
	}
}

func TestCoreType_NonInterfaceHasNone(t *testing.T) {
	if _, ok := coreType(types.Typ[types.Int]); ok {
		t.Error("a non-interface constraint reported a core type")
	}
	if got := pick([]types.Type{types.Typ[types.Int]}, 5); got != types.Typ[types.Int] {
		t.Errorf("pick past the end = %v, want the last candidate", got)
	}
}

// -- checkHarness and pruneHarness --

func TestCheckHarness_ReportsByLine(t *testing.T) {
	if bad := checkHarness("package main\n\nfunc main() {}\n", nil, ""); len(bad) != 0 {
		t.Errorf("clean harness: %v", bad)
	}
	bad := checkHarness("package main\n\nfunc main() {\n\t_ = undefinedThing\n}\n", nil, "")
	if !strings.Contains(bad[4], "undefinedThing") {
		t.Errorf("type error: %v, want line 4", bad)
	}
	bad = checkHarness("package main\n\nfunc main() {\n\t_ = (\n}\n", nil, "")
	if len(bad) == 0 {
		t.Error("parse error not reported")
	}
}

// A reference that fails the type check is dropped and named, and the rest of
// the harness is kept; an error off a reference line is the generator's own.
func TestPruneHarness_DropsAndNamesFailingReferences(t *testing.T) {
	_, work, imp := loadExports(t, map[string]string{
		"go.mod":     goMod127,
		"lib/lib.go": "package lib\n\nfunc Real() {}\n",
	})
	exports := map[string][]exportedFunc{"example.com/probe/lib": {{name: "Real"}, {name: "Missing"}}}
	code, omitted, err := pruneHarness(work, exports, imp, "go1.27")
	if err != nil {
		t.Fatalf("pruneHarness: %v", err)
	}
	if !strings.Contains(code, "p0.Real") || strings.Contains(code, "Missing") {
		t.Errorf("harness kept the wrong references:\n%s", code)
	}
	if len(omitted) != 1 || omitted[0].Symbol != "example.com/probe/lib.Missing" ||
		!strings.Contains(omitted[0].Reason, "does not type-check") {
		t.Errorf("omitted = %+v, want lib.Missing named", omitted)
	}

	ghost := []goListPackage{{ImportPath: "example.com/ghost"}}
	_, _, err = pruneHarness(ghost, map[string][]exportedFunc{"example.com/ghost": {{name: "F"}}}, imp, "")
	if err == nil || !strings.Contains(err.Error(), "the generated harness does not type-check at line 4") {
		t.Errorf("err = %v, want the import failure as the generator's own error", err)
	}
}

// -- internal packages --

func TestImportableFrom(t *testing.T) {
	const from = "example.com/m/_kanonarion_probe"
	cases := map[string]bool{
		"example.com/m/lib":                true,
		"example.com/m/internal/y":         true,
		"example.com/m/internal":           true,
		"example.com/m/lib/internal/x":     false,
		"example.com/m/lib/internal":       false,
		"example.com/dep/internal/k":       false,
		"internal/abi":                     false,
		"internal":                         false,
		"example.com/m/internalish/x":      true,
		"example.com/m/a/internal/b/c/d/e": false,
	}
	for path, want := range cases {
		if got := importableFrom(from, path); got != want {
			t.Errorf("importableFrom(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestWithoutUnimportable_OutsideAModuleKeepsEverything(t *testing.T) {
	exports := map[string][]exportedFunc{"example.com/m/lib/internal/x": {{name: "F"}}}
	kept, omitted := withoutUnimportable(exports, "")
	if len(kept["example.com/m/lib/internal/x"]) != 1 || len(omitted) != 0 {
		t.Errorf("kept = %v, omitted = %v, want everything kept", kept, omitted)
	}
	if got := harnessPath([]goListPackage{{ImportPath: "x"}}); got != "" {
		t.Errorf("harnessPath with no module = %q, want empty", got)
	}
}

// go/types does not apply the internal-package rule, so a reference the harness
// may not import passed the type check and stopped the probe at the build. A
// nested internal package and a type argument from another module's internal
// package are each named instead; a root internal package is still referenced.
func TestProbe_LibraryTarget_InternalPackagesTheHarnessCannotImport(t *testing.T) {
	root := writeModule(t, map[string]string{
		"go.mod": "module example.com/probe\n\ngo 1.24\n\nrequire example.com/dep v0.0.0\n\n" +
			"replace example.com/dep => ./dep\n",
		"dep/go.mod":          "module example.com/dep\n\ngo 1.24\n",
		"dep/internal/k/k.go": "package k\n\ntype Kind int\n",
		"dep/pub/pub.go":      "package pub\n\nimport \"example.com/dep/internal/k\"\n\ntype Kind = k.Kind\n",
		"lib/lib.go":          "package lib\n\nimport \"example.com/dep/pub\"\n\nfunc ProbeKind[T interface{ pub.Kind }](x T) {}\n",
		"lib/internal/x/x.go": "package x\n\nfunc ProbeNested() {}\n",
		"internal/y/y.go":     "package y\n\nfunc ProbeRootInternal() {}\n",
	})
	res, err := New("").Probe(context.Background(), root)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	got := make(map[string]string, len(res.HarnessOmitted))
	for _, o := range res.HarnessOmitted {
		got[o.Symbol] = o.Reason
	}
	want := map[string]string{
		"example.com/probe/lib.ProbeKind":              "the harness cannot import internal package example.com/dep/internal/k",
		"example.com/probe/lib/internal/x.ProbeNested": "the harness cannot import internal package example.com/probe/lib/internal/x",
	}
	if len(got) != len(want) {
		t.Errorf("HarnessOmitted = %+v, want %v", res.HarnessOmitted, want)
	}
	for sym, reason := range want {
		if got[sym] != reason {
			t.Errorf("%s: reason %q, want %q", sym, got[sym], reason)
		}
	}
	if !hasSymbolContaining(res.BinarySymbols, "ProbeRootInternal") {
		t.Error("expected ProbeRootInternal retained via synthetic harness")
	}
}

// -- neighbouring shapes --

// randomLibrary writes declarations combining the shapes at random: generic or
// plain types, value or pointer receivers, one or two type parameters, each
// constraint class, and generic methods. It returns the source and the
// declarations no candidate can instantiate, which must be named, not built.
func randomLibrary(r *rand.Rand, pkg string, n int) (string, map[string]bool) {
	constraints := []struct {
		text      string
		satisfied bool
	}{
		{"any", true}, {"comparable", true}, {"~int | ~string", true}, {"~string", true},
		{"Number", true}, {"~[]int", true}, {"~float32 | ~float64", true}, {"interface{ M() }", false},
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "package %s\n\ntype Number interface{ ~int | ~float64 }\n\n", pkg)
	omitted := make(map[string]bool)
	params := func(i int) (decl, use string, ok bool) {
		ok = true
		var ds, us []string
		for j := range 1 + r.IntN(2) {
			c := constraints[r.IntN(len(constraints))]
			ok = ok && c.satisfied
			ds = append(ds, fmt.Sprintf("T%d_%d %s", i, j, c.text))
			us = append(us, fmt.Sprintf("T%d_%d", i, j))
		}
		return "[" + strings.Join(ds, ", ") + "]", "[" + strings.Join(us, ", ") + "]", ok
	}
	for i := range n {
		sym := fmt.Sprintf("example.com/probe/%s.", pkg)
		switch r.IntN(3) {
		case 0: // a function, generic or not
			name, tps := fmt.Sprintf("Fn%d", i), ""
			if r.IntN(2) == 0 {
				var ok bool
				tps, _, ok = params(i)
				if !ok {
					omitted[sym+name] = true
				}
			}
			fmt.Fprintf(&sb, "func %s%s() {}\n", name, tps)
		default: // a method on a generic or plain type, value or pointer receiver
			typ, method := fmt.Sprintf("Ty%d", i), fmt.Sprintf("M%d", i)
			tdecl, tuse, ok := "", "", true
			if r.IntN(2) == 0 {
				tdecl, tuse, ok = params(i)
			}
			fmt.Fprintf(&sb, "type %s%s struct{}\n", typ, tdecl)
			recv, symRecv := typ+tuse, typ
			if r.IntN(2) == 0 {
				recv, symRecv = "*"+recv, "(*"+typ+")"
			}
			own := ""
			if r.IntN(3) == 0 {
				var mok bool
				own, _, mok = params(i + 1000)
				ok = ok && mok
			}
			if !ok {
				omitted[sym+symRecv+"."+method] = true
			}
			fmt.Fprintf(&sb, "func (%s) %s%s() {}\n", recv, method, own)
		}
	}
	return sb.String(), omitted
}

// TestProbe_LibraryTarget_RandomShapes asserts, over random combinations of the
// shapes, that the harness type-checks and builds, that every declaration is
// either in the binary or named, and that only the unsatisfiable are named.
func TestProbe_LibraryTarget_RandomShapes(t *testing.T) {
	for seed := uint64(1); seed <= 3; seed++ {
		r := rand.New(rand.NewPCG(seed, seed)) // #nosec G404 -- a seeded, reproducible shape generator, not a secret
		srcA, omitA := randomLibrary(r, "a", 14)
		srcB, omitB := randomLibrary(r, "b", 14)
		root := writeModule(t, map[string]string{"go.mod": goMod127, "a/a.go": srcA, "b/b.go": srcB})

		res, err := New("").Probe(context.Background(), root)
		if err != nil {
			t.Fatalf("seed %d: Probe: %v\n%s\n%s", seed, err, srcA, srcB)
		}
		want := make([]string, 0, len(omitA)+len(omitB))
		for s := range omitA {
			want = append(want, s)
		}
		for s := range omitB {
			want = append(want, s)
		}
		sort.Strings(want)
		got := make([]string, 0, len(res.HarnessOmitted))
		for _, o := range res.HarnessOmitted {
			got = append(got, o.Symbol)
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("seed %d: omitted\n%s\nwant\n%s\n%s\n%s", seed, strings.Join(got, "\n"), strings.Join(want, "\n"), srcA, srcB)
		}
		for _, src := range []string{srcA, srcB} {
			assertDeclsLinkedOrNamed(t, seed, src, res.BinarySymbols, got)
		}
	}
}

// assertDeclsLinkedOrNamed checks every declared function or method name in
// src is in the symbol table unless it was named as omitted.
func assertDeclsLinkedOrNamed(t *testing.T, seed uint64, src string, symbols map[string]struct{}, omitted []string) {
	t.Helper()
	for line := range strings.SplitSeq(src, "\n") {
		if !strings.HasPrefix(line, "func ") {
			continue
		}
		rest := strings.TrimPrefix(line, "func ")
		if strings.HasPrefix(rest, "(") {
			rest = rest[strings.Index(rest, ") ")+2:]
		}
		name := rest[:strings.IndexAny(rest, "[(")]
		named := false
		for _, o := range omitted {
			named = named || strings.HasSuffix(o, "."+name)
		}
		if !named && !hasSymbolContaining(symbols, "."+name) {
			t.Errorf("seed %d: %s is neither in the binary nor named", seed, name)
		}
	}
}
