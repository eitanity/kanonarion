package tinycgo_test

import (
	"context"
	"go/constant"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/goenv"
	"code.eitanity.com/kanonarion/internal/callgraph/adapters/analyser/staticcha/tinycgo"
	"code.eitanity.com/kanonarion/internal/callgraph/adapters/analyser/staticcha/tinycgo/tinycgotest"
	"golang.org/x/tools/go/packages"
)

func load(t *testing.T, frame goenv.TinyGo, program string, env []string) (tinycgo.Result, []string) {
	t.Helper()
	var steps []string
	cfg := tinycgo.Config{
		SourceRoot: frame.SourceRoot(), Target: frame.Target(), Triple: frame.LLVMTriple(),
		GOOS: frame.GOOS(), GOARCH: frame.GOARCH(),
		Dir: tinycgotest.Program(t, program), Env: env, BuildFlags: frame.ListArgs(), Tests: true,
		Fset: token.NewFileSet(), Step: func(s string) { steps = append(steps, s) },
	}
	res, err := tinycgo.Load(context.Background(), cfg, "./...")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return res, steps
}

func frameEnv(frame goenv.TinyGo) []string {
	return frame.Apply(append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOFLAGS=", "GOWORK=off"))
}

func errorsByPackage(res tinycgo.Result) map[string][]string {
	out := map[string][]string{}
	packages.Visit(res.Roots, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			out[p.PkgPath] = append(out[p.PkgPath], e.Error())
		}
	})
	return out
}

func tinyGoPackage(t *testing.T, res tinycgo.Result, path string) *packages.Package {
	t.Helper()
	for _, p := range res.TinyGo {
		if p.PkgPath == path {
			return p
		}
	}
	t.Fatalf("%s is not among TinyGo's packages", path)
	return nil
}

// Every kind the translation covers, through clang, type-checks to the Go
// TinyGo declares for it; the package importing "C" for its preamble alone
// never reaches clang, whose #error would otherwise fail it.
func TestLoad_TranslatesEveryCoveredKind(t *testing.T) {
	tinycgotest.RequireClang(t)
	frame := tinycgotest.Frame(t)

	res, steps := load(t, frame, "ok", frameEnv(frame))

	if errs := errorsByPackage(res); len(errs) != 0 {
		t.Fatalf("type errors: %v", errs)
	}
	var tiny []string
	for _, p := range res.TinyGo {
		tiny = append(tiny, p.PkgPath)
	}
	if strings.Join(tiny, " ") != "tinycgofx/full tinycgofx/noref" {
		t.Errorf("TinyGo's packages = %v, want the two the fake TINYGOROOT holds and none of Go's", tiny)
	}
	if len(steps) != 1 || !strings.HasPrefix(steps[0], "C compiler ") {
		t.Errorf("steps = %q, want the compiler named once", steps)
	}

	checkFullDeclarations(t, tinyGoPackage(t, res, "tinycgofx/full").Types.Scope())
	for _, f := range tinyGoPackage(t, res, "tinycgofx/noref").Syntax {
		if name := filepath.Base(frameFile(res, f.Pos())); name == "!cgo.go" {
			t.Errorf("a package referencing no C name was given a generated file")
		}
	}
}

func checkFullDeclarations(t *testing.T, full *types.Scope) {
	t.Helper()
	for name, want := range map[string]constant.Value{
		"Int": constant.MakeInt64(0x10000000), "Name": constant.MakeString("fakeboard"),
		"Expr": constant.MakeInt64(2<<4 | 3), "Auto": constant.MakeInt64(6),
	} {
		c, ok := full.Lookup(name).(*types.Const)
		if !ok || !constant.Compare(c.Val(), token.EQL, want) {
			t.Errorf("%s = %v, want %v", name, full.Lookup(name), want)
		}
	}
	for name, want := range map[string]string{
		"_Cgo_fake_copy":         "func(src *uint8, dst *uint8, n tinycgofx/full._Cgo_size_t)",
		"_Cgo_fake_counter":      "uint32",
		"_Cgo_fake_word":         "uint32",
		"_Cgo_size_t":            "tinycgofx/full._Cgo_uint",
		"_Cgo_uint":              "tinycgofx/full._Cgo_uint",
		"_Cgo_enum_fake_mode":    "tinycgofx/full._Cgo_uint",
		"_Cgo_struct_fake_point": "tinycgofx/full._Cgo_struct_fake_point",
	} {
		obj := full.Lookup(name)
		if obj == nil || types.Unalias(obj.Type()).String() != want {
			t.Errorf("%s: %v, want type %s", name, obj, want)
		}
	}
	point, ok := full.Lookup("_Cgo_struct_fake_point").Type().Underlying().(*types.Struct)
	if !ok || point.String() != "struct{x tinycgofx/full._Cgo_int; y tinycgofx/full._Cgo_int; next *tinycgofx/full._Cgo_struct_fake_point}" {
		t.Errorf("struct fake_point = %v", point)
	}
	if u := full.Lookup("_Cgo_uint").Type().Underlying().String(); u != "uint32" {
		t.Errorf("C.uint is %s on thumbv6m, want uint32", u)
	}
}

func frameFile(res tinycgo.Result, pos token.Pos) string {
	for _, p := range res.Roots {
		if p.Fset != nil {
			return p.Fset.File(pos).Name()
		}
	}
	return ""
}

func TestLoad_APreambleClangRejectsIsNamed(t *testing.T) {
	tinycgotest.RequireClang(t)
	frame := tinycgotest.Frame(t)

	res, _ := load(t, frame, "rejected", frameEnv(frame))

	errs := tinyGoPackage(t, res, "tinycgofx/rejected").Errors
	if len(errs) == 0 || !strings.Contains(errs[0].Error(), "rejected.go: clang rejected the preamble: ") ||
		!strings.Contains(errs[0].Error(), "rejected.go:5:") || !strings.Contains(errs[0].Error(), "error: ") {
		t.Fatalf("errors = %v, want the file and clang's first diagnostic first", errs)
	}
}

func TestLoad_AnUnmappedTypeIsNamedNotGuessed(t *testing.T) {
	tinycgotest.RequireClang(t)
	frame := tinycgotest.Frame(t)

	res, _ := load(t, frame, "unmapped", frameEnv(frame))

	var got []string
	for _, e := range tinyGoPackage(t, res, "tinycgofx/unmapped").Errors {
		got = append(got, e.Error())
	}
	for _, want := range []string{
		"unmapped.go:6:1: #cgo CFLAGS lines are not read by this analysis",
		"unmapped.go: C.fake_complex: _Complex float is a C type this analysis does not translate",
		"unmapped.go: C.struct_bits: struct with the bit field low is a C type this analysis does not translate",
		"unmapped.go: C.union_two: union of 2 fields, which needs accessors is a C type this analysis does not translate",
		`unmapped.go: C.NOT_A_CONSTANT: the macro "__attribute__((unused))" is not a constant this analysis evaluates`,
	} {
		found := false
		for _, g := range got {
			found = found || strings.Contains(g, want)
		}
		if !found {
			t.Errorf("no error says %q:\n%s", want, strings.Join(got, "\n"))
		}
	}
}

// The remaining forms: anonymous typedefs, a one-field union, static and
// variadic functions, function types, array parameters, the errno form, the
// generated helpers and every constant kind; and two files that declare a
// name differently are refused naming it.
func TestLoad_TranslatesTheRemainingForms(t *testing.T) {
	tinycgotest.RequireClang(t)
	frame := tinycgotest.Frame(t)

	res, _ := load(t, frame, "more", frameEnv(frame))

	errs := errorsByPackage(res)
	if len(errs["tinycgofx/more"]) != 0 {
		t.Fatalf("more: %v", errs["tinycgofx/more"])
	}
	conflict := errs["tinycgofx/conflict"]
	if len(conflict) == 0 || !strings.Contains(conflict[0], "shared_t defined previously at") {
		t.Errorf("conflict: %v, want the second definition refused", conflict)
	}
	scope := tinyGoPackage(t, res, "tinycgofx/more").Types.Scope()
	for name, want := range map[string]string{
		"_Cgo_anon_t":              "tinycgofx/more._Cgo__Ctype_struct___0",
		"_Cgo_anon_e":              "tinycgofx/more._Cgo_int",
		"_Cgo_union_one":           "tinycgofx/more._Cgo_union_one",
		"_Cgo_callback_t":          "*[0]byte",
		"_Cgo_handler_t":           "[0]byte",
		"_Cgo_fill":                "func(buf *tinycgofx/more._Cgo_char)",
		"_Cgo_name":                "func(n *tinycgofx/more._Cgo_char)",
		"_Cgo_flag":                "func() bool",
		"_Cgo_ratio":               "func(f float32) float64",
		"_Cgo_opaque":              "func(p *tinycgofx/more._Cgo_struct_never_defined) unsafe.Pointer",
		"_Cgo_sum":                 "func(n tinycgofx/more._Cgo_int) tinycgofx/more._Cgo_int",
		"_Cgo_twice!a.go":          "func(v tinycgofx/more._Cgo_int) tinycgofx/more._Cgo_int",
		"_Cgo_twice!a.go$funcaddr": "unsafe.Pointer",
		"_Cgo_CString":             "func(string) *tinycgofx/more._Cgo_char",
		"_Cgo_char":                "tinycgofx/more._Cgo_char",
	} {
		obj := scope.Lookup(name)
		if obj == nil || types.Unalias(obj.Type()).String() != want {
			t.Errorf("%s: %v, want type %s", name, obj, want)
		}
	}
	if u := scope.Lookup("_Cgo_char").Type().Underlying().String(); u != "uint8" {
		t.Errorf("char is %s on thumbv6m, where it is unsigned", u)
	}
	for name, want := range map[string]constant.Value{
		"Char": constant.MakeInt64('x'), "Float": constant.MakeFloat64(1.5), "Neg": constant.MakeInt64(-3), "Alias": constant.MakeInt64(-3),
	} {
		c, ok := scope.Lookup(name).(*types.Const)
		if !ok || !constant.Compare(c.Val(), token.EQL, want) {
			t.Errorf("%s = %v, want %v", name, scope.Lookup(name), want)
		}
	}
}

// No compiler on PATH fails the file that needs one, by name, and nothing else.
func TestLoad_NoCompilerIsNamed(t *testing.T) {
	frame := tinycgotest.Frame(t)
	bin := t.TempDir()
	goBin, err := filepath.Abs(filepath.Join(frame.GOROOT(), "bin", "go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(goBin, filepath.Join(bin, "go")); err != nil {
		t.Fatal(err)
	}
	env := append(frameEnv(frame), "PATH="+bin)

	res, _ := load(t, frame, "ok", env)

	errs := errorsByPackage(res)
	got := errs["tinycgofx/full"]
	want := "full.go: package tinycgofx/full: no C compiler found on PATH (looked for clang, then clang-<N>)"
	if len(got) == 0 || !strings.HasSuffix(got[0], want) {
		t.Fatalf("errors = %v, want %q first", got, want)
	}
	if len(errs["tinycgofx/noref"]) != 0 {
		t.Errorf("the package referencing no C name failed too: %v", errs["tinycgofx/noref"])
	}
}

func TestLoad_AnUnknownTripleIsRefusedBeforeAnyChild(t *testing.T) {
	_, err := tinycgo.Load(context.Background(), tinycgo.Config{Triple: "sparc-unknown-none", Fset: token.NewFileSet()}, "./...")
	if err == nil || !strings.Contains(err.Error(), "sparc-unknown-none") {
		t.Fatalf("Load = %v", err)
	}
}
