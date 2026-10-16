package builder

import (
	"go/types"
	"strings"
	"testing"
)

// Tests for unexported helpers in the probe builder package.

// -- generateHarness --

func TestGenerateHarness_TopLevelFunc(t *testing.T) {
	pkgs := []goListPackage{
		{ImportPath: "example.com/lib", Name: "lib"},
	}
	exports := map[string][]exportedFunc{
		"example.com/lib": {{name: "DoSomething"}},
	}
	code := generateHarness(pkgs, exports)

	if !strings.Contains(code, `"example.com/lib"`) {
		t.Error("import path not in generated code")
	}
	if !strings.Contains(code, "p0.DoSomething") {
		t.Error("top-level func reference not in generated code")
	}
	if !strings.Contains(code, "package main") {
		t.Error("package main not in generated code")
	}
	if !strings.Contains(code, "func main()") {
		t.Error("func main not in generated code")
	}
}

func TestGenerateHarness_PointerReceiverMethod(t *testing.T) {
	pkgs := []goListPackage{
		{ImportPath: "example.com/lib", Name: "lib"},
	}
	exports := map[string][]exportedFunc{
		"example.com/lib": {{receiver: "*MyType", name: "Method"}},
	}
	code := generateHarness(pkgs, exports)

	// pointer-receiver method expression must be (*p0.MyType).Method.
	// The previous assertion codified the invalid form (p0.*MyType).Method,
	// which is a Go syntax error and broke the library probe build.
	if !strings.Contains(code, "(*p0.MyType).Method") {
		t.Errorf("pointer method reference not in generated code; got:\n%s", code)
	}
	if strings.Contains(code, "(p0.*MyType).Method") {
		t.Errorf("invalid pointer method expression emitted; got:\n%s", code)
	}
}

func TestGenerateHarness_ValueReceiverMethod(t *testing.T) {
	pkgs := []goListPackage{
		{ImportPath: "example.com/lib", Name: "lib"},
	}
	exports := map[string][]exportedFunc{
		"example.com/lib": {{receiver: "MyType", name: "String"}},
	}
	code := generateHarness(pkgs, exports)

	if !strings.Contains(code, "(p0.MyType).String") {
		t.Errorf("value method reference not in generated code; got:\n%s", code)
	}
}

func TestGenerateHarness_PackageWithNoExportsOmittedFromImports(t *testing.T) {
	pkgs := []goListPackage{
		{ImportPath: "example.com/lib", Name: "lib"},
		{ImportPath: "example.com/noexport", Name: "noexport"},
	}
	exports := map[string][]exportedFunc{
		"example.com/lib": {{name: "Func"}},
		// noexport: no entry → should not appear in import block
	}
	code := generateHarness(pkgs, exports)

	if strings.Contains(code, `"example.com/noexport"`) {
		t.Error("package with no exports should not appear in import block")
	}
	if !strings.Contains(code, `"example.com/lib"`) {
		t.Error("package with exports should appear in import block")
	}
}

func TestGenerateHarness_Deterministic(t *testing.T) {
	pkgs := []goListPackage{
		{ImportPath: "example.com/z", Name: "z"},
		{ImportPath: "example.com/a", Name: "a"},
	}
	exports := map[string][]exportedFunc{
		"example.com/z": {{name: "ZFunc"}},
		"example.com/a": {{name: "AFunc"}},
	}

	c1 := generateHarness(pkgs, exports)
	c2 := generateHarness(pkgs, exports)
	if c1 != c2 {
		t.Error("generateHarness is not deterministic")
	}
}

func TestGenerateHarness_SortedByImportPath(t *testing.T) {
	// Packages provided in reverse alphabetical order — harness should sort them.
	pkgs := []goListPackage{
		{ImportPath: "example.com/z", Name: "z"},
		{ImportPath: "example.com/a", Name: "a"},
	}
	exports := map[string][]exportedFunc{
		"example.com/z": {{name: "ZFunc"}},
		"example.com/a": {{name: "AFunc"}},
	}
	code := generateHarness(pkgs, exports)

	posA := strings.Index(code, `"example.com/a"`)
	posZ := strings.Index(code, `"example.com/z"`)
	if posA < 0 || posZ < 0 {
		t.Fatal("expected both imports to be present")
	}
	if posA > posZ {
		t.Error("imports are not sorted: example.com/a should appear before example.com/z")
	}
}

func TestGenerateHarness_EmptyExports(t *testing.T) {
	pkgs := []goListPackage{{ImportPath: "example.com/lib", Name: "lib"}}
	exports := map[string][]exportedFunc{}
	code := generateHarness(pkgs, exports)

	// Should still produce valid package main with no imports.
	if !strings.Contains(code, "package main") {
		t.Error("package main not in generated code")
	}
	if strings.Contains(code, `"example.com/lib"`) {
		t.Error("package with no exports should not be imported")
	}
}

func TestGenerateHarness_SinksSliceDeclared(t *testing.T) {
	pkgs := []goListPackage{{ImportPath: "example.com/lib", Name: "lib"}}
	exports := map[string][]exportedFunc{
		"example.com/lib": {{name: "Func"}},
	}
	code := generateHarness(pkgs, exports)

	if !strings.Contains(code, "var _sinks []interface{}") {
		t.Error("_sinks declaration not found in generated code")
	}
	if !strings.Contains(code, "_sinks = append(_sinks,") {
		t.Error("_sinks append not found in generated code")
	}
}

// Generic declarations cannot be referenced without instantiation, so each
// shape is written with its type arguments.
func TestGenerateHarness_GenericShapes(t *testing.T) {
	pkgs := []goListPackage{{ImportPath: "example.com/lib", Name: "lib"}}
	intT, strT := types.Typ[types.Int], types.Typ[types.String]
	exports := map[string][]exportedFunc{
		"example.com/lib": {
			{name: "Accept", ownArgs: []types.Type{intT}},
			{receiver: "Box", name: "ValAccept", recvArgs: []types.Type{intT}},
			{receiver: "*Box", name: "PtrAccept", recvArgs: []types.Type{intT}},
			{receiver: "*Pair", name: "Pair2", recvArgs: []types.Type{intT, strT}},
			{receiver: "Parser", name: "Map", ownArgs: []types.Type{strT}},
		},
	}
	code := generateHarness(pkgs, exports)
	for _, want := range []string{
		"p0.Accept[int]",
		"(p0.Box[int]).ValAccept",
		"(*p0.Box[int]).PtrAccept",
		"(*p0.Pair[int, string]).Pair2",
		"(p0.Parser).Map[string]",
	} {
		if !strings.Contains(code, want) {
			t.Errorf("%s not in generated code; got:\n%s", want, code)
		}
	}
}

// A type argument naming a package outside the workspace imports it under its
// own alias, and only when a written reference uses it.
func TestGenerateHarness_TypeArgFromAnotherPackageIsImported(t *testing.T) {
	pkgs := []goListPackage{{ImportPath: "example.com/lib", Name: "lib"}}
	other := types.NewPackage("example.com/other", "other")
	named := types.NewNamed(types.NewTypeName(0, other, "Kind", nil), types.Typ[types.Int], nil)
	exports := map[string][]exportedFunc{
		"example.com/lib": {{name: "F", ownArgs: []types.Type{named}}},
	}
	code := generateHarness(pkgs, exports)
	if !strings.Contains(code, `t0 "example.com/other"`) || !strings.Contains(code, "p0.F[t0.Kind]") {
		t.Errorf("type argument from another package not imported and qualified; got:\n%s", code)
	}
	if code := generateHarness(pkgs, map[string][]exportedFunc{}); strings.Contains(code, "example.com/other") {
		t.Errorf("an unused package was imported; got:\n%s", code)
	}
}

// Every reference line maps back to its export, so a reference that fails the
// type check is the one dropped and named.
func TestRenderHarness_LinesMapToReferences(t *testing.T) {
	pkgs := []goListPackage{{ImportPath: "example.com/z"}, {ImportPath: "example.com/a"}}
	exports := map[string][]exportedFunc{
		"example.com/z": {{name: "Z1"}, {name: "Z2"}},
		"example.com/a": {{name: "A1"}},
	}
	code, lines := renderHarness(pkgs, exports)
	src := strings.Split(code, "\n")
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want 3", len(lines))
	}
	for line, ref := range lines {
		ef := exports[ref.pkgPath][ref.index]
		if !strings.Contains(src[line-1], "."+ef.name+")") {
			t.Errorf("line %d = %q, want the reference to %s", line, src[line-1], ef.symbol(ref.pkgPath))
		}
	}
}
