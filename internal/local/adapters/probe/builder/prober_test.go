package builder

import (
	"fmt"
	"go/ast"
	"os"
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

// -- enumerateExportedFuncs --

func TestEnumerateExportedFuncs_SkipsUnexportedFuncs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pkg.go", `package mypkg

func Exported() {}
func unexported() {}
`)
	pkgs := []goListPackage{{ImportPath: "example.com/mypkg", Dir: dir, GoFiles: []string{"pkg.go"}}}
	result, err := enumerateExportedFuncs(pkgs)
	if err != nil {
		t.Fatalf("enumerateExportedFuncs: %v", err)
	}
	funcs := result["example.com/mypkg"]
	if len(funcs) != 1 {
		t.Fatalf("funcs = %d, want 1 (only Exported)", len(funcs))
	}
	if funcs[0].name != "Exported" {
		t.Errorf("func name = %q, want Exported", funcs[0].name)
	}
}

func TestEnumerateExportedFuncs_SkipsMethodsOnUnexportedTypes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pkg.go", `package mypkg

type Exported struct{}
type unexported struct{}

func (e Exported) Method() {}
func (u unexported) Method() {}
`)
	pkgs := []goListPackage{{ImportPath: "example.com/mypkg", Dir: dir, GoFiles: []string{"pkg.go"}}}
	result, err := enumerateExportedFuncs(pkgs)
	if err != nil {
		t.Fatalf("enumerateExportedFuncs: %v", err)
	}
	funcs := result["example.com/mypkg"]
	if len(funcs) != 1 {
		t.Fatalf("funcs = %d, want 1 (only method on Exported type)", len(funcs))
	}
	if funcs[0].receiver != "Exported" || funcs[0].name != "Method" {
		t.Errorf("unexpected func %+v", funcs[0])
	}
}

func TestEnumerateExportedFuncs_PointerReceiverPreserved(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pkg.go", `package mypkg

type MyType struct{}

func (m *MyType) PtrMethod() {}
func (m MyType) ValMethod() {}
`)
	pkgs := []goListPackage{{ImportPath: "example.com/mypkg", Dir: dir, GoFiles: []string{"pkg.go"}}}
	result, err := enumerateExportedFuncs(pkgs)
	if err != nil {
		t.Fatalf("enumerateExportedFuncs: %v", err)
	}
	funcs := result["example.com/mypkg"]
	if len(funcs) != 2 {
		t.Fatalf("funcs = %d, want 2", len(funcs))
	}

	byName := make(map[string]exportedFunc)
	for _, f := range funcs {
		byName[f.name] = f
	}
	if byName["PtrMethod"].receiver != "*MyType" {
		t.Errorf("PtrMethod receiver = %q, want *MyType", byName["PtrMethod"].receiver)
	}
	if byName["ValMethod"].receiver != "MyType" {
		t.Errorf("ValMethod receiver = %q, want MyType", byName["ValMethod"].receiver)
	}
}

func TestEnumerateExportedFuncs_SkipsTestFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pkg.go", `package mypkg

func Real() {}
`)
	writeFile(t, dir, "pkg_test.go", `package mypkg

func TestOnly() {}
`)
	pkgs := []goListPackage{{
		ImportPath: "example.com/mypkg",
		Dir:        dir,
		GoFiles:    []string{"pkg.go", "pkg_test.go"},
	}}
	result, err := enumerateExportedFuncs(pkgs)
	if err != nil {
		t.Fatalf("enumerateExportedFuncs: %v", err)
	}
	funcs := result["example.com/mypkg"]
	for _, f := range funcs {
		if f.name == "TestOnly" {
			t.Error("TestOnly from _test.go file should have been skipped")
		}
	}
}

func TestEnumerateExportedFuncs_EmptyPackage(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pkg.go", `package mypkg
`)
	pkgs := []goListPackage{{ImportPath: "example.com/mypkg", Dir: dir, GoFiles: []string{"pkg.go"}}}
	result, err := enumerateExportedFuncs(pkgs)
	if err != nil {
		t.Fatalf("enumerateExportedFuncs: %v", err)
	}
	if len(result["example.com/mypkg"]) != 0 {
		t.Error("expected no exported funcs in empty package")
	}
}

// -- receiverTypeName --

func TestReceiverTypeName_Ident(t *testing.T) {
	expr := &ast.Ident{Name: "MyType"}
	got := receiverTypeName(expr)
	if got != "MyType" {
		t.Errorf("receiverTypeName(Ident) = %q, want MyType", got)
	}
}

func TestReceiverTypeName_StarIdent(t *testing.T) {
	expr := &ast.StarExpr{X: &ast.Ident{Name: "MyType"}}
	got := receiverTypeName(expr)
	if got != "*MyType" {
		t.Errorf("receiverTypeName(StarExpr) = %q, want *MyType", got)
	}
}

func TestReceiverTypeName_IndexExpr_OneTypeParam(t *testing.T) {
	// Generic type with one type parameter: type Stack[T any] struct{}
	// The receiver expression is IndexExpr{X: Ident("Stack"), Index: Ident("T")}.
	expr := &ast.IndexExpr{
		X:     &ast.Ident{Name: "Stack"},
		Index: &ast.Ident{Name: "T"},
	}
	got := receiverTypeName(expr)
	if got != "Stack" {
		t.Errorf("receiverTypeName(IndexExpr) = %q, want Stack", got)
	}
}

func TestReceiverTypeName_IndexListExpr_MultipleTypeParams(t *testing.T) {
	// Generic type with multiple type parameters: type Pair[K, V any] struct{}
	// The receiver expression is IndexListExpr{X: Ident("Pair"), Indices: [...]}.
	expr := &ast.IndexListExpr{
		X:       &ast.Ident{Name: "Pair"},
		Indices: []ast.Expr{&ast.Ident{Name: "K"}, &ast.Ident{Name: "V"}},
	}
	got := receiverTypeName(expr)
	if got != "Pair" {
		t.Errorf("receiverTypeName(IndexListExpr) = %q, want Pair", got)
	}
}

func TestReceiverTypeName_StarNonIdent_ReturnsEmpty(t *testing.T) {
	// StarExpr whose X is not an Ident (unusual but should return "").
	expr := &ast.StarExpr{X: &ast.StarExpr{X: &ast.Ident{Name: "Nested"}}}
	got := receiverTypeName(expr)
	if got != "" {
		t.Errorf("receiverTypeName(StarExpr with non-Ident X) = %q, want empty", got)
	}
}

func TestReceiverTypeName_UnknownExpr_ReturnsEmpty(t *testing.T) {
	// An expression type that receiverTypeName doesn't handle.
	expr := &ast.SelectorExpr{X: &ast.Ident{Name: "pkg"}, Sel: &ast.Ident{Name: "Type"}}
	got := receiverTypeName(expr)
	if got != "" {
		t.Errorf("receiverTypeName(SelectorExpr) = %q, want empty", got)
	}
}

// -- helpers --

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := dir + "/" + name
	if err := writeTestFile(path, content); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}

func writeTestFile(path, content string) error {
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
