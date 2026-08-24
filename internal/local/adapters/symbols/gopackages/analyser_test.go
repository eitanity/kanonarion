package gopackages

import (
	"context"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"github.com/eitanity/kanonarion/internal/local/domain"
)

// Tests for unexported helpers: qualifiedName and sortedSet.

// -- sortedSet --

func TestSortedSet_ReturnsSortedSlice(t *testing.T) {
	m := map[string]struct{}{
		"github.com/z": {},
		"github.com/a": {},
		"github.com/m": {},
	}
	got := sortedSet(m)
	if !sort.StringsAreSorted(got) {
		t.Errorf("sortedSet result is not sorted: %v", got)
	}
	if len(got) != 3 {
		t.Errorf("len = %d, want 3", len(got))
	}
}

func TestSortedSet_Empty(t *testing.T) {
	got := sortedSet(map[string]struct{}{})
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}

func TestSortedSet_SingleElement(t *testing.T) {
	got := sortedSet(map[string]struct{}{"only": {}})
	if len(got) != 1 || got[0] != "only" {
		t.Errorf("got = %v, want [only]", got)
	}
}

func TestSortedSet_NoDuplicates(t *testing.T) {
	// Maps can't have duplicate keys, so this just verifies every key appears once.
	m := map[string]struct{}{
		"a": {},
		"b": {},
	}
	got := sortedSet(m)
	seen := make(map[string]int)
	for _, v := range got {
		seen[v]++
	}
	for k, n := range seen {
		if n > 1 {
			t.Errorf("key %q appears %d times, want 1", k, n)
		}
	}
}

// -- qualifiedName --

func makePkg(t *testing.T) *types.Package {
	t.Helper()
	return types.NewPackage("example.com/lib", "lib")
}

func TestQualifiedName_NonFunc_ReturnsName(t *testing.T) {
	pkg := makePkg(t)
	v := types.NewVar(token.NoPos, pkg, "MyVar", types.Typ[types.Int])
	got := qualifiedName(v)
	if got != "MyVar" {
		t.Errorf("qualifiedName(Var) = %q, want MyVar", got)
	}
}

func TestQualifiedName_TypeName_ReturnsName(t *testing.T) {
	pkg := makePkg(t)
	tn := types.NewTypeName(token.NoPos, pkg, "MyType", nil)
	got := qualifiedName(tn)
	if got != "MyType" {
		t.Errorf("qualifiedName(TypeName) = %q, want MyType", got)
	}
}

func TestQualifiedName_Const_ReturnsName(t *testing.T) {
	pkg := makePkg(t)
	c := types.NewConst(token.NoPos, pkg, "MyConst", types.Typ[types.Int], nil)
	got := qualifiedName(c)
	if got != "MyConst" {
		t.Errorf("qualifiedName(Const) = %q, want MyConst", got)
	}
}

func TestQualifiedName_StandaloneFunc_ReturnsName(t *testing.T) {
	pkg := makePkg(t)
	sig := types.NewSignatureType(nil, nil, nil, nil, nil, false)
	fn := types.NewFunc(token.NoPos, pkg, "DoWork", sig)
	got := qualifiedName(fn)
	if got != "DoWork" {
		t.Errorf("qualifiedName(standalone func) = %q, want DoWork", got)
	}
}

func TestQualifiedName_ValueReceiverMethod_ReturnsTypeDotMethod(t *testing.T) {
	pkg := makePkg(t)
	// Build: type MyType struct{}; func (m MyType) Method {}
	typeName := types.NewTypeName(token.NoPos, pkg, "MyType", nil)
	named := types.NewNamed(typeName, types.NewStruct(nil, nil), nil)
	recv := types.NewVar(token.NoPos, pkg, "m", named)
	sig := types.NewSignatureType(recv, nil, nil, nil, nil, false)
	fn := types.NewFunc(token.NoPos, pkg, "Method", sig)

	got := qualifiedName(fn)
	if got != "MyType.Method" {
		t.Errorf("qualifiedName(value receiver) = %q, want MyType.Method", got)
	}
}

func TestQualifiedName_PointerReceiverMethod_ReturnsTypeDotMethod(t *testing.T) {
	pkg := makePkg(t)
	// Build: type MyType struct{}; func (m *MyType) PtrMethod {}
	typeName := types.NewTypeName(token.NoPos, pkg, "MyType", nil)
	named := types.NewNamed(typeName, types.NewStruct(nil, nil), nil)
	ptrType := types.NewPointer(named)
	recv := types.NewVar(token.NoPos, pkg, "m", ptrType)
	sig := types.NewSignatureType(recv, nil, nil, nil, nil, false)
	fn := types.NewFunc(token.NoPos, pkg, "PtrMethod", sig)

	got := qualifiedName(fn)
	// Pointer is stripped: result should still be "MyType.PtrMethod"
	if got != "MyType.PtrMethod" {
		t.Errorf("qualifiedName(pointer receiver) = %q, want MyType.PtrMethod", got)
	}
}

// -- test-scope classification against a real workspace --

// writeTestScopeFixture builds a workspace whose dependency is a local replace,
// so the tree type-checks offline. The dependency exports symbols referenced
// only from production code, only from a _test.go file, and from both.
func writeTestScopeFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.22\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => ./dep\n",
		"app.go": "package app\n\nimport (\n\t\"example.com/dep/prod\"\n\t\"example.com/dep/shared\"\n)\n\n" +
			"// Run uses the production-scope dependency surface.\nfunc Run() { prod.Prod(); shared.Prod() }\n",
		"app_test.go": "package app\n\nimport (\n\t\"testing\"\n\n\t\"example.com/dep/shared\"\n\t\"example.com/dep/testonly\"\n)\n\n" +
			"func TestRun(t *testing.T) {\n\tRun()\n\ttestonly.Helper()\n\tshared.OnlyTest()\n}\n",
		"dep/go.mod":               "module example.com/dep\n\ngo 1.22\n",
		"dep/prod/prod.go":         "package prod\n\n// Prod is referenced from production code.\nfunc Prod() {}\n",
		"dep/testonly/testonly.go": "package testonly\n\n// Helper is referenced only from a _test.go file.\nfunc Helper() {}\n",
		"dep/shared/shared.go":     "package shared\n\n// Prod is referenced from production code.\nfunc Prod() {}\n\n// OnlyTest is referenced only from a _test.go file.\nfunc OnlyTest() {}\n",
	}
	for name, content := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("creating %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	return root
}

func analyseFixture(t *testing.T) domain.ImportedModule {
	t.Helper()
	mods, err := New().AnalyseSymbols(context.Background(), writeTestScopeFixture(t))
	if err != nil {
		t.Fatalf("AnalyseSymbols: %v", err)
	}
	if len(mods) != 1 {
		t.Fatalf("modules = %v, want the single replaced dependency", mods)
	}
	return mods[0]
}

// TestAnalyseSymbols_ReportsSymbolsReferencedOnlyFromTests is the defect the
// Tests:true load exists for: a dependency package no production file
// references was absent from the answer, so a module the tests genuinely
// compile and run against was reported as unused.
func TestAnalyseSymbols_ReportsSymbolsReferencedOnlyFromTests(t *testing.T) {
	got := analyseFixture(t)
	for _, want := range []string{
		"example.com/dep/prod.Prod",
		"example.com/dep/shared.Prod",
		"example.com/dep/shared.OnlyTest",
		"example.com/dep/testonly.Helper",
	} {
		if !slices.Contains(got.UsedSymbols, want) {
			t.Errorf("UsedSymbols missing %q: %v", want, got.UsedSymbols)
		}
	}
}

// The marking is per reference, not per package variant. The in-package test
// variant type-checks the production files too, so a classification that read
// the variant wholesale would mark every production reference in a tested
// package as test scope — and --exclude-tests would then drop real users.
func TestAnalyseSymbols_MarksOnlyTheReferencesMadeFromTestFiles(t *testing.T) {
	got := analyseFixture(t)
	wantTestOnly := []string{"example.com/dep/shared.OnlyTest", "example.com/dep/testonly.Helper"}
	if !slices.Equal(got.TestOnlySymbols, wantTestOnly) {
		t.Errorf("TestOnlySymbols = %v, want exactly %v", got.TestOnlySymbols, wantTestOnly)
	}
	if !slices.Contains(got.TestOnlyPackages, "example.com/dep/testonly") {
		t.Errorf("TestOnlyPackages = %v, want example.com/dep/testonly", got.TestOnlyPackages)
	}
	if slices.Contains(got.TestOnlyPackages, "example.com/dep/shared") {
		t.Error("a package with a production reference was marked test-only")
	}
}
