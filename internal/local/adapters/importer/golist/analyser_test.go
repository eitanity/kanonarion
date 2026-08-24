package golist

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Tests for the unexported parseGoListOutput helper.

func TestParseGoListOutput_SinglePackage(t *testing.T) {
	pkg := goListPackage{
		ImportPath: "example.com/app",
		Standard:   false,
	}
	data := mustMarshal(t, pkg)

	pkgs, err := parseGoListOutput(data)
	if err != nil {
		t.Fatalf("parseGoListOutput: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("len = %d, want 1", len(pkgs))
	}
	if pkgs[0].ImportPath != "example.com/app" {
		t.Errorf("ImportPath = %q, want example.com/app", pkgs[0].ImportPath)
	}
}

func TestParseGoListOutput_MultiplePackages_ConcatenatedJSON(t *testing.T) {
	// go list -json emits multiple top-level JSON objects concatenated without
	// a separator — the standard format for the multi-package case.
	a := goListPackage{ImportPath: "example.com/a"}
	b := goListPackage{ImportPath: "example.com/b"}
	c := goListPackage{ImportPath: "example.com/c"}

	var data []byte
	for _, p := range []goListPackage{a, b, c} {
		data = append(data, mustMarshal(t, p)...)
	}

	pkgs, err := parseGoListOutput(data)
	if err != nil {
		t.Fatalf("parseGoListOutput: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("len = %d, want 3", len(pkgs))
	}
	paths := map[string]bool{"example.com/a": true, "example.com/b": true, "example.com/c": true}
	for _, p := range pkgs {
		if !paths[p.ImportPath] {
			t.Errorf("unexpected package %q", p.ImportPath)
		}
	}
}

func TestParseGoListOutput_Empty(t *testing.T) {
	pkgs, err := parseGoListOutput([]byte{})
	if err != nil {
		t.Fatalf("parseGoListOutput: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("len = %d, want 0", len(pkgs))
	}
}

func TestParseGoListOutput_PreservesStandardAndModuleFields(t *testing.T) {
	modPath := "example.com/dep"
	pkg := goListPackage{
		ImportPath: "example.com/dep/sub",
		Standard:   false,
		Imports:    []string{"fmt", "example.com/other"},
		Module: &struct {
			Path    string
			Version string
			Main    bool
		}{Path: modPath, Version: "v1.2.3", Main: false},
	}
	data := mustMarshal(t, pkg)

	pkgs, err := parseGoListOutput(data)
	if err != nil {
		t.Fatalf("parseGoListOutput: %v", err)
	}
	if pkgs[0].Module == nil {
		t.Fatal("Module is nil")
	}
	if pkgs[0].Module.Path != modPath {
		t.Errorf("Module.Path = %q, want %q", pkgs[0].Module.Path, modPath)
	}
	if pkgs[0].Module.Version != "v1.2.3" {
		t.Errorf("Module.Version = %q, want v1.2.3", pkgs[0].Module.Version)
	}
	if pkgs[0].Module.Main {
		t.Error("Module.Main should be false")
	}
	if len(pkgs[0].Imports) != 2 {
		t.Errorf("Imports = %v, want 2 entries", pkgs[0].Imports)
	}
}

func TestParseGoListOutput_InvalidJSON_Error(t *testing.T) {
	_, err := parseGoListOutput([]byte(`{"ImportPath": "broken"`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseGoListOutput_StandardPackagePreserved(t *testing.T) {
	pkg := goListPackage{ImportPath: "fmt", Standard: true}
	data := mustMarshal(t, pkg)

	pkgs, err := parseGoListOutput(data)
	if err != nil {
		t.Fatalf("parseGoListOutput: %v", err)
	}
	if !pkgs[0].Standard {
		t.Error("Standard field should be true")
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

// TestAnalyseImports_IgnoresAmbientResolution guards the same posture the
// call-graph load of this tree runs under: an exported GOWORK decided how these
// children resolved, while the load beside them was pinned.
func TestAnalyseImports_IgnoresAmbientResolution(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GOWORK", filepath.Join(t.TempDir(), "absent.go.work"))
	for name, content := range map[string]string{
		"go.mod": "module example.com/imports\n\ngo 1.22\n",
		"a.go":   "package imports\n\n// Answer is the module's only symbol.\nconst Answer = 42\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	if _, err := New("").AnalyseImports(context.Background(), root); err != nil {
		t.Fatalf("AnalyseImports under an inherited GOWORK: %v", err)
	}
}

// -- test-scope classification --

// writeTestScopeFixture builds a workspace whose dependency is a local replace,
// so the tree resolves offline. The dependency has three packages: one only
// production code imports, one only a _test.go file imports, and one both do.
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

// TestAnalyseImports_ReportsTestOnlyImports is the defect this file's -test flag
// exists for: a package no production file imports was absent from the answer
// entirely, so a dependency a developer only reaches from _test.go was reported
// as unused.
func TestAnalyseImports_ReportsTestOnlyImports(t *testing.T) {
	mods, err := New("").AnalyseImports(context.Background(), writeTestScopeFixture(t))
	if err != nil {
		t.Fatalf("AnalyseImports: %v", err)
	}
	if len(mods) != 1 {
		t.Fatalf("modules = %v, want the single replaced dependency", mods)
	}
	got := mods[0]
	wantPkgs := []string{"example.com/dep/prod", "example.com/dep/shared", "example.com/dep/testonly"}
	if !slices.Equal(got.ImportedPackages, wantPkgs) {
		t.Errorf("ImportedPackages = %v, want %v", got.ImportedPackages, wantPkgs)
	}
	if !slices.Equal(got.TestOnlyPackages, []string{"example.com/dep/testonly"}) {
		t.Errorf("TestOnlyPackages = %v, want only example.com/dep/testonly", got.TestOnlyPackages)
	}
}

// A package both scopes import is production. The in-package test variant
// carries the production imports too, so a classification that read that
// variant wholesale would move every one of them into the test set.
func TestAnalyseImports_PackageImportedByBothScopesIsProduction(t *testing.T) {
	mods, err := New("").AnalyseImports(context.Background(), writeTestScopeFixture(t))
	if err != nil {
		t.Fatalf("AnalyseImports: %v", err)
	}
	for _, p := range mods[0].TestOnlyPackages {
		if p == "example.com/dep/shared" || p == "example.com/dep/prod" {
			t.Errorf("%s is imported by production code but was marked test-only", p)
		}
	}
}

// BuildModules answers what goes into the artefact, so it must NOT widen with
// AnalyseImports: a dependency only the tests reach is not linked into the
// binary anything measuring the artefact is scoped to.
func TestBuildModules_StaysAtProductionScope(t *testing.T) {
	root := writeTestScopeFixture(t)
	mods, err := New("").BuildModules(context.Background(), root)
	if err != nil {
		t.Fatalf("BuildModules: %v", err)
	}
	// The one replaced module is in the build either way; what must not appear
	// is a module the test files alone pull in. This fixture has a single
	// dependency module, so the assertion is on the count.
	if len(mods) != 1 {
		t.Fatalf("BuildModules = %v, want the single replaced dependency", mods)
	}
}
