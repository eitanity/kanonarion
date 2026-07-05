package golist

import (
	"encoding/json"
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

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}
