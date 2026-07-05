package gosrc_test

import (
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/godebug/adapters/scanner/gosrc"
)

const corpus = "../../../../../test/fixtures/supplychain/godebug"

// TestScanProject_Clean: a project with no //go:debug yields zero settings
// but a populated module path (clean case).
func TestScanProject_Clean(t *testing.T) {
	res, err := gosrc.New().ScanProject(filepath.Join(corpus, "clean", "go.mod"))
	if err != nil {
		t.Fatalf("ScanProject: %v", err)
	}
	if len(res.Settings) != 0 {
		t.Errorf("clean fixture must have no settings, got %+v", res.Settings)
	}
	if res.ProjectModulePath != "example.com/supplychain/godebug/clean" {
		t.Errorf("module path = %q", res.ProjectModulePath)
	}
}

// TestScanProject_RedMain: a //go:debug in the main module's main package is
// detected with file/line provenance and Applied=true.
func TestScanProject_RedMain(t *testing.T) {
	res, err := gosrc.New().ScanProject(filepath.Join(corpus, "red-main", "go.mod"))
	if err != nil {
		t.Fatalf("ScanProject: %v", err)
	}
	if len(res.Settings) != 1 {
		t.Fatalf("want 1 setting, got %+v", res.Settings)
	}
	s := res.Settings[0]
	if s.Name != "tlsrsakex" || s.Value != "1" {
		t.Errorf("setting = %q=%q, want tlsrsakex=1", s.Name, s.Value)
	}
	if !s.Applied {
		t.Error("main-module main-package directive must be Applied")
	}
	if s.Source != "main.go.txt" || s.Line == 0 {
		t.Errorf("provenance not captured: %+v", s)
	}
}

// TestScanProject_DependencyNotApplied: a //go:debug carried by a vendored
// dependency is recorded with the dependency's module path and Applied=false
// — never silently dropped.
func TestScanProject_DependencyNotApplied(t *testing.T) {
	res, err := gosrc.New().ScanProject(filepath.Join(corpus, "dep-not-applied", "go.mod"))
	if err != nil {
		t.Fatalf("ScanProject: %v", err)
	}
	if len(res.Settings) != 1 {
		t.Fatalf("want 1 setting, got %+v", res.Settings)
	}
	s := res.Settings[0]
	if s.Applied {
		t.Error("vendored dependency directive must be Applied=false")
	}
	if s.Module != "example.com/dep" {
		t.Errorf("dependency module = %q, want example.com/dep", s.Module)
	}
	if s.Name != "tlsrsakex" {
		t.Errorf("setting = %q, want tlsrsakex", s.Name)
	}
}
