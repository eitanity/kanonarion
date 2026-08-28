package gosrc_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/godebug/adapters/scanner/gosrc"
	gdvendortree "github.com/eitanity/kanonarion/internal/godebug/adapters/vendortree"
	venlocalfs "github.com/eitanity/kanonarion/internal/vendortree/adapters/scanner/localfs"
	vendordomain "github.com/eitanity/kanonarion/internal/vendortree/domain"
)

// scanner is the scanner as the composition root builds it: the vendor
// context's own reader of vendor/modules.txt behind the godebug port. The tests
// below assert what a vendored directive NAMES, so wiring a stub here would be
// testing the stub.
func scanner() *gosrc.Scanner {
	return gosrc.New(gdvendortree.New(venlocalfs.New(nil)))
}

const corpus = "../../../../../test/fixtures/supplychain/godebug"

// TestScanProject_Clean: a project with no //go:debug yields zero settings
// but a populated module path (clean case).
func TestScanProject_Clean(t *testing.T) {
	res, err := scanner().ScanProject(context.Background(), filepath.Join(corpus, "clean", "go.mod"))
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
	res, err := scanner().ScanProject(context.Background(), filepath.Join(corpus, "red-main", "go.mod"))
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
	res, err := scanner().ScanProject(context.Background(), filepath.Join(corpus, "dep-not-applied", "go.mod"))
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

// TestScanProject_VendoredDirectivesNameTheirModule is the acceptance for
// reading the module off vendor/modules.txt instead of off the path.
//
// Every case is a segment count the old two-segment split got wrong, plus the
// one it got right. golang.org/x/crypto and github.com/IBM/ibm-cos-sdk-go have
// three segments and used to report golang.org/x and github.com/IBM — neither
// of which is a module anyone can upgrade, pin or exempt.
func TestScanProject_VendoredDirectivesNameTheirModule(t *testing.T) {
	res, err := scanner().ScanProject(context.Background(),
		filepath.Join(corpus, "vendored-modules", "go.mod"))
	if err != nil {
		t.Fatalf("ScanProject: %v", err)
	}
	got := map[string]string{}
	applied := map[string]bool{}
	for _, st := range res.Settings {
		got[st.Source] = st.Module
		applied[st.Source] = st.Applied
	}

	want := map[string]string{
		// Two segments — the only shape the old split resolved correctly, kept
		// as the control that this fix did not move what already worked.
		"vendor/k8s.io/client-go/main.go.txt": "k8s.io/client-go",
		// Three segments.
		"vendor/golang.org/x/crypto/main.go.txt":           "golang.org/x/crypto",
		"vendor/github.com/IBM/ibm-cos-sdk-go/main.go.txt": "github.com/IBM/ibm-cos-sdk-go",
		// Four segments, and the nesting case: minio-go/v7's directory lives
		// inside minio-go's, and both are listed, so a first-prefix match would
		// attribute every v7 file to the module v7 succeeded.
		"vendor/github.com/minio/minio-go/main.go.txt":    "github.com/minio/minio-go",
		"vendor/github.com/minio/minio-go/v7/main.go.txt": "github.com/minio/minio-go/v7",
		// A directory modules.txt does not list. "github.com/nobody" is the
		// plausible invention this refuses to make.
		"vendor/github.com/nobody/unlisted-here/main.go.txt": vendordomain.ModuleUnresolved,
		// Control: the project's own directive still names the project module.
		"main.go.txt": "example.com/supplychain/godebug/vendored-modules",
	}
	if len(got) != len(want) {
		t.Fatalf("settings = %v, want %d entries", got, len(want))
	}
	for src, wantMod := range want {
		if got[src] != wantMod {
			t.Errorf("module for %s = %q, want %q", src, got[src], wantMod)
		}
	}

	// The applied flag comes from the same reading of the path as the module,
	// including for the directory nothing claims: a directive under vendor/
	// does not take effect whether or not its module can be named.
	for src, isApplied := range applied {
		wantApplied := src == "main.go.txt"
		if isApplied != wantApplied {
			t.Errorf("applied for %s = %v, want %v", src, isApplied, wantApplied)
		}
	}
}

// TestScanProject_SegmentCountsAreDistinct guards the fixture rather than the
// scanner: the acceptance is that three DIFFERENT segment counts resolve, and a
// fixture that quietly drifted to three modules of the same shape would still
// pass the test above while proving nothing.
func TestScanProject_SegmentCountsAreDistinct(t *testing.T) {
	counts := map[int]string{}
	for _, m := range []string{
		"k8s.io/client-go",
		"golang.org/x/crypto",
		"github.com/minio/minio-go/v7",
	} {
		counts[strings.Count(m, "/")+1] = m
	}
	if len(counts) != 3 {
		t.Fatalf("the resolved modules cover %d distinct segment counts, want 3: %v", len(counts), counts)
	}
}
