package staticcha_test

import (
	"context"
	"log/slog"
	"path/filepath"
	"slices"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// TestArtifactKind_MainPackageWithoutAMainFuncIsALibrary is the shape
// github.com/alicebob/miniredis/v2 ships: an integration/ directory whose files
// are package main and where none of them declares func main. Every package
// loads, so the set is complete and the module is a library — a finding, not the
// absence below.
func TestArtifactKind_MainPackageWithoutAMainFuncIsALibrary(t *testing.T) {
	rec := analyseFiles(t, map[string]string{
		"go.mod": "module example.com/cgtestmod\n\ngo 1.21\n",
		"lib.go": "package cgtestmod\n\n// Exported is the module's API.\nfunc Exported() {}\n",
		"integration/helper.go": `package main

// Helper is declared in a package named main that has no main function, so
// nothing here builds a command.
func Helper() {}
`,
	})
	if rec.OverallStatus != domain.CallGraphStatusExtracted {
		t.Fatalf("OverallStatus = %q (%s), want Extracted: the fixture must load cleanly for the claim to be about the kind",
			rec.OverallStatus, rec.FailureDetail)
	}
	if rec.ArtifactKind != domain.ArtifactLibrary {
		t.Errorf("ArtifactKind = %q, want library: the whole package set loaded and none of it defines func main",
			rec.ArtifactKind)
	}
}

// TestArtifactKind_APackageThatDidNotLoadLeavesTheKindUnestablished is the shape
// github.com/clbanning/mxj/v2 ships: an examples/ directory whose files each
// declare func main in one package, which cannot compile. The package does not
// load, so the module's package set was never seen whole and the analysis cannot
// claim the module ships no command.
func TestArtifactKind_APackageThatDidNotLoadLeavesTheKindUnestablished(t *testing.T) {
	rec := analyseFiles(t, map[string]string{
		"go.mod": "module example.com/cgtestmod\n\ngo 1.21\n",
		"lib.go": "package cgtestmod\n\n// Exported is the module's API.\nfunc Exported() {}\n",
		"examples/one.go": `package main

func main() {}
`,
		"examples/two.go": `package main

func main() {}
`,
	})
	if rec.OverallStatus != domain.CallGraphStatusPartial {
		t.Fatalf("OverallStatus = %q, want Partial: the examples package cannot compile", rec.OverallStatus)
	}
	if !slices.Contains(rec.FailedPackages, "example.com/cgtestmod/examples") {
		t.Fatalf("FailedPackages = %v, want the examples package among them", rec.FailedPackages)
	}
	if rec.ArtifactKind != domain.ArtifactNotEstablished {
		t.Errorf("ArtifactKind = %q, want %q: a package that did not load may be the command, "+
			"so no library claim is available", rec.ArtifactKind, domain.ArtifactNotEstablished)
	}
}

// TestArtifactKind_AFailedAnalysisEstablishesNothing covers the record built
// when nothing loaded at all. That record used to carry the zero value, so an
// analysis that measured nothing published the positive claim that the module is
// a library — the same words a clean load of a library produces.
func TestArtifactKind_AFailedAnalysisEstablishesNothing(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("example.com/absent", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	a := staticcha.New("0.1.0", "", slog.Default())
	rec, err := a.Analyse(context.Background(), filepath.Join(t.TempDir(), "not-a.zip"), coord, domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("Analyse returned an infrastructure error: %v", err)
	}
	if rec.OverallStatus != domain.CallGraphStatusLoadFailed {
		t.Fatalf("OverallStatus = %q, want LoadFailed", rec.OverallStatus)
	}
	if rec.ArtifactKind != domain.ArtifactNotEstablished {
		t.Errorf("ArtifactKind = %q, want %q", rec.ArtifactKind, domain.ArtifactNotEstablished)
	}
}
