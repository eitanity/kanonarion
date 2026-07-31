package staticcha_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// preModulesFiles is a module as it was published before Go modules existed: Go
// source, no go.mod, and nothing imported beyond the standard library.
var preModulesFiles = map[string]string{
	"premod.go": `package premod

import "strings"

// Upper is the module's exported entry point.
func Upper(s string) string {
	return helper(s)
}

func helper(s string) string {
	return strings.ToUpper(s)
}
`,
}

func mustTestCoord(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate(%q, %q): %v", path, version, err)
	}
	return c
}

func requireGraph(t *testing.T, rec domain.CallGraphRecord) {
	t.Helper()
	switch rec.OverallStatus {
	case domain.CallGraphStatusExtracted, domain.CallGraphStatusPartial:
	default:
		t.Fatalf("status %s (%s): a pre-modules module must analyse to a graph", rec.OverallStatus, rec.FailureDetail)
	}
	if len(rec.Nodes) == 0 {
		t.Fatalf("empty graph: %d node(s), %d edge(s), detail %q", len(rec.Nodes), len(rec.Edges), rec.FailureDetail)
	}
}

// TestAnalyse_PreModulesZipAnalysesToAGraph is the regression this change
// exists for. Extracted into a bare directory a module with no go.mod loads
// outside any module, so no package carries its import path, nothing is
// recognised as the target, and the record is an empty graph.
func TestAnalyse_PreModulesZipAnalysesToAGraph(t *testing.T) {
	coord := mustTestCoord(t, "example.com/premod", "v0.0.0-20180430131211-7c2a214ada46")
	a := staticcha.New("0.1.0", "", slog.Default())

	rec, err := a.Analyse(context.Background(), writeZipToTemp(t, makeZip(t, coord, preModulesFiles)), coord)
	if err != nil {
		t.Fatalf("Analyse returned error: %v", err)
	}
	requireGraph(t, rec)

	// The graph has to be the MODULE's, not a collection of packages loaded under
	// some other identity; that is what makes its node IDs join the ledger.
	var sawUpper bool
	for _, n := range rec.Nodes {
		if n.Symbol == "Upper" {
			sawUpper = true
			if n.Module != coord.Path() {
				t.Errorf("node %s carries module %q, want %q", n.ID, n.Module, coord.Path())
			}
		}
	}
	if !sawUpper {
		t.Errorf("no node for the module's exported entry point; nodes: %v", rec.Nodes)
	}

	// The record must say the analysed tree was not the published tree.
	if rec.SynthesisedGoMod.IsZero() {
		t.Fatal("record does not state that a go.mod was synthesised")
	}
	if got, want := rec.SynthesisedGoMod.ModulePath, coord.Path(); got != want {
		t.Errorf("SynthesisedGoMod.ModulePath = %q, want %q", got, want)
	}
	if rec.SynthesisedGoMod.GoDirective == "" {
		t.Error("SynthesisedGoMod.GoDirective is empty: the directive must be pinned and recorded, never defaulted")
	}
	if rec.AnalysisSource != domain.AnalysisSourceModuleZip {
		t.Errorf("AnalysisSource = %q, want %q", rec.AnalysisSource, domain.AnalysisSourceModuleZip)
	}
}

// TestAnalyse_PreModulesIncompatibleKeepsPublishedPath pins the +incompatible
// rule end to end. Five of the failing coordinates are +incompatible, and a
// graph built under a "/vN" path would build cleanly while naming a module that
// does not exist — a silent non-join, worse than the failure it replaces.
func TestAnalyse_PreModulesIncompatibleKeepsPublishedPath(t *testing.T) {
	coord := mustTestCoord(t, "example.com/premod", "v2.22.0+incompatible")
	a := staticcha.New("0.1.0", "", slog.Default())

	rec, err := a.Analyse(context.Background(), writeZipToTemp(t, makeZip(t, coord, preModulesFiles)), coord)
	if err != nil {
		t.Fatalf("Analyse returned error: %v", err)
	}
	requireGraph(t, rec)

	for _, n := range rec.Nodes {
		if n.IsExternal {
			continue
		}
		if strings.Contains(n.ID, "/v2") || strings.Contains(n.Module, "/v2") {
			t.Errorf("node %q (module %q) carries a major-version suffix the published path does not have", n.ID, n.Module)
		}
	}
	if got := rec.SynthesisedGoMod.ModulePath; got != "example.com/premod" {
		t.Errorf("SynthesisedGoMod.ModulePath = %q, want the published path with no /v2", got)
	}
}

// TestAnalyse_ZipShippingGoModIsNotSynthesised is the refusal. A module that
// publishes a go.mod and still fails is failing for its own reasons, and
// synthesis must not overwrite the published file and turn that into a graph.
func TestAnalyse_ZipShippingGoModIsNotSynthesised(t *testing.T) {
	a := staticcha.New("0.1.0", "", slog.Default())

	t.Run("a module that loads keeps its own file", func(t *testing.T) {
		rec, err := a.Analyse(context.Background(), writeZipToTemp(t, makeZip(t, testCoord, testModuleFiles)), testCoord)
		if err != nil {
			t.Fatalf("Analyse returned error: %v", err)
		}
		requireGraph(t, rec)
		if !rec.SynthesisedGoMod.IsZero() {
			t.Errorf("SynthesisedGoMod = %+v on a module that ships its own go.mod", rec.SynthesisedGoMod)
		}
	})

	t.Run("a module that fails keeps failing", func(t *testing.T) {
		// The shipped go.mod declares a path the coordinate does not name, so
		// nothing loads as the target. Synthesising over it would replace that with
		// a clean graph and hide the disagreement entirely.
		files := map[string]string{
			"go.mod": "module example.com/notthecoordinate\n\ngo 1.21\n",
			"a.go":   "package notthecoordinate\n\n// F is exported.\nfunc F() {}\n",
		}
		coord := mustTestCoord(t, "example.com/premod", "v1.0.0")
		rec, err := a.Analyse(context.Background(), writeZipToTemp(t, makeZip(t, coord, files)), coord)
		if err != nil {
			t.Fatalf("Analyse returned error: %v", err)
		}
		if !rec.SynthesisedGoMod.IsZero() {
			t.Errorf("SynthesisedGoMod = %+v: the published go.mod was overwritten", rec.SynthesisedGoMod)
		}
		if len(rec.Nodes) != 0 {
			t.Errorf("expected no graph for a module whose own go.mod names another path, got %d node(s)", len(rec.Nodes))
		}
	})
}

// TestAnalyse_PreModulesNeedingDependenciesIsLeftUnchanged holds the scope line.
// A pre-modules module whose own packages import third-party code needs a
// require list this change cannot derive: synthesising a file with none would
// look for versions nobody chose, and any edge it produced would name
// coordinates that join nothing else in the ledger. Such a module keeps failing
// exactly as it did, and its record says nothing was synthesised.
func TestAnalyse_PreModulesNeedingDependenciesIsLeftUnchanged(t *testing.T) {
	coord := mustTestCoord(t, "example.com/premod", "v1.0.0")
	files := map[string]string{
		"premod.go": "package premod\n\nimport \"github.com/example/dep\"\n\n// F uses a dependency.\nfunc F() { dep.G() }\n",
	}

	a := staticcha.New("0.1.0", "", slog.Default())
	rec, err := a.Analyse(context.Background(), writeZipToTemp(t, makeZip(t, coord, files)), coord)
	if err != nil {
		t.Fatalf("Analyse returned error: %v", err)
	}
	if !rec.SynthesisedGoMod.IsZero() {
		t.Errorf("SynthesisedGoMod = %+v: a module needing dependency resolution was synthesised for", rec.SynthesisedGoMod)
	}
	if len(rec.Nodes) != 0 {
		t.Errorf("expected no graph, got %d node(s)", len(rec.Nodes))
	}
	if rec.OverallStatus != domain.CallGraphStatusLoadFailed {
		t.Errorf("OverallStatus = %s, want the LoadFailed this module already recorded", rec.OverallStatus)
	}
}

// TestAnalyse_PreModulesWithVendorTreeDisablesVendorMode covers the vendor
// hazard explicitly. A synthesised go.mod beside a vendor directory would
// auto-select -mod=vendor and fail consistency checking against a require list
// the synthesised file does not have, so the load says which mode it means.
func TestAnalyse_PreModulesWithVendorTreeDisablesVendorMode(t *testing.T) {
	coord := mustTestCoord(t, "example.com/premod", "v1.0.0")
	files := map[string]string{}
	for k, v := range preModulesFiles {
		files[k] = v
	}
	files["vendor/modules.txt"] = "# example.com/dep v1.0.0\n## explicit\nexample.com/dep\n"
	files["vendor/example.com/dep/dep.go"] = "package dep\n\n// Vendored is a vendored leaf.\nfunc Vendored() {}\n"

	a := staticcha.New("0.1.0", "", slog.Default())
	rec, err := a.Analyse(context.Background(), writeZipToTemp(t, makeZip(t, coord, files)), coord)
	if err != nil {
		t.Fatalf("Analyse returned error: %v", err)
	}
	requireGraph(t, rec)
	if !rec.SynthesisedGoMod.VendorTreePresent {
		t.Error("SynthesisedGoMod.VendorTreePresent = false for a module that ships vendor/")
	}
}
