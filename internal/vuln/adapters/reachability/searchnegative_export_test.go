package reachability_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/vuln/adapters/reachability"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// exportedConsumerGraph is a build whose main does nothing: the only way into
// the vulnerable code is a function the host or C code calls, which reaches
// the linked standard-library function the join continues from.
func exportedConsumerGraph(symbol, kind, name string) ports.CallGraphProjection {
	entry := consumerModule + "." + symbol
	return ports.CallGraphProjection{
		Completeness:   "BUILT_WITH_BODIES",
		ArtifactKind:   "Application",
		StdlibPackages: []string{linkedPackage},
		Nodes: []ports.CallGraphNode{
			{ID: consumerModule + ".main", Module: consumerModule, Package: consumerModule, Symbol: "main"},
			{ID: entry, Module: consumerModule, Package: consumerModule, Symbol: symbol, ExportKind: kind, ExportName: name},
			{ID: linkedPackage + ".Marshal", Package: linkedPackage, Symbol: "Marshal", IsExternal: true},
		},
		Edges: []ports.CallGraphEdge{{FromID: entry, ToID: linkedPackage + ".Marshal"}},
	}
}

func searchExported(t *testing.T, consumer ports.CallGraphProjection) (domain.VulnerabilityFinding, domain.ReachabilitySoundness, string) {
	t.Helper()
	loader := &byCoordinateLoader{graphs: map[string]ports.CallGraphProjection{
		consumerModule + "@" + coordinate.LocalVersion: consumer,
		coordinate.StdlibPath + "@v1.26.5":             stdlibGraph(),
	}}
	// encodeState sits behind Marshal in the linked package.
	rec := stdlibRecord([]string{linkedPackage}, []string{"encodeState"})
	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)
	got, reason := domain.NegativeSoundness(rec.Findings[0])
	return rec.Findings[0], got, reason
}

// TestSearchNegative_AnExportRootsTheConfirmingSearch is the case govulncheck is
// silent on: it roots at main and init, so a path entered only by the host reads
// as no path. Rooted at the export, the search finds it and the rung says the
// two analysers disagree, naming the export as where the route starts.
func TestSearchNegative_AnExportRootsTheConfirmingSearch(t *testing.T) {
	tests := []struct{ symbol, kind, name string }{
		{symbol: "parse", kind: "wasmexport", name: "parse"},
		{symbol: "goParse", kind: "export", name: "goParse"},
		{symbol: "irq", kind: "interrupt"},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			f, got, reason := searchExported(t, exportedConsumerGraph(tt.symbol, tt.kind, tt.name))
			if got != domain.SoundnessDisputed {
				t.Fatalf("soundness = %s (%s), want %s", got, reason, domain.SoundnessDisputed)
			}
			route := f.NegativeSearch.Route
			if len(route) == 0 || route[0].Package != consumerModule || route[0].Symbol != tt.symbol {
				t.Errorf("route = %s, want it rooted at %s.%s", route, consumerModule, tt.symbol)
			}
			if !strings.Contains(reason, tt.symbol) {
				t.Errorf("the rung does not name the export the route starts at: %s", reason)
			}
		})
	}
}

// TestSearchNegative_AnUnusedFunctionDoesNotDispute is the control: the same
// build with the directive removed has a parse nothing calls, and the search
// from main finds nothing.
func TestSearchNegative_AnUnusedFunctionDoesNotDispute(t *testing.T) {
	f, got, reason := searchExported(t, exportedConsumerGraph("parse", "", ""))
	if got == domain.SoundnessDisputed {
		t.Fatalf("an unused function disputes the negative: %s", reason)
	}
	if f.NegativeSearch == nil || f.NegativeSearch.PathFound {
		t.Errorf("the entry-point search found a path from an unused function: %+v", f.NegativeSearch)
	}
}
