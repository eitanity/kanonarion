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

// wrappedConsumerGraph is the export reaching the standard library only through
// a call into another module, whose graph the join does not hold. With direct
// set, the export also calls the linked standard-library function itself.
func wrappedConsumerGraph(direct bool) ports.CallGraphProjection {
	g := exportedConsumerGraph("render", "wasmexport", "render")
	g.Nodes = append(g.Nodes, ports.CallGraphNode{ID: "example.com/wrap.Next", Package: "example.com/wrap", Symbol: "Next", IsExternal: true})
	g.Edges = []ports.CallGraphEdge{{FromID: consumerModule + ".render", ToID: "example.com/wrap.Next"}}
	if direct {
		g.Edges = append(g.Edges, ports.CallGraphEdge{FromID: consumerModule + ".render", ToID: linkedPackage + ".Marshal"})
	}
	return g
}

// TestSearchNegative_StdlibJoinDoesNotCertifyPastAnUnjoinedModule: the route
// export -> other module -> standard library is invisible to the join, so the
// clean search keeps govulncheck's rung and names the call it could not follow.
func TestSearchNegative_StdlibJoinDoesNotCertifyPastAnUnjoinedModule(t *testing.T) {
	f, got, reason := searchExported(t, wrappedConsumerGraph(false))
	if got != domain.SoundnessInferred {
		t.Fatalf("soundness = %s (%s), want %s", got, reason, domain.SoundnessInferred)
	}
	s := f.NegativeSearch
	if s.PathFound || !s.InRecordedFrame || len(s.GraphsSearched) != 2 {
		t.Errorf("search = %+v, want a clean search over the joined graph", s)
	}
	want := "reached 1 call into modules whose call graphs are not joined (example.com/wrap.Next)"
	if !strings.Contains(s.NotJoined, want) || !strings.Contains(s.NotJoined, "so the search does not confirm the negative") {
		t.Errorf("not_joined = %q, want it to name the call and say it does not confirm", s.NotJoined)
	}
	if !strings.Contains(reason, want) {
		t.Errorf("the rung does not carry the unjoined call: %s", reason)
	}
}

// TestSearchNegative_StdlibJoinStillDisputesBesideAnUnjoinedModule: a route the
// join does see is a contradiction whatever else the export calls.
func TestSearchNegative_StdlibJoinStillDisputesBesideAnUnjoinedModule(t *testing.T) {
	f, got, reason := searchExported(t, wrappedConsumerGraph(true))
	if got != domain.SoundnessDisputed {
		t.Fatalf("soundness = %s (%s), want %s", got, reason, domain.SoundnessDisputed)
	}
	if f.NegativeSearch.NotJoined != "" || len(f.NegativeSearch.UnjoinedCalls) != 0 {
		t.Errorf("a found path carries the unjoined guard: %+v", f.NegativeSearch)
	}
}

// TestSearchNegative_StdlibJoinIgnoresAnUnjoinedCallNoEntryPointReaches: the
// call into another module sits in a function nothing enters, so the search
// from the entry points covered every route and confirms.
func TestSearchNegative_StdlibJoinIgnoresAnUnjoinedCallNoEntryPointReaches(t *testing.T) {
	g := wrappedConsumerGraph(false)
	g.Nodes[1].ExportKind, g.Nodes[1].ExportName = "", ""
	f, got, reason := searchExported(t, g)
	if got != domain.SoundnessConfirmed || f.NegativeSearch.NotJoined != "" {
		t.Errorf("soundness = %s (%s), not_joined = %q, want %s and none", got, reason, f.NegativeSearch.NotJoined, domain.SoundnessConfirmed)
	}
}
