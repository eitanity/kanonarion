package reachability_test

import (
	"context"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"

	callgraphdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"

	"code.eitanity.com/kanonarion/internal/vuln/adapters/reachability"
	"code.eitanity.com/kanonarion/internal/vuln/domain"
	"code.eitanity.com/kanonarion/internal/vuln/ports"
)

const readerDetail = "a dependency can call it through io.Reader"

// dispatchGraph is libraryGraph with a method of an unexported type that a
// dependency can call, and that alone reaches the vulnerable symbol.
func dispatchGraph(detail string) ports.CallGraphProjection {
	proj := libraryGraph("BUILT_WITH_BODIES", false)
	proj.Nodes = append(proj.Nodes, ports.CallGraphNode{
		ID: "read", Module: searchedModule, Package: searchedModule, Symbol: "Read", Receiver: "*body",
		DependencyDispatch: detail,
	})
	proj.Edges = append(proj.Edges, ports.CallGraphEdge{FromID: "read", ToID: "vuln"})
	return proj
}

func searchOver(t *testing.T, proj ports.CallGraphProjection) domain.VulnerabilityFinding {
	t.Helper()
	rec := searchedRecord(domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0")), []string{"vulnerable"})
	reachability.NewNegativeSearcher(&countingLoader{projection: proj}).Search(t.Context(), &rec)
	return rec.Findings[0]
}

// A dependency's call into the module has no edge, so a clean search from the
// named entry points does not confirm while a method it could call reaches the
// symbol; that route is its own claim and never disputes the negative. Without
// the fact the same graph confirms, as before.
func TestSearchNegative_AMethodADependencyCanCallHoldsTheNegativeUnconfirmed(t *testing.T) {
	f := searchOver(t, dispatchGraph(readerDetail))
	s := f.NegativeSearch
	if s == nil || s.PathFound || !s.DispatchPathFound || len(s.DispatchRoute) == 0 || s.DispatchRoute[0].Symbol != "Read" {
		t.Fatalf("search = %+v, want the dispatch route alone", s)
	}
	if s.EntryPointRoots != 1 || s.DispatchDetail != readerDetail {
		t.Errorf("EntryPointRoots = %d, detail = %q; want the named roots counted and the root's detail", s.EntryPointRoots, s.DispatchDetail)
	}
	got, reason := domain.NegativeSoundness(f)
	if got != domain.SoundnessUnconfirmed || !strings.Contains(reason, "(*body).Read") || !strings.Contains(reason, "io.Reader") ||
		!strings.Contains(reason, "a dependency could call through a value the module hands it") {
		t.Errorf("soundness = %s (%s), want unconfirmed naming the method and its interface", got, reason)
	}

	if got, reason := domain.NegativeSoundness(searchOver(t, dispatchGraph(""))); got != domain.SoundnessConfirmed {
		t.Errorf("without the fact soundness = %s (%s), want %s as before", got, reason, domain.SoundnessConfirmed)
	}
}

// Where the named entry points already reach the symbol, their route is the one
// reported, and the second set is not consulted.
func TestSearchNegative_ANamedEntryPointsRouteIsKept(t *testing.T) {
	graph := dispatchGraph(readerDetail)
	graph.Edges = append(graph.Edges, ports.CallGraphEdge{FromID: "entry", ToID: "vuln"})
	s := searchOver(t, graph).NegativeSearch
	if s == nil || !s.PathFound || s.Route[0].Symbol != "Serve" || s.DispatchPathFound || s.EntryPointRoots != 1 {
		t.Errorf("search = %+v, want the exported entry point's route only", s)
	}
}

// A method whose only hand-off is in a test reaches the search with no detail,
// through the loader, so it roots nothing and the negative confirms.
func TestSearchNegative_ATestOnlyHandOffRootsNothing(t *testing.T) {
	escape := callgraphdomain.DispatchEscape{Kind: callgraphdomain.EscapeConversion, Type: "*body", Via: "any", Function: searchedModule + ".TestRead"}
	rec := callgraphdomain.CallGraphRecord{
		Completeness: callgraphdomain.CompletenessBuiltWithBodies, ArtifactKind: callgraphdomain.ArtifactLibrary, PipelineVersion: "p1",
		Nodes: []callgraphdomain.CallNode{
			{ID: "entry", Module: searchedModule, Package: searchedModule, Symbol: "Serve", IsExportedAPI: true},
			{ID: "vuln", Module: searchedModule, Package: searchedModule, Symbol: "vulnerable"},
			{ID: "read", Module: searchedModule, Package: searchedModule, Symbol: "Read", Receiver: "*body",
				DependencyDispatch: callgraphdomain.DependencyDispatch{Escape: escape}},
		},
		Edges: []callgraphdomain.CallEdge{{FromID: "read", ToID: "vuln"}},
	}
	proj, err := reachability.NewCallGraphStoreLoader(&fakeStore{record: rec, found: true}, "p1").Load(context.Background(), loaderCoord)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	f := searchOver(t, proj)
	if got, reason := domain.NegativeSoundness(f); got != domain.SoundnessConfirmed || f.NegativeSearch.DispatchPathFound {
		t.Errorf("soundness = %s (%s), want confirmed: a test's hand-off is in no consumer's build", got, reason)
	}
}
