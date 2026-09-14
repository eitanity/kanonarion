package reachability_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	"github.com/eitanity/kanonarion/internal/vuln/adapters/reachability"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// reflectSiteGraph is libraryGraph with reflective dispatch sites added: two in
// code the exported entry point reaches, one in code nothing reaches, and one
// whose edge recorded no source position at all.
//
// Positions are the reason this test exists beside the end-to-end one. A real
// graph holds edges with a file and a line, edges with a file alone and edges
// with neither, and a reader sent to "somewhere in this module" cannot go and
// look.
func reflectSiteGraph() ports.CallGraphProjection {
	proj := libraryGraph("BUILT_WITH_BODIES", false)
	proj.Nodes = append(proj.Nodes,
		ports.CallGraphNode{ID: "bind", Module: searchedModule, Package: searchedModule, Symbol: "bind"},
		ports.CallGraphNode{ID: "orphan", Module: searchedModule, Package: searchedModule, Symbol: "orphan"},
	)
	proj.Edges = append(proj.Edges, ports.CallGraphEdge{FromID: "entry", ToID: "bind"})
	proj.ReflectiveDispatch = []ports.CallGraphReflectSite{
		// Deliberately out of order, so the sort is asserted rather than inherited
		// from however the store happened to return the edges.
		{CallerID: "bind", CalleeID: "reflect.(Value).FieldByName", File: "bind.go", Line: 31},
		{CallerID: "orphan", CalleeID: "reflect.(Value).MethodByName", File: "orphan.go", Line: 4},
		{CallerID: "bind", CalleeID: "reflect.(Value).FieldByName", File: "bind.go", Line: 10},
		{CallerID: "bind", CalleeID: "reflect.(Value).Call"},
		{CallerID: "bind", CalleeID: "reflect.(Value).CallSlice", File: "generated.go"},
	}
	return proj
}

// TestSearchNegative_ReflectiveSitesAreNamedWithTheirPositionAndReach is the
// adapter half of the reporting acceptance.
//
// Three things are asserted that the end-to-end test cannot reach: that a site
// with no recorded position says nothing rather than "file:0", that a file
// without a line renders as the file, and that the list comes back in a stable
// order. The order matters because two calls from one function to one reflect
// method differ only in their line, so a sort on the caller alone would leave
// them in whatever order the store returned.
func TestSearchNegative_ReflectiveSitesAreNamedWithTheirPositionAndReach(t *testing.T) {
	t.Parallel()

	loader := &countingLoader{projection: reflectSiteGraph()}
	rec := searchedRecord(domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0")), []string{"vulnerable"})
	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	search := rec.Findings[0].NegativeSearch
	if search == nil {
		t.Fatal("no search was attached")
	}
	got := search.ReflectiveDispatch
	want := []domain.ReflectiveDispatchSite{
		{Caller: "bind", Callee: "reflect.(Value).Call", CallSite: "", ReachableFromEntryPoint: true},
		{Caller: "bind", Callee: "reflect.(Value).CallSlice", CallSite: "generated.go", ReachableFromEntryPoint: true},
		{Caller: "bind", Callee: "reflect.(Value).FieldByName", CallSite: "bind.go:10", ReachableFromEntryPoint: true},
		{Caller: "bind", Callee: "reflect.(Value).FieldByName", CallSite: "bind.go:31", ReachableFromEntryPoint: true},
		{Caller: "orphan", Callee: "reflect.(Value).MethodByName", CallSite: "orphan.go:4", ReachableFromEntryPoint: false},
	}
	if len(got) != len(want) {
		t.Fatalf("the search names %d reflective dispatch sites, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("site %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if n := search.ReachableReflectiveDispatch(); n != 4 {
		t.Errorf("%d sites reported reachable from an entry point, want 4 — only the one in orphan is unreached", n)
	}
}

// TestSearchNegative_AGraphWithNoReflectiveSitesReportsNone is the commoner
// case, and the one a stated zero exists for.
//
// A search that ran and found none, and a search that could not be made, are
// different facts. The first is evidence and the second is not, and the field
// below carries the first while NotSearched carries the second.
func TestSearchNegative_AGraphWithNoReflectiveSitesReportsNone(t *testing.T) {
	t.Parallel()

	loader := &countingLoader{projection: libraryGraph("BUILT_WITH_BODIES", false)}
	rec := searchedRecord(domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0")), []string{"vulnerable"})
	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	search := rec.Findings[0].NegativeSearch
	if search == nil {
		t.Fatal("no search was attached")
	}
	if search.NotSearched != "" {
		t.Fatalf("the search declined to run: %s", search.NotSearched)
	}
	if len(search.ReflectiveDispatch) != 0 {
		t.Errorf("a graph holding no reflective dispatch names %d sites: %+v",
			len(search.ReflectiveDispatch), search.ReflectiveDispatch)
	}
}

// TestSearchNegative_ReflectiveSitesCostOneGraphWalkPerGraph pins the cost.
//
// The reachable set is derived once per graph beside the root sets, not once per
// finding. A record holding many negatives against one coordinate must not pay
// for the walk again on each of them.
func TestSearchNegative_ReflectiveSitesCostOneGraphWalkPerGraph(t *testing.T) {
	t.Parallel()

	loader := &countingLoader{projection: reflectSiteGraph()}
	rooted := domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0"))
	rec := searchedRecord(rooted, []string{"vulnerable"})
	rec.Findings = append(rec.Findings, rec.Findings[0], rec.Findings[0])

	searcher := reachability.NewNegativeSearcher(loader)
	searcher.Search(t.Context(), &rec)

	if loader.calls != 1 {
		t.Errorf("3 findings over one coordinate decoded the graph %d times, want 1", loader.calls)
	}
	for i, f := range rec.Findings {
		if f.NegativeSearch == nil || len(f.NegativeSearch.ReflectiveDispatch) != 5 {
			t.Errorf("finding %d does not carry the graph's 5 reflective dispatch sites: %+v", i, f.NegativeSearch)
		}
	}
}
