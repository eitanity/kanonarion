package domain_test

import (
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/walk/domain"
)

func coord(path, version string) fetchdomain.ModuleCoordinate {
	return fetchdomain.ModuleCoordinate{Path: path, Version: version}
}

func TestGraphSort_nodes(t *testing.T) {
	g := &domain.Graph{
		Nodes: []domain.GraphNode{
			{Coordinate: coord("golang.org/x/text", "v0.3.0")},
			{Coordinate: coord("example.com/alpha", "v1.0.0")},
			{Coordinate: coord("example.com/alpha", "v0.9.0")},
			{Coordinate: coord("github.com/foo/bar", "v2.0.0")},
		},
	}
	g.Sort()

	want := []string{
		"example.com/alpha@v0.9.0",
		"example.com/alpha@v1.0.0",
		"github.com/foo/bar@v2.0.0",
		"golang.org/x/text@v0.3.0",
	}
	if len(g.Nodes) != len(want) {
		t.Fatalf("node count = %d, want %d", len(g.Nodes), len(want))
	}
	for i, n := range g.Nodes {
		if got := n.Coordinate.String(); got != want[i] {
			t.Errorf("node[%d] = %q, want %q", i, got, want[i])
		}
	}
}

func TestGraphSort_edges(t *testing.T) {
	g := &domain.Graph{
		Edges: []domain.GraphEdge{
			{From: coord("z.com/z", "v1.0.0"), To: coord("a.com/a", "v1.0.0")},
			{From: coord("a.com/a", "v1.0.0"), To: coord("b.com/b", "v2.0.0")},
			{From: coord("a.com/a", "v1.0.0"), To: coord("a.com/a", "v1.0.0")},
		},
	}
	g.Sort()

	// Expected order: a.com/a→a.com/a, a.com/a→b.com/b, z.com/z→a.com/a
	if g.Edges[0].From.Path != "a.com/a" || g.Edges[0].To.Path != "a.com/a" {
		t.Errorf("edges[0] = %q→%q, want a.com/a→a.com/a", g.Edges[0].From.Path, g.Edges[0].To.Path)
	}
	if g.Edges[1].From.Path != "a.com/a" || g.Edges[1].To.Path != "b.com/b" {
		t.Errorf("edges[1] = %q→%q, want a.com/a→b.com/b", g.Edges[1].From.Path, g.Edges[1].To.Path)
	}
	if g.Edges[2].From.Path != "z.com/z" {
		t.Errorf("edges[2].From = %q, want z.com/z", g.Edges[2].From.Path)
	}
}

func TestGraphSort_idempotent(t *testing.T) {
	nodes := []domain.GraphNode{
		{Coordinate: coord("c.com/c", "v1.0.0")},
		{Coordinate: coord("a.com/a", "v1.0.0")},
		{Coordinate: coord("b.com/b", "v1.0.0")},
	}
	g := &domain.Graph{Nodes: nodes}
	g.Sort()
	first := make([]string, len(g.Nodes))
	for i, n := range g.Nodes {
		first[i] = n.Coordinate.String()
	}
	g.Sort()
	for i, n := range g.Nodes {
		if n.Coordinate.String() != first[i] {
			t.Errorf("sort not idempotent: index %d changed from %q to %q", i, first[i], n.Coordinate.String())
		}
	}
}

func TestGraphSort_emptyGraph(t *testing.T) {
	g := &domain.Graph{}
	g.Sort() // must not panic
}

func TestGraphNode_fields(t *testing.T) {
	n := domain.GraphNode{
		Coordinate:       coord("example.com/pkg", "v1.2.3"),
		DirectDependency: true,
		ResolutionSource: domain.ResolutionMVS,
		ErrorDetail:      "",
		Retracted:        false,
	}
	if n.Coordinate.Path != "example.com/pkg" {
		t.Errorf("Path = %q", n.Coordinate.Path)
	}
	if !n.DirectDependency {
		t.Error("DirectDependency should be true")
	}
	if n.ResolutionSource != domain.ResolutionMVS {
		t.Errorf("ResolutionSource = %q", n.ResolutionSource)
	}
}

func TestGraph_partialMarking(t *testing.T) {
	g := domain.Graph{
		Target:          coord("example.com/target", "v1.0.0"),
		PipelineVersion: "1.0.0",
		ResolvedAt:      time.Now(),
		Partial:         true,
		PartialReason:   "fetch_failed",
	}
	if !g.Partial {
		t.Error("expected Partial=true")
	}
	if g.PartialReason == "" {
		t.Error("partial graph must have non-empty PartialReason")
	}
}

func TestGraphSort_edges_sameFromPath(t *testing.T) {
	g := &domain.Graph{
		Edges: []domain.GraphEdge{
			{From: coord("a.com/x", "v2.0.0"), To: coord("b.com/y", "v1.0.0")},
			{From: coord("a.com/x", "v1.0.0"), To: coord("b.com/y", "v1.0.0")},
		},
	}
	g.Sort()
	if g.Edges[0].From.Version != "v1.0.0" {
		t.Errorf("edges[0].From.Version = %q, want v1.0.0", g.Edges[0].From.Version)
	}
}

func TestGraphSort_edges_sameFromDifferentToPath(t *testing.T) {
	g := &domain.Graph{
		Edges: []domain.GraphEdge{
			{From: coord("a.com/x", "v1.0.0"), To: coord("z.com/z", "v1.0.0")},
			{From: coord("a.com/x", "v1.0.0"), To: coord("a.com/a", "v1.0.0")},
		},
	}
	g.Sort()
	if g.Edges[0].To.Path != "a.com/a" {
		t.Errorf("edges[0].To.Path = %q, want a.com/a", g.Edges[0].To.Path)
	}
}

func TestGraphSort_edges_sameFromSameToPathDiffVersion(t *testing.T) {
	g := &domain.Graph{
		Edges: []domain.GraphEdge{
			{From: coord("a.com/x", "v1.0.0"), To: coord("b.com/y", "v2.0.0")},
			{From: coord("a.com/x", "v1.0.0"), To: coord("b.com/y", "v1.0.0")},
		},
	}
	g.Sort()
	if g.Edges[0].To.Version != "v1.0.0" {
		t.Errorf("edges[0].To.Version = %q, want v1.0.0", g.Edges[0].To.Version)
	}
}

func TestGraphReachableFrom_transitiveClosure(t *testing.T) {
	// root → a → b → c ; root → d (independent branch)
	g := domain.Graph{
		Edges: []domain.GraphEdge{
			{From: coord("root", "local"), To: coord("a", "v1.0.0")},
			{From: coord("a", "v1.0.0"), To: coord("b", "v1.0.0")},
			{From: coord("b", "v1.0.0"), To: coord("c", "v1.0.0")},
			{From: coord("root", "local"), To: coord("d", "v1.0.0")},
		},
	}

	got := g.ReachableFrom(coord("a", "v1.0.0"))
	want := map[string]bool{"b@v1.0.0": true, "c@v1.0.0": true}
	if len(got) != len(want) {
		t.Fatalf("reachable count = %d, want %d (%v)", len(got), len(want), keysOf(got))
	}
	for c := range got {
		if !want[c.String()] {
			t.Errorf("unexpected reachable %q", c.String())
		}
	}
}

func TestGraphReachableFrom_excludesOrigin(t *testing.T) {
	g := domain.Graph{
		Edges: []domain.GraphEdge{
			{From: coord("a", "v1.0.0"), To: coord("b", "v1.0.0")},
			{From: coord("b", "v1.0.0"), To: coord("a", "v1.0.0")}, // cycle back to origin
		},
	}
	got := g.ReachableFrom(coord("a", "v1.0.0"))
	if _, ok := got[coord("a", "v1.0.0")]; ok {
		t.Error("origin must not be included in its own reachable set")
	}
	if _, ok := got[coord("b", "v1.0.0")]; !ok {
		t.Error("b should be reachable from a")
	}
}

func TestGraphReachableFrom_noOutgoingEdges(t *testing.T) {
	g := domain.Graph{
		Edges: []domain.GraphEdge{
			{From: coord("a", "v1.0.0"), To: coord("b", "v1.0.0")},
		},
	}
	// "b" is a leaf with no outgoing edges.
	if got := g.ReachableFrom(coord("b", "v1.0.0")); len(got) != 0 {
		t.Errorf("leaf reachable set = %v, want empty", keysOf(got))
	}
	// A coordinate absent from the graph yields an empty set.
	if got := g.ReachableFrom(coord("absent", "v1.0.0")); len(got) != 0 {
		t.Errorf("absent reachable set = %v, want empty", keysOf(got))
	}
}

func TestGraphReachableFrom_selfEdge(t *testing.T) {
	g := domain.Graph{
		Edges: []domain.GraphEdge{
			{From: coord("a", "v1.0.0"), To: coord("a", "v1.0.0")},
		},
	}
	if got := g.ReachableFrom(coord("a", "v1.0.0")); len(got) != 0 {
		t.Errorf("self-edge reachable set = %v, want empty", keysOf(got))
	}
}

func keysOf(m map[fetchdomain.ModuleCoordinate]struct{}) []string {
	out := make([]string, 0, len(m))
	for c := range m {
		out = append(out, c.String())
	}
	return out
}

func TestResolutionSource_constants(t *testing.T) {
	sources := []domain.ResolutionSource{
		domain.ResolutionTarget,
		domain.ResolutionMVS,
		domain.ResolutionReplace,
		domain.ResolutionFetchFailed,
		domain.ResolutionParseFailed,
	}
	seen := map[domain.ResolutionSource]bool{}
	for _, s := range sources {
		if seen[s] {
			t.Errorf("duplicate ResolutionSource: %q", s)
		}
		seen[s] = true
		if s == "" {
			t.Error("ResolutionSource must not be empty string")
		}
	}
}

func TestSupersededRequirements_returnsIntermediateVersions(t *testing.T) {
	// stdr@v1.2.2 requires logr@v1.2.2, but MVS selected logr@v1.4.3 (required
	// higher elsewhere). The edge records the selected To.Version with the
	// original required version as the constraint. That superseded v1.2.2 is the
	// intermediate go.mod the offline toolchain still reads.
	g := domain.Graph{
		Nodes: []domain.GraphNode{
			{Coordinate: coord("github.com/go-logr/logr", "v1.4.3")},
			{Coordinate: coord("github.com/go-logr/stdr", "v1.2.2")},
		},
		Edges: []domain.GraphEdge{
			{From: coord("github.com/go-logr/stdr", "v1.2.2"), To: coord("github.com/go-logr/logr", "v1.4.3"), ConstraintVersion: "v1.2.2"},
			// A direct require that matches the selected version is not superseded.
			{From: coord("example.com/app", "v1.0.0"), To: coord("github.com/go-logr/logr", "v1.4.3"), ConstraintVersion: "v1.4.3"},
		},
	}

	got := g.SupersededRequirements()
	if len(got) != 1 {
		t.Fatalf("SupersededRequirements() = %v, want exactly one entry", got)
	}
	if got[0].Path != "github.com/go-logr/logr" || got[0].Version != "v1.2.2" {
		t.Errorf("SupersededRequirements()[0] = %s, want github.com/go-logr/logr@v1.2.2", got[0])
	}
}

func TestSupersededRequirements_skipsModuleReplaceTarget(t *testing.T) {
	// mattn/go-sqlite3@v1.14.44 is replaced by rqlite/go-sqlite3@v1.47.0. The
	// edge To is normalised to the replacement path but keeps the original
	// require version as its constraint. Pairing To.Path (rqlite) with the
	// constraint (v1.14.44) would fabricate rqlite/go-sqlite3@v1.14.44, a
	// coordinate that never existed. The replace node must be recognised and the
	// edge skipped.
	g := domain.Graph{
		Nodes: []domain.GraphNode{
			{
				Coordinate:         coord("github.com/rqlite/go-sqlite3", "v1.47.0"),
				OriginalCoordinate: coord("github.com/mattn/go-sqlite3", "v1.14.44"),
				ResolutionSource:   domain.ResolutionReplace,
			},
		},
		Edges: []domain.GraphEdge{
			{From: coord("github.com/rqlite/rqlite/v10", "v10.2.0"), To: coord("github.com/rqlite/go-sqlite3", "v1.47.0"), ConstraintVersion: "v1.14.44"},
		},
	}
	if got := g.SupersededRequirements(); len(got) != 0 {
		t.Fatalf("SupersededRequirements() = %v, want empty (replace target must be skipped)", got)
	}
}

func TestSupersededRequirements_dedupesAndSorts(t *testing.T) {
	g := domain.Graph{
		Edges: []domain.GraphEdge{
			{From: coord("a.com/a", "v1.0.0"), To: coord("z.com/z", "v2.0.0"), ConstraintVersion: "v1.0.0"},
			{From: coord("b.com/b", "v1.0.0"), To: coord("z.com/z", "v2.0.0"), ConstraintVersion: "v1.0.0"}, // duplicate
			{From: coord("c.com/c", "v1.0.0"), To: coord("z.com/z", "v2.0.0"), ConstraintVersion: "v1.5.0"},
			// An empty constraint (main-module edge) is skipped.
			{From: coord("main", ""), To: coord("z.com/z", "v2.0.0"), ConstraintVersion: ""},
		},
	}
	got := g.SupersededRequirements()
	want := []string{"z.com/z@v1.0.0", "z.com/z@v1.5.0"}
	if len(got) != len(want) {
		t.Fatalf("SupersededRequirements() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("SupersededRequirements()[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestSupersededRequirements_emptyWhenFullyPrunedSelected(t *testing.T) {
	// Every constraint equals the selected version: no supersession.
	g := domain.Graph{
		Edges: []domain.GraphEdge{
			{From: coord("a.com/a", "v1.0.0"), To: coord("b.com/b", "v2.0.0"), ConstraintVersion: "v2.0.0"},
		},
	}
	if got := g.SupersededRequirements(); len(got) != 0 {
		t.Errorf("SupersededRequirements() = %v, want empty", got)
	}
}

func TestPrePruning(t *testing.T) {
	cases := map[string]bool{
		"":       true,  // no go directive → pre-modules, unpruned
		"1.16":   true,  // below the pruning boundary
		"1.16.5": true,
		"1.17":   false, // pruning boundary
		"1.21":   false,
		"1.24.0": false,
		"garbage": true, // unparseable → treat as pre-pruning
	}
	for version, want := range cases {
		if got := domain.PrePruning(version); got != want {
			t.Errorf("PrePruning(%q) = %v, want %v", version, got, want)
		}
	}
}
