package domain

import (
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func c(path, version string) fetchdomain.ModuleCoordinate {
	return fetchdomain.ModuleCoordinate{Path: path, Version: version}
}

// FilterGraphToScope keeps the main anchor plus the kept module paths, drops the
// rest, and retains only edges whose endpoints both survive.
func TestFilterGraphToScope_KeepsSetDropsRest(t *testing.T) {
	main := c("example.com/project", fetchdomain.LocalVersion)
	g := Graph{
		Target: main,
		Nodes: []GraphNode{
			{Coordinate: main, ResolutionSource: ResolutionLocalMainModule},
			{Coordinate: c("example.com/keep", "v1.0.0"), DirectDependency: true},
			{Coordinate: c("example.com/sub", "v1.0.0")},
			{Coordinate: c("example.com/drop", "v1.0.0"), DirectDependency: true},
		},
		Edges: []GraphEdge{
			{From: main, To: c("example.com/keep", "v1.0.0")},
			{From: c("example.com/keep", "v1.0.0"), To: c("example.com/sub", "v1.0.0")},
			{From: main, To: c("example.com/drop", "v1.0.0")},
		},
	}

	got := FilterGraphToScope(g, main.Path, []string{"example.com/keep", "example.com/sub"})

	paths := map[string]bool{}
	for _, n := range got.Nodes {
		paths[n.Coordinate.Path] = true
	}
	for _, want := range []string{"example.com/project", "example.com/keep", "example.com/sub"} {
		if !paths[want] {
			t.Errorf("scope missing %s; have %v", want, paths)
		}
	}
	if paths["example.com/drop"] {
		t.Errorf("out-of-scope module example.com/drop must be dropped")
	}
	for _, e := range got.Edges {
		if e.From.Path == "example.com/drop" || e.To.Path == "example.com/drop" {
			t.Errorf("edge touching dropped node survived: %s -> %s", e.From, e.To)
		}
	}
	if len(got.Edges) != 2 {
		t.Errorf("edge count = %d, want 2 (main->keep, keep->sub)", len(got.Edges))
	}
}

// An empty keep-set leaves only the main anchor — never the whole graph, so a
// scope can never be silently widened to everything.
func TestFilterGraphToScope_EmptyKeepsOnlyMain(t *testing.T) {
	main := c("example.com/project", fetchdomain.LocalVersion)
	g := Graph{
		Target: main,
		Nodes: []GraphNode{
			{Coordinate: main, ResolutionSource: ResolutionLocalMainModule},
			{Coordinate: c("example.com/a", "v1.0.0")},
		},
		Edges: []GraphEdge{{From: main, To: c("example.com/a", "v1.0.0")}},
	}
	got := FilterGraphToScope(g, main.Path, nil)
	if len(got.Nodes) != 1 || got.Nodes[0].Coordinate.Path != "example.com/project" {
		t.Errorf("expected only the main anchor, got %+v", got.Nodes)
	}
	if len(got.Edges) != 0 {
		t.Errorf("expected no edges, got %+v", got.Edges)
	}
}

// Partial/metadata fields are carried through the filter unchanged.
func TestFilterGraphToScope_PreservesGraphMetadata(t *testing.T) {
	main := c("example.com/project", fetchdomain.LocalVersion)
	g := Graph{
		Target:          main,
		PipelineVersion: "1.5.0",
		Partial:         true,
		PartialReason:   "fetch_failed",
		HasLocalReplace: true,
		Nodes:           []GraphNode{{Coordinate: main, ResolutionSource: ResolutionLocalMainModule}},
	}
	got := FilterGraphToScope(g, main.Path, nil)
	if !got.Partial || got.PartialReason != "fetch_failed" || !got.HasLocalReplace || got.PipelineVersion != "1.5.0" {
		t.Errorf("metadata not preserved: %+v", got)
	}
}
