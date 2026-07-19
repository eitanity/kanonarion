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

// A module-replaced dependency (Coordinate = replacement path, OriginalCoordinate
// = original require path) is in scope when its ORIGINAL path is kept — the keep
// set is built from require/import paths, which never surface the replacement.
// Matching only Coordinate.Path would drop it, losing the replaced module's
// entire surface (regression: mattn/go-sqlite3 => rqlite/go-sqlite3 vanished from
// the walk though it is linked into the binary).
func TestFilterGraphToScope_KeepsModuleReplaceByOriginalPath(t *testing.T) {
	main := c("example.com/project", fetchdomain.LocalVersion)
	replaced := GraphNode{
		Coordinate:         c("example.com/fork", "v1.47.0"), // replacement (what compiles)
		OriginalCoordinate: c("example.com/orig", "v1.14.0"), // require path (in keep)
		ResolutionSource:   ResolutionReplace,
		DirectDependency:   true,
	}
	g := Graph{
		Target: main,
		Nodes: []GraphNode{
			{Coordinate: main, ResolutionSource: ResolutionLocalMainModule},
			replaced,
		},
		// go mod graph keys the edge by the original require path; nodeByPath may
		// normalise it to the replacement — the filter must keep it either way.
		Edges: []GraphEdge{
			{From: main, To: c("example.com/orig", "v1.14.0")},
			{From: main, To: c("example.com/fork", "v1.47.0")},
		},
	}

	// keep carries the ORIGINAL path only, exactly as `go list -deps` reports it.
	got := FilterGraphToScope(g, main.Path, []string{"example.com/orig"})

	paths := map[string]bool{}
	for _, n := range got.Nodes {
		paths[n.Coordinate.Path] = true
	}
	if !paths["example.com/fork"] {
		t.Fatalf("module-replace node dropped; scope kept %v", paths)
	}
	if len(got.Edges) != 2 {
		t.Errorf("edge count = %d, want 2 (edge keyed by either original or replacement path must survive)", len(got.Edges))
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

// TestFilterGraphToScope_PreservesBuildEnv verifies the build environment (a
// property of the whole resolution, not any node) survives scope filtering, so a
// code- or tool-scoped SBOM records the same platform as the complete scope.
func TestFilterGraphToScope_PreservesBuildEnv(t *testing.T) {
	in := Graph{
		Target:   c("example.com/main", "local"),
		Nodes:    []GraphNode{{Coordinate: c("example.com/main", "local")}},
		BuildEnv: BuildEnv{GOOS: "linux", GOARCH: "amd64", GoVersion: "go1.26.4"},
	}
	out := FilterGraphToScope(in, "example.com/main", nil)
	if out.BuildEnv != in.BuildEnv {
		t.Errorf("BuildEnv after scope filter = %+v, want %+v", out.BuildEnv, in.BuildEnv)
	}
}
