package application_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/walk/application"
	domain3 "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// fakeBuildListResolver returns a canned BuildList (or an error) without invoking
// the Go toolchain.
type fakeBuildListResolver struct {
	list walkports.BuildList
	err  error
}

func (f *fakeBuildListResolver) Resolve(_ context.Context, _ string) (walkports.BuildList, error) {
	if f.err != nil {
		return walkports.BuildList{}, f.err
	}
	return f.list, nil
}

// sampleBuildList exercises every node class: plain MVS (direct + indirect),
// module replacement, and filesystem replacement, plus an edge whose constraint
// version differs from the selected version, a duplicate edge, and pseudo-nodes.
func sampleBuildList() walkports.BuildList {
	return walkports.BuildList{
		Modules: []walkports.BuildListModule{
			{Path: "example.com/project", Main: true},
			{Path: "golang.org/x/mod", Version: "v0.35.0", Indirect: false},
			{Path: "golang.org/x/sys", Version: "v0.20.0", Indirect: true},
			{
				Path: "example.com/forked", Version: "v1.0.0", Indirect: false,
				Replace: &walkports.BuildListReplace{Path: "example.com/fork", Version: "v1.2.0"},
			},
			{
				Path: "example.com/local", Version: "v0.0.0", Indirect: false,
				Replace: &walkports.BuildListReplace{Path: "../local"},
			},
		},
		Edges: []walkports.BuildListEdge{
			{From: "example.com/project", To: "golang.org/x/mod@v0.35.0"},
			// Constraint v0.18.0 must normalise To.Version to the selected v0.20.0.
			{From: "example.com/project", To: "golang.org/x/sys@v0.18.0"},
			{From: "golang.org/x/mod@v0.35.0", To: "golang.org/x/sys@v0.20.0"},
			// Duplicate of the first edge — must be deduped.
			{From: "example.com/project", To: "golang.org/x/mod@v0.35.0"},
			// Pseudo-nodes — must be excluded.
			{From: "example.com/project", To: "go@1.23"},
			{From: "example.com/project", To: "toolchain@go1.23.4"},
		},
	}
}

// buildListResolver wires newResolver's fakes plus a fake build-list resolver.
func buildListResolver(t *testing.T, bl *fakeBuildListResolver) (*application.GraphResolver, *fakeModuleFetcher) {
	t.Helper()
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("golang.org/x/mod", "v0.35.0", "module golang.org/x/mod\n", blobs)
	fetcher.addRetracted("golang.org/x/sys", "v0.20.0", "module golang.org/x/sys\n", blobs)
	fetcher.add("example.com/fork", "v1.2.0", "module example.com/fork\n", blobs)
	return newResolver(fetcher, blobs).WithBuildListResolver(bl), fetcher
}

func TestResolveProject_BuildList_NodeMapping(t *testing.T) {
	r, _ := buildListResolver(t, &fakeBuildListResolver{list: sampleBuildList()})
	target := coord("example.com/project", domain2.LocalVersion)

	g, err := r.ResolveProject(context.Background(), target, nil, "/proj", domain3.DefaultDepthPolicy().FetchStage(), nil, false)
	if err != nil {
		t.Fatalf("ResolveProject: %v", err)
	}
	if g.Partial {
		t.Fatalf("graph should not be partial: %s", g.PartialReason)
	}

	byPath := map[string]domain3.GraphNode{}
	for _, n := range g.Nodes {
		byPath[n.Coordinate.Path] = n
	}

	// Main module: local anchor, unfetched.
	root := byPath["example.com/project"]
	if root.Coordinate != target {
		t.Errorf("root coordinate = %s, want %s", root.Coordinate, target)
	}
	if root.ResolutionSource != domain3.ResolutionLocalMainModule {
		t.Errorf("root source = %s, want local_main_module", root.ResolutionSource)
	}

	// Plain MVS direct + indirect.
	if mod := byPath["golang.org/x/mod"]; mod.ResolutionSource != domain3.ResolutionMVS ||
		!mod.DirectDependency || mod.Coordinate.Version != "v0.35.0" {
		t.Errorf("golang.org/x/mod node = %+v, want mvs/direct/v0.35.0", mod)
	}
	sys := byPath["golang.org/x/sys"]
	if sys.ResolutionSource != domain3.ResolutionMVS || sys.DirectDependency {
		t.Errorf("golang.org/x/sys node = %+v, want mvs/indirect", sys)
	}
	if !sys.Retracted {
		t.Errorf("golang.org/x/sys should carry the fetched record's Retracted flag")
	}

	// Module replacement → ResolutionReplace at the replacement coordinate.
	fork, ok := byPath["example.com/fork"]
	if !ok {
		t.Fatalf("replacement node example.com/fork missing; nodes: %v", byPath)
	}
	if fork.ResolutionSource != domain3.ResolutionReplace {
		t.Errorf("fork source = %s, want replace", fork.ResolutionSource)
	}
	if fork.Coordinate != coord("example.com/fork", "v1.2.0") {
		t.Errorf("fork coordinate = %s, want example.com/fork@v1.2.0", fork.Coordinate)
	}
	if fork.OriginalCoordinate != coord("example.com/forked", "v1.0.0") {
		t.Errorf("fork OriginalCoordinate = %s, want example.com/forked@v1.0.0", fork.OriginalCoordinate)
	}

	// Filesystem replacement → ResolutionLocalReplace, unfetched, LocalPath set.
	local := byPath["example.com/local"]
	if local.ResolutionSource != domain3.ResolutionLocalReplace {
		t.Errorf("local source = %s, want local_replace", local.ResolutionSource)
	}
	if local.LocalPath != "../local" {
		t.Errorf("local LocalPath = %q, want ../local", local.LocalPath)
	}
	if local.Coordinate != coord("example.com/local", "v0.0.0") {
		t.Errorf("local coordinate = %s, want example.com/local@v0.0.0", local.Coordinate)
	}
	if !g.HasLocalReplace {
		t.Errorf("graph HasLocalReplace should be true with a filesystem replacement")
	}

	if len(g.Nodes) != 5 {
		t.Errorf("node count = %d, want 5 (project + mod + sys + fork + local)", len(g.Nodes))
	}
}

func TestResolveProject_BuildList_Edges(t *testing.T) {
	r, _ := buildListResolver(t, &fakeBuildListResolver{list: sampleBuildList()})
	target := coord("example.com/project", domain2.LocalVersion)

	g, err := r.ResolveProject(context.Background(), target, nil, "/proj", domain3.DefaultDepthPolicy().FetchStage(), nil, false)
	if err != nil {
		t.Fatalf("ResolveProject: %v", err)
	}

	want := []domain3.GraphEdge{
		// Main-module edges normalise the From endpoint to the local anchor.
		{From: target, To: coord("golang.org/x/mod", "v0.35.0"), ConstraintVersion: "v0.35.0"},
		// To.Version normalised to selected v0.20.0; ConstraintVersion keeps v0.18.0.
		{From: target, To: coord("golang.org/x/sys", "v0.20.0"), ConstraintVersion: "v0.18.0"},
		{From: coord("golang.org/x/mod", "v0.35.0"), To: coord("golang.org/x/sys", "v0.20.0"), ConstraintVersion: "v0.20.0"},
	}
	if !reflect.DeepEqual(g.Edges, want) {
		t.Errorf("edges mismatch:\n got %+v\nwant %+v", g.Edges, want)
	}
}

func TestResolveProject_BuildList_FetchFailureIsPartial(t *testing.T) {
	bl := &fakeBuildListResolver{list: walkports.BuildList{
		Modules: []walkports.BuildListModule{
			{Path: "example.com/project", Main: true},
			{Path: "example.com/missing", Version: "v1.0.0"},
		},
	}}
	// buildListResolver seeds the common fixtures but not example.com/missing, so
	// EnsureFetched fails for it.
	r, _ := buildListResolver(t, bl)
	target := coord("example.com/project", domain2.LocalVersion)

	g, err := r.ResolveProject(context.Background(), target, nil, "/proj", domain3.DefaultDepthPolicy().FetchStage(), nil, false)
	if err != nil {
		t.Fatalf("ResolveProject: %v", err)
	}
	if !g.Partial {
		t.Fatalf("graph should be partial when a listed module fails to fetch")
	}
	if !strings.Contains(g.PartialReason, "fetch_failed") {
		t.Errorf("PartialReason = %q, want it to mention fetch_failed", g.PartialReason)
	}

	var missing domain3.GraphNode
	for _, n := range g.Nodes {
		if n.Coordinate.Path == "example.com/missing" {
			missing = n
		}
	}
	if missing.ResolutionSource != domain3.ResolutionFetchFailed {
		t.Errorf("missing node source = %s, want fetch_failed", missing.ResolutionSource)
	}
	if missing.ErrorDetail == "" {
		t.Errorf("fetch-failed node should carry an ErrorDetail")
	}
}

func TestResolveProject_BuildList_Deterministic(t *testing.T) {
	target := coord("example.com/project", domain2.LocalVersion)

	run := func() domain3.Graph {
		r, _ := buildListResolver(t, &fakeBuildListResolver{list: sampleBuildList()})
		g, err := r.ResolveProject(context.Background(), target, nil, "/proj", domain3.DefaultDepthPolicy().FetchStage(), nil, false)
		if err != nil {
			t.Fatalf("ResolveProject: %v", err)
		}
		return g
	}
	a, b := run(), run()
	if !reflect.DeepEqual(a.Nodes, b.Nodes) {
		t.Errorf("nodes not deterministic across runs:\n%+v\n%+v", a.Nodes, b.Nodes)
	}
	if !reflect.DeepEqual(a.Edges, b.Edges) {
		t.Errorf("edges not deterministic across runs:\n%+v\n%+v", a.Edges, b.Edges)
	}
}

// TestResolveProject_BuildList_FallbackOnToolchainError asserts that when the Go
// toolchain is unavailable the walk completes via the internal resolver and is
// marked Partial with the build-list-approximate caveat (never presenting the
// approximate set as authoritative).
func TestResolveProject_BuildList_FallbackOnToolchainError(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/dep", "v1.0.0", "module example.com/dep\n\ngo 1.21\n", blobs)

	bl := &fakeBuildListResolver{err: errors.New("exec: \"go\": executable file not found in $PATH")}
	r := newResolver(fetcher, blobs).WithBuildListResolver(bl)
	target := coord("example.com/project", domain2.LocalVersion)

	mainGoMod := []byte("module example.com/project\n\ngo 1.21\n\nrequire example.com/dep v1.0.0\n")
	g, err := r.ResolveProject(context.Background(), target, mainGoMod, "/proj", domain3.DefaultDepthPolicy().FetchStage(), nil, false)
	if err != nil {
		t.Fatalf("ResolveProject: %v", err)
	}
	if !g.Partial {
		t.Fatalf("toolchain-absent walk should be Partial")
	}
	if !strings.Contains(g.PartialReason, "build_list_approximate") ||
		!strings.Contains(g.PartialReason, "go toolchain unavailable") {
		t.Errorf("PartialReason = %q, want it to name the toolchain unavailability", g.PartialReason)
	}
	// The internal resolver still produced the closure.
	var depPresent bool
	for _, n := range g.Nodes {
		if n.Coordinate.Path == "example.com/dep" {
			depPresent = true
		}
	}
	if !depPresent {
		t.Errorf("fallback closure should still contain example.com/dep")
	}
}

// toolScopeBuildList models a project whose build list mixes production deps
// with a tool directive's closure and a dependency shared by both.
func toolScopeBuildList() walkports.BuildList {
	return walkports.BuildList{
		Modules: []walkports.BuildListModule{
			{Path: "example.com/project", Main: true},
			{Path: "example.com/prod", Version: "v1.0.0", Indirect: false},
			{Path: "example.com/tool", Version: "v2.0.0", Indirect: true},
			{Path: "example.com/toolsub", Version: "v1.0.0", Indirect: true},
			{Path: "example.com/shared", Version: "v1.0.0", Indirect: true},
		},
		Edges: []walkports.BuildListEdge{
			{From: "example.com/project", To: "example.com/prod@v1.0.0"},
			{From: "example.com/project", To: "example.com/tool@v2.0.0"},
			{From: "example.com/prod@v1.0.0", To: "example.com/shared@v1.0.0"},
			{From: "example.com/tool@v2.0.0", To: "example.com/toolsub@v1.0.0"},
			{From: "example.com/tool@v2.0.0", To: "example.com/shared@v1.0.0"},
		},
	}
}

// A tool-scoped project walk restricts the build list to the tooling supply
// chain: the main anchor plus the tool directive's closure, excluding
// production-only modules. A dependency shared with production survives.
func TestResolveProject_ToolScope_RestrictsToToolClosure(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/prod", "v1.0.0", "module example.com/prod\n", blobs)
	fetcher.add("example.com/tool", "v2.0.0", "module example.com/tool\n", blobs)
	fetcher.add("example.com/toolsub", "v1.0.0", "module example.com/toolsub\n", blobs)
	fetcher.add("example.com/shared", "v1.0.0", "module example.com/shared\n", blobs)
	r := newResolver(fetcher, blobs).WithBuildListResolver(&fakeBuildListResolver{list: toolScopeBuildList()})
	target := coord("example.com/project", domain2.LocalVersion)

	goMod := []byte("module example.com/project\n\ngo 1.24\n\ntool example.com/tool/cmd/lint\n")
	// The caller (CLI) resolves the tool scope's module set via the toolchain;
	// here it is the tool directive's closure.
	toolSet := []string{"example.com/tool", "example.com/toolsub", "example.com/shared"}
	g, err := r.ResolveProject(context.Background(), target, goMod, "/proj", domain3.DefaultDepthPolicy().FetchStage(), toolSet, false)
	if err != nil {
		t.Fatalf("ResolveProject: %v", err)
	}

	paths := map[string]bool{}
	for _, n := range g.Nodes {
		paths[n.Coordinate.Path] = true
	}
	for _, want := range []string{"example.com/project", "example.com/tool", "example.com/toolsub", "example.com/shared"} {
		if !paths[want] {
			t.Errorf("tool-scope walk missing %s; have %v", want, paths)
		}
	}
	if paths["example.com/prod"] {
		t.Errorf("production-only example.com/prod must not appear in a tool-scope walk")
	}
}

// The default (production) scope keeps the whole build list, including tool deps
// — it is the project's complete build-dependency set.
func TestResolveProject_ProductionScope_KeepsWholeBuildList(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/prod", "v1.0.0", "module example.com/prod\n", blobs)
	fetcher.add("example.com/tool", "v2.0.0", "module example.com/tool\n", blobs)
	fetcher.add("example.com/toolsub", "v1.0.0", "module example.com/toolsub\n", blobs)
	fetcher.add("example.com/shared", "v1.0.0", "module example.com/shared\n", blobs)
	r := newResolver(fetcher, blobs).WithBuildListResolver(&fakeBuildListResolver{list: toolScopeBuildList()})
	target := coord("example.com/project", domain2.LocalVersion)

	goMod := []byte("module example.com/project\n\ngo 1.24\n\ntool example.com/tool/cmd/lint\n")
	g, err := r.ResolveProject(context.Background(), target, goMod, "/proj", domain3.DefaultDepthPolicy().FetchStage(), nil, false)
	if err != nil {
		t.Fatalf("ResolveProject: %v", err)
	}
	// Whole build list (4 modules incl. tools) plus the project anchor and the
	// synthetic stdlib node injected from the go.mod directive (the fake build
	// list reports no toolchain version).
	if len(g.Nodes) != 6 {
		t.Errorf("production scope node count = %d, want 6 (whole build list incl. tools + stdlib)", len(g.Nodes))
	}
	if !hasStdlibNode(g) {
		t.Errorf("stdlib node missing from project build list")
	}
}

// hasStdlibNode reports whether g contains the synthetic standard-library node.
func hasStdlibNode(g domain3.Graph) bool {
	for _, n := range g.Nodes {
		if n.ResolutionSource == domain3.ResolutionStdlib {
			return true
		}
	}
	return false
}

// TestResolveProject_NoBuildListResolver_NoCaveat asserts that when no
// BuildListResolver is wired at all (e.g. the published single-module path or a
// legacy test), the internal resolver runs with no spurious Partial caveat.
func TestResolveProject_NoBuildListResolver_NoCaveat(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/dep", "v1.0.0", "module example.com/dep\n\ngo 1.21\n", blobs)

	r := newResolver(fetcher, blobs) // no WithBuildListResolver
	target := coord("example.com/project", domain2.LocalVersion)
	mainGoMod := []byte("module example.com/project\n\ngo 1.21\n\nrequire example.com/dep v1.0.0\n")

	g, err := r.ResolveProject(context.Background(), target, mainGoMod, "/proj", domain3.DefaultDepthPolicy().FetchStage(), nil, false)
	if err != nil {
		t.Fatalf("ResolveProject: %v", err)
	}
	if g.Partial {
		t.Errorf("legacy path should not be partial: %s", g.PartialReason)
	}
}
