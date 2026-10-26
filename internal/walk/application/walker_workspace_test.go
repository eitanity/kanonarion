package application_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
	domain "code.eitanity.com/kanonarion/internal/walk/domain"
	walkports "code.eitanity.com/kanonarion/internal/walk/ports"

	application2 "code.eitanity.com/kanonarion/internal/walk/application"
)

// workspaceBuildList is what the toolchain reports from member a of a go.work
// holding a and b, where a replaces c with ../c: both members are main modules,
// and the replace path comes back relative to the go.work directory.
func workspaceBuildList() walkports.BuildList {
	return walkports.BuildList{
		WorkDir: "/ws",
		Modules: []walkports.BuildListModule{
			{Path: "example.com/ws/a", Main: true, Dir: "/ws/a"},
			{Path: "example.com/ws/b", Main: true, Dir: "/ws/b"},
			{
				Path: "example.com/ws/c", Version: "v1.2.3",
				Replace: &walkports.BuildListReplace{Path: "./c"}, Dir: "/ws/c",
			},
			{Path: "example.com/dep", Version: "v1.0.0", Indirect: true},
		},
		Edges: []walkports.BuildListEdge{
			{From: "example.com/ws/a", To: "example.com/ws/c@v1.2.3"},
			{From: "example.com/ws/a", To: "go@1.22"},
			{From: "example.com/ws/b", To: "example.com/dep@v1.0.0"},
			{From: "example.com/ws/b", To: "go@1.22"},
		},
	}
}

func walkWorkspace(t *testing.T, lf *fakeLocalFetcher) domain.WalkOutcome {
	t.Helper()
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(t, "example.com/dep", "v1.0.0", "module example.com/dep\ngo 1.21\n", blobs)
	wf := newWalkerFetcher()
	wf.addRecord(t, "example.com/dep", "v1.0.0")

	resolver := application2.NewGraphResolver(
		newXmodParser(), rf, blobs, fixedClock{fixedNow}, "",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	).WithBuildListResolver(&fakeBuildListResolver{list: workspaceBuildList()})
	w := application2.NewWalker(resolver, wf, lf, fixedClock{fixedNow}, fakeStopwatch{}, 1,
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target:          coord("example.com/ws/a", coordinate.LocalVersion),
		ProjectMode:     true,
		MainModuleGoMod: []byte("module example.com/ws/a\n\ngo 1.22\n\nrequire example.com/ws/c v1.2.3\n\nreplace example.com/ws/c v1.2.3 => ../c\n"),
		ProjectDir:      "/ws/a",
		ResolutionDir:   "/ws/a",
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	return outcome
}

// A workspace member and a local replacement each become a node at their own
// local identity, read from disk: the member from its module directory, the
// replacement against the go.work directory, as the go command reads it.
func TestWalker_WorkspaceMembersAndReplacementsHaveLocalIdentity(t *testing.T) {
	lf := newFakeLocalFetcher()
	lf.addRecord(t, "example.com/ws/b", coordinate.LocalVersion)
	lf.addRecord(t, "example.com/ws/c", coordinate.LocalVersion)

	outcome := walkWorkspace(t, lf)

	root := coord("example.com/ws/a", coordinate.LocalVersion)
	member := coord("example.com/ws/b", coordinate.LocalVersion)
	replaced := coord("example.com/ws/c", coordinate.LocalVersion)
	assertWorkspaceNodes(t, outcome.Graph, member, replaced)
	assertWorkspaceEdges(t, outcome.Graph, root, member, replaced)
	assertWorkspaceReads(t, lf, member, replaced)
	for _, c := range []coordinate.ModuleCoordinate{member, replaced} {
		if r := outcome.PerNodeResults[c]; r.Status != domain.NodeSucceeded || r.FetchRecord == nil {
			t.Errorf("%s result = %s, want succeeded with its local record", c, r.Status)
		}
	}
	if outcome.OverallStatus != domain.WalkSucceeded {
		t.Errorf("overall status = %s, want succeeded", outcome.OverallStatus)
	}
}

func assertWorkspaceNodes(t *testing.T, g domain.Graph, member, replaced coordinate.ModuleCoordinate) {
	t.Helper()
	nodes := map[coordinate.ModuleCoordinate]domain.GraphNode{}
	for _, n := range g.Nodes {
		nodes[n.Coordinate] = n
	}
	if n := nodes[member]; n.ResolutionSource != domain.ResolutionLocalWorkspaceMember || !n.OriginalCoordinate.IsZero() || n.LocalPath != "" {
		t.Errorf("member node = %+v, want local_workspace_member with no original and no path", n)
	}
	if n := nodes[replaced]; n.ResolutionSource != domain.ResolutionLocalReplace ||
		n.OriginalCoordinate != coord("example.com/ws/c", "v1.2.3") || n.LocalPath != "./c" {
		t.Errorf("replacement node = %+v, want local_replace of example.com/ws/c@v1.2.3 at ./c", n)
	}
	if _, ok := nodes[coord("example.com/ws/c", "v1.2.3")]; ok {
		t.Error("the published coordinate of the replaced module is a node; the local code must not be filed under it")
	}
}

func assertWorkspaceEdges(t *testing.T, g domain.Graph, root, member, replaced coordinate.ModuleCoordinate) {
	t.Helper()
	edges := map[string]bool{}
	for _, e := range g.Edges {
		edges[e.From.String()+" -> "+e.To.String()] = true
	}
	for _, want := range []string{
		root.String() + " -> " + member.String(),
		root.String() + " -> " + replaced.String(),
		member.String() + " -> example.com/dep@v1.0.0",
	} {
		if !edges[want] {
			t.Errorf("edge %s missing; edges %v", want, edges)
		}
	}
}

func assertWorkspaceReads(t *testing.T, lf *fakeLocalFetcher, member, replaced coordinate.ModuleCoordinate) {
	t.Helper()
	reads := map[coordinate.ModuleCoordinate]localFetchCall{}
	for _, c := range lf.calls {
		reads[c.coord] = c
	}
	if c := reads[member]; c.absPath != "/ws/b" || c.writtenPath != "" {
		t.Errorf("member read = %+v, want /ws/b with no written path", c)
	}
	if c := reads[replaced]; c.absPath != "/ws/c" || c.writtenPath != "./c" {
		t.Errorf("replacement read = %+v, want /ws/c recorded as ./c", c)
	}
}

// A workspace build list scoped to a set that names the member keeps it; one
// that does not drops it, as any module outside the scope is dropped.
func TestResolveProject_WorkspaceMemberFollowsScope(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(t, "example.com/dep", "v1.0.0", "module example.com/dep\ngo 1.21\n", blobs)
	r := newResolver(rf, blobs).WithBuildListResolver(&fakeBuildListResolver{list: workspaceBuildList()})
	target := coord("example.com/ws/a", coordinate.LocalVersion)
	member := coord("example.com/ws/b", coordinate.LocalVersion)

	for _, tc := range []struct {
		name  string
		scope []string
		want  bool
	}{
		{"member in scope", []string{"example.com/ws/b", "example.com/ws/c"}, true},
		{"member out of scope", []string{"example.com/ws/c"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, err := r.ResolveProject(context.Background(), target, nil, "/ws/a", domain.DefaultDepthPolicy().FetchStage(), tc.scope, false, false)
			if err != nil {
				t.Fatalf("ResolveProject: %v", err)
			}
			got := false
			for _, n := range g.Nodes {
				if n.Coordinate == member {
					got = true
				}
			}
			if got != tc.want {
				t.Errorf("member in graph = %v, want %v", got, tc.want)
			}
		})
	}
}
