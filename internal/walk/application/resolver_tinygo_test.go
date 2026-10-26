package application_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"

	domain3 "code.eitanity.com/kanonarion/internal/walk/domain"
	walkports "code.eitanity.com/kanonarion/internal/walk/ports"
)

func tinyGoBuildList() walkports.BuildList {
	bl := buildListWithEnv()
	bl.TinyGoTarget, bl.TinyGoVersion = "wasip1", "0.42.0"
	bl.TinyGo = &domain3.TinyGoFacts{Target: "wasip1", Packages: []string{"os", "runtime"}}
	bl.GoPackages = []string{"io", "strconv"}
	return bl
}

func resolveTinyGoProject(t *testing.T, bl *fakeBuildListResolver) (domain3.Graph, coordinate.ModuleCoordinate) {
	t.Helper()
	r, _ := buildListResolver(t, bl)
	target := coord("example.com/project", coordinate.LocalVersion)
	g, err := r.ResolveProject(context.Background(), target, []byte("module example.com/project\n\ngo 1.21\n"), "/proj",
		domain3.DefaultDepthPolicy().FetchStage(), nil, false, false)
	if err != nil {
		t.Fatalf("ResolveProject: %v", err)
	}
	return g, target
}

func TestResolveProject_TinyGo_RecordsTheSplit(t *testing.T) {
	g, target := resolveTinyGoProject(t, &fakeBuildListResolver{list: tinyGoBuildList()})

	var node *domain3.GraphNode
	for i, n := range g.Nodes {
		if n.ResolutionSource == domain3.ResolutionTinyGo {
			node = &g.Nodes[i]
		}
	}
	if node == nil {
		t.Fatal("a TinyGo walk holds no TinyGo node")
	}
	if node.Coordinate.String() != "github.com/tinygo-org/tinygo@v0.42.0" || node.DirectDependency ||
		node.TinyGo == nil || !reflect.DeepEqual(node.TinyGo.Packages, []string{"os", "runtime"}) {
		t.Errorf("TinyGo node = %+v", node)
	}
	edge := false
	for _, e := range g.Edges {
		if e.From == target && e.To == node.Coordinate {
			edge = true
		}
	}
	if !edge {
		t.Error("no root→TinyGo edge, as the stdlib node has")
	}
	if got := stdlibNode(t, g).Packages; !reflect.DeepEqual(got, []string{"io", "strconv"}) {
		t.Errorf("stdlib packages = %v, want the Go-served set", got)
	}
}

func TestResolveProject_HostWalk_HasNoSplit(t *testing.T) {
	g, _ := resolveTinyGoProject(t, &fakeBuildListResolver{list: buildListWithEnv()})
	for _, n := range g.Nodes {
		if n.ResolutionSource == domain3.ResolutionTinyGo || n.TinyGo != nil || n.Packages != nil {
			t.Errorf("a host walk carries a TinyGo field on %s", n.Coordinate)
		}
	}
}

func TestResolveProject_TinyGo_AttachesToTheProjectsOwnTinyGoDependency(t *testing.T) {
	bl := tinyGoBuildList()
	bl.Modules = append(bl.Modules, walkports.BuildListModule{Path: domain3.TinyGoModulePath, Version: "v0.41.0"})
	bl.Edges = append(bl.Edges, walkports.BuildListEdge{From: "example.com/project", To: domain3.TinyGoModulePath + "@v0.41.0"})

	g, _ := resolveTinyGoProject(t, &fakeBuildListResolver{list: bl})

	var held []domain3.GraphNode
	for _, n := range g.Nodes {
		if n.Coordinate.Path() == domain3.TinyGoModulePath {
			held = append(held, n)
		}
	}
	if len(held) != 1 {
		t.Fatalf("%d nodes for TinyGo's module, want the project's dependency alone", len(held))
	}
	if held[0].Coordinate.Version() != "v0.41.0" || held[0].ResolutionSource == domain3.ResolutionTinyGo || held[0].TinyGo == nil {
		t.Errorf("the split did not attach to the dependency: %+v", held[0])
	}
}

func TestResolveProject_TinyGo_UnusableReleaseRecordsNoHalfSplit(t *testing.T) {
	bl := tinyGoBuildList()
	bl.TinyGoVersion = "not a version"
	g, _ := resolveTinyGoProject(t, &fakeBuildListResolver{list: bl})
	if _, ok := g.TinyGoPartition(); ok {
		t.Error("a release that is no version still named a TinyGo node")
	}
	if stdlibNode(t, g).Packages != nil {
		t.Error("the stdlib node holds Go's half of a split whose TinyGo half was not recorded")
	}
}

func TestResolveProject_TinyGo_AFailedBuildListRecordsNoSplit(t *testing.T) {
	g, _ := resolveTinyGoProject(t, &fakeBuildListResolver{err: errors.New("go list -deps -json ./...: exit status 1")})
	if _, ok := g.TinyGoPartition(); ok {
		t.Error("a walk whose build list failed carries a TinyGo split")
	}
	if g.BuildListUnavailable == "" {
		t.Error("the failure is not on the graph")
	}
}
