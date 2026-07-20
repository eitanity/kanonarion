package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"

	"github.com/eitanity/kanonarion/internal/local/domain"
)

func makeRecord(t *testing.T, modPath, modVer string, nodes []callgraphdomain.CallNode, edges []callgraphdomain.CallEdge) callgraphdomain.CallGraphRecord {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate(modPath, modVer)
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	return callgraphdomain.CallGraphRecord{
		Coordinate:    coord,
		OverallStatus: callgraphdomain.CallGraphStatusExtracted,
		Nodes:         nodes,
		Edges:         edges,
	}
}

func TestNewAnalysisSession_Empty(t *testing.T) {
	s := domain.NewAnalysisSession(nil)
	if s.ModuleCount() != 0 {
		t.Errorf("ModuleCount = %d, want 0", s.ModuleCount())
	}
}

func TestNewAnalysisSession_ModuleCount(t *testing.T) {
	r1 := makeRecord(t, "example.com/a", "v1.0.0", nil, nil)
	r2 := makeRecord(t, "example.com/b", "v1.0.0", nil, nil)
	s := domain.NewAnalysisSession([]callgraphdomain.CallGraphRecord{r1, r2})
	if s.ModuleCount() != 2 {
		t.Errorf("ModuleCount = %d, want 2", s.ModuleCount())
	}
}

func TestNewAnalysisSession_ModuleRecord_Found(t *testing.T) {
	r := makeRecord(t, "example.com/a", "v1.0.0", nil, nil)
	s := domain.NewAnalysisSession([]callgraphdomain.CallGraphRecord{r})
	got, ok := s.ModuleRecord("example.com/a")
	if !ok {
		t.Fatal("ModuleRecord returned not found")
	}
	if got.Coordinate.Path != "example.com/a" {
		t.Errorf("ModuleRecord.Path = %q, want %q", got.Coordinate.Path, "example.com/a")
	}
}

func TestNewAnalysisSession_ModuleRecord_NotFound(t *testing.T) {
	s := domain.NewAnalysisSession(nil)
	_, ok := s.ModuleRecord("example.com/missing")
	if ok {
		t.Error("expected not found, got found")
	}
}

func TestNewAnalysisSession_FindNode_Found(t *testing.T) {
	node := callgraphdomain.CallNode{
		ID:      "example.com/a.Foo",
		Module:  "example.com/a",
		Package: "example.com/a",
		Symbol:  "Foo",
	}
	r := makeRecord(t, "example.com/a", "v1.0.0", []callgraphdomain.CallNode{node}, nil)
	s := domain.NewAnalysisSession([]callgraphdomain.CallGraphRecord{r})
	got, ok := s.FindNode("example.com/a.Foo")
	if !ok {
		t.Fatal("FindNode returned not found")
	}
	if got.Symbol != "Foo" {
		t.Errorf("Symbol = %q, want %q", got.Symbol, "Foo")
	}
}

func TestNewAnalysisSession_FindNode_NotFound(t *testing.T) {
	s := domain.NewAnalysisSession(nil)
	_, ok := s.FindNode("example.com/a.Missing")
	if ok {
		t.Error("expected not found, got found")
	}
}

func TestNewAnalysisSession_FindNode_AcrossModules(t *testing.T) {
	nodeA := callgraphdomain.CallNode{ID: "example.com/a.A", Module: "example.com/a", Package: "example.com/a", Symbol: "A"}
	nodeB := callgraphdomain.CallNode{ID: "example.com/b.B", Module: "example.com/b", Package: "example.com/b", Symbol: "B"}
	r1 := makeRecord(t, "example.com/a", "v1.0.0", []callgraphdomain.CallNode{nodeA}, nil)
	r2 := makeRecord(t, "example.com/b", "v1.0.0", []callgraphdomain.CallNode{nodeB}, nil)
	s := domain.NewAnalysisSession([]callgraphdomain.CallGraphRecord{r1, r2})

	if _, ok := s.FindNode("example.com/a.A"); !ok {
		t.Error("FindNode: example.com/a.A not found")
	}
	if _, ok := s.FindNode("example.com/b.B"); !ok {
		t.Error("FindNode: example.com/b.B not found")
	}
}

func TestNewAnalysisSession_OutEdges_Found(t *testing.T) {
	edge := callgraphdomain.CallEdge{
		FromID:     "example.com/a.Foo",
		ToID:       "example.com/b.Bar",
		Confidence: callgraphdomain.ConfidenceDirect,
	}
	r := makeRecord(t, "example.com/a", "v1.0.0", nil, []callgraphdomain.CallEdge{edge})
	s := domain.NewAnalysisSession([]callgraphdomain.CallGraphRecord{r})
	edges := s.OutEdges("example.com/a.Foo")
	if len(edges) != 1 {
		t.Fatalf("OutEdges count = %d, want 1", len(edges))
	}
	if edges[0].ToID != "example.com/b.Bar" {
		t.Errorf("edge.ToID = %q, want %q", edges[0].ToID, "example.com/b.Bar")
	}
}

func TestNewAnalysisSession_OutEdges_None(t *testing.T) {
	s := domain.NewAnalysisSession(nil)
	if edges := s.OutEdges("example.com/a.Leaf"); edges != nil {
		t.Errorf("OutEdges on unknown symbol = %v, want nil", edges)
	}
}

func TestNewAnalysisSession_OutEdges_AcrossModules(t *testing.T) {
	edgeA := callgraphdomain.CallEdge{FromID: "example.com/a.A", ToID: "example.com/b.B", Confidence: callgraphdomain.ConfidenceDirect}
	edgeB := callgraphdomain.CallEdge{FromID: "example.com/b.B", ToID: "example.com/c.C", Confidence: callgraphdomain.ConfidenceDirect}
	r1 := makeRecord(t, "example.com/a", "v1.0.0", nil, []callgraphdomain.CallEdge{edgeA})
	r2 := makeRecord(t, "example.com/b", "v1.0.0", nil, []callgraphdomain.CallEdge{edgeB})
	s := domain.NewAnalysisSession([]callgraphdomain.CallGraphRecord{r1, r2})

	if out := s.OutEdges("example.com/a.A"); len(out) != 1 || out[0].ToID != "example.com/b.B" {
		t.Errorf("OutEdges(a.A) = %v", out)
	}
	if out := s.OutEdges("example.com/b.B"); len(out) != 1 || out[0].ToID != "example.com/c.C" {
		t.Errorf("OutEdges(b.B) = %v", out)
	}
}

func TestNewAnalysisSession_MultipleEdgesFromSameNode(t *testing.T) {
	e1 := callgraphdomain.CallEdge{FromID: "example.com/a.Foo", ToID: "example.com/b.X", Confidence: callgraphdomain.ConfidenceDirect}
	e2 := callgraphdomain.CallEdge{FromID: "example.com/a.Foo", ToID: "example.com/b.Y", Confidence: callgraphdomain.ConfidenceDirect}
	r := makeRecord(t, "example.com/a", "v1.0.0", nil, []callgraphdomain.CallEdge{e1, e2})
	s := domain.NewAnalysisSession([]callgraphdomain.CallGraphRecord{r})
	edges := s.OutEdges("example.com/a.Foo")
	if len(edges) != 2 {
		t.Errorf("OutEdges count = %d, want 2", len(edges))
	}
}
