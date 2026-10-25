package application

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	domain2 "github.com/eitanity/kanonarion/internal/walk/domain"
)

// The TinyGo node ships with the toolchain: it is recorded succeeded with no
// fetch record, as the stdlib node is, and never queued for a fetch.
func TestClassifyGraphNodes_TinyGoNodeIsUnfetchedAndSucceeded(t *testing.T) {
	target := coordinatetest.MustNew("example.com/project", coordinate.LocalVersion)
	node, ok := domain2.TinyGoNode("0.42.0", domain2.TinyGoFacts{Target: "pico", Packages: []string{"machine"}})
	if !ok {
		t.Fatal("TinyGoNode refused 0.42.0")
	}
	graph := domain2.Graph{Target: target, Nodes: []domain2.GraphNode{
		{Coordinate: target, ResolutionSource: domain2.ResolutionLocalMainModule}, node,
	}}
	outcome := &domain2.WalkOutcome{PerNodeResults: map[coordinate.ModuleCoordinate]domain2.NodeResult{}}

	local := (&Walker{}).classifyGraphNodes(WalkRequest{Target: target}, graph, newRecorderForTest(newRecorderFakeFetcher()), outcome)

	if len(local) != 0 {
		t.Errorf("local nodes to ingest = %v, want none", local)
	}
	r, ok := outcome.PerNodeResults[node.Coordinate]
	if !ok || r.Status != domain2.NodeSucceeded || r.FetchRecord != nil {
		t.Errorf("TinyGo node result = %+v (present %t), want succeeded with no fetch record", r, ok)
	}
}
