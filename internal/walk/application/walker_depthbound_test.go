package application_test

import (
	"context"
	"testing"

	application2 "github.com/eitanity/kanonarion/internal/walk/application"
	"github.com/eitanity/kanonarion/internal/walk/domain"
)

// depthBoundPolicy is a fetch stage bounded at one hop, the shape a policy file
// carrying `stages: fetch: max_depth: 1` loads as.
func depthBoundPolicy(maxDepth int) *domain.DepthPolicy {
	p := domain.DefaultDepthPolicy()
	stage := p.Stages["fetch"]
	stage.MaxDepth = maxDepth
	p.Stages["fetch"] = stage
	return &p
}

// A requirement the depth bound stopped the walk from following is recorded the
// way a shallow walk records one it did not follow: a node in the graph with no
// per-node result at all.
//
// It used to reach the walker's classification default — the arm labelled
// "defensive: the resolver should have fetched every graph node with a
// non-failure resolution source" — because a boundary node kept the source its
// version was selected with. That arm writes NodeFetchFailed with "resolver did
// not fetch this coordinate", so a walk that did exactly what its policy asked
// reported two failed dependencies and refused with the fetch sentence.
func TestWalker_MaxDepth_BoundaryNodeHasNoResultAndIsNotAFailure(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(t, "example.com/target", "v1.0.0",
		"module example.com/target\ngo 1.21\nrequire example.com/dep1 v1.0.0\n", blobs)
	rf.add(t, "example.com/dep1", "v1.0.0",
		"module example.com/dep1\ngo 1.21\nrequire example.com/dep2 v1.0.0\n", blobs)
	// dep2 is deliberately absent from both fakes: the bound means nothing may
	// ask for it, and a test that supplied it could not tell a walk that skipped
	// the fetch from one that made it.

	wf := newWalkerFetcher()
	wf.addRecord(t, "example.com/target", "v1.0.0")
	wf.addRecord(t, "example.com/dep1", "v1.0.0")

	w := buildWalker(rf, wf, blobs, 1)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
		Policy: depthBoundPolicy(1),
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	boundary := coord("example.com/dep2", "v1.0.0")
	var node domain.GraphNode
	var inGraph bool
	for _, n := range outcome.Graph.Nodes {
		if n.Coordinate == boundary {
			node, inGraph = n, true
		}
	}
	if !inGraph {
		t.Fatal("the boundary requirement must still be a node: the walk knows the edge exists, it just did not follow it")
	}
	if node.ResolutionSource != domain.ResolutionDepthBounded {
		t.Errorf("boundary node resolution source = %q, want %q",
			node.ResolutionSource, domain.ResolutionDepthBounded)
	}
	if res, ok := outcome.PerNodeResults[boundary]; ok {
		t.Errorf("boundary node has a per-node result (status %s, error %+v); "+
			"a node the policy said not to fetch has no outcome to report",
			res.Status, res.Error)
	}

	// The two nodes the walk did follow are the two it reports on.
	if len(outcome.PerNodeResults) != 2 {
		t.Errorf("per-node results = %d, want 2 (the target and the one hop the bound allowed)",
			len(outcome.PerNodeResults))
	}
	for c, res := range outcome.PerNodeResults {
		if res.Status.IsFailure() {
			t.Errorf("%s reported as a failure (%s: %+v); nothing failed in this walk", c, res.Status, res.Error)
		}
	}

	// Partial, and for the bound: the closure really is incomplete, and that is
	// what KN-395 settled. What must not happen is it being incomplete for a
	// fetch nobody attempted.
	if outcome.OverallStatus != domain.WalkPartial {
		t.Errorf("status = %s, want partial: the graph is truncated", outcome.OverallStatus)
	}
	if !outcome.Graph.Partial {
		t.Error("graph should be Partial when the bound truncates the closure")
	}
	if outcome.Graph.PartialReason != domain.DepthBoundedReason(1) {
		t.Errorf("PartialReason = %q, want %q", outcome.Graph.PartialReason, domain.DepthBoundedReason(1))
	}
}

// The control the fix must not move: a bound larger than the graph follows
// everything, so there is no boundary node and every node is reported on.
func TestWalker_MaxDepth_LargerThanGraph_ReportsEveryNode(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(t, "example.com/target", "v1.0.0",
		"module example.com/target\ngo 1.21\nrequire example.com/dep1 v1.0.0\n", blobs)
	rf.add(t, "example.com/dep1", "v1.0.0", "module example.com/dep1\ngo 1.21\n", blobs)

	wf := newWalkerFetcher()
	wf.addRecord(t, "example.com/target", "v1.0.0")
	wf.addRecord(t, "example.com/dep1", "v1.0.0")

	w := buildWalker(rf, wf, blobs, 1)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
		Policy: depthBoundPolicy(5),
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if outcome.OverallStatus != domain.WalkSucceeded {
		t.Errorf("status = %s, want succeeded: the bound truncated nothing", outcome.OverallStatus)
	}
	if len(outcome.PerNodeResults) != len(outcome.Graph.Nodes) {
		t.Errorf("per-node results = %d over %d graph nodes; an untruncated walk reports on all of them",
			len(outcome.PerNodeResults), len(outcome.Graph.Nodes))
	}
	for _, n := range outcome.Graph.Nodes {
		if n.ResolutionSource == domain.ResolutionDepthBounded {
			t.Errorf("%s marked depth-bounded, but nothing was cut off", n.Coordinate)
		}
	}
}

// A genuine fetch failure under a depth bound is still a failure. The two
// conditions are told apart by the node, not by the walk: one node was not
// reachable within the bound, the other was fetched and did not arrive.
func TestWalker_MaxDepth_WithFetchFailure_StillCountsTheFailure(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(t, "example.com/target", "v1.0.0",
		"module example.com/target\ngo 1.21\nrequire example.com/dep1 v1.0.0\nrequire example.com/broken v1.0.0\n", blobs)
	rf.add(t, "example.com/dep1", "v1.0.0",
		"module example.com/dep1\ngo 1.21\nrequire example.com/dep2 v1.0.0\n", blobs)
	// example.com/broken is required at depth 1, inside the bound, and no fake
	// serves it — so the resolver tries and fails.

	wf := newWalkerFetcher()
	wf.addRecord(t, "example.com/target", "v1.0.0")
	wf.addRecord(t, "example.com/dep1", "v1.0.0")

	w := buildWalker(rf, wf, blobs, 1)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
		Policy: depthBoundPolicy(1),
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	broken := outcome.PerNodeResults[coord("example.com/broken", "v1.0.0")]
	if !broken.Status.IsFailure() {
		t.Errorf("the unreachable module's status = %s, want a failure: it was asked for and did not arrive", broken.Status)
	}
	if _, ok := outcome.PerNodeResults[coord("example.com/dep2", "v1.0.0")]; ok {
		t.Error("the boundary node still has a result; the bound and the failure are different conditions")
	}
	if outcome.OverallStatus != domain.WalkPartial {
		t.Errorf("status = %s, want partial", outcome.OverallStatus)
	}
}
