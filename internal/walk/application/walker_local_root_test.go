package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	application2 "github.com/eitanity/kanonarion/internal/walk/application"
	"github.com/eitanity/kanonarion/internal/walk/domain"
)

// A project walk with local-root analysis enabled ingests the working tree as
// the root's FactRecord and promotes the root node to ResolutionLocalAnalysed
// so extraction treats it as a normal analysable module.
func TestWalker_ProjectMode_AnalyseLocalRoot_PromotesRootToLocalAnalysed(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(t, "example.com/dep", "v1.0.0", "module example.com/dep\ngo 1.21\n", blobs)

	wf := newWalkerFetcher()
	wf.addRecord(t, "example.com/dep", "v1.0.0")

	lf := newFakeLocalFetcher()
	lf.addRecord(t, "example.com/project", coordinate.LocalVersion)

	mainGoMod := []byte("module example.com/project\ngo 1.21\nrequire example.com/dep v1.0.0\n")
	target := coordinatetest.MustNew("example.com/project", coordinate.LocalVersion)

	w := buildWalkerWithLocal(rf, wf, lf, blobs, 2)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target:           target,
		ProjectMode:      true,
		MainModuleGoMod:  mainGoMod,
		AnalyseLocalRoot: true,
		ProjectDir:       "/work/project",
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if outcome.OverallStatus != domain.WalkSucceeded {
		t.Fatalf("status = %s, want succeeded", outcome.OverallStatus)
	}

	tr := outcome.PerNodeResults[target]
	if tr.Status != domain.NodeSucceeded {
		t.Errorf("root status = %s, want succeeded", tr.Status)
	}
	if tr.FetchRecord == nil {
		t.Fatal("root carries no fetch record, want the ingested working-tree record")
	}

	var root domain.GraphNode
	found := false
	for _, n := range outcome.Graph.Nodes {
		if n.Coordinate == target {
			root, found = n, true
		}
	}
	if !found {
		t.Fatalf("root node %s absent from graph", target)
	}
	if root.ResolutionSource != domain.ResolutionLocalAnalysed {
		t.Errorf("root source = %s, want local_analysed", root.ResolutionSource)
	}
	if root.LocalPath != "/work/project" {
		t.Errorf("root LocalPath = %q, want the project dir", root.LocalPath)
	}
}

// A root ingest that fails degrades the walk; it does not discard it. The
// project's go.mod was read and every dependency fetched, so the graph is
// intact and answerable — what is missing is the project's own packages. The
// walk reads partial, the root keeps the succeeded result the project resolve
// gave it, and the reason rides on that result so nothing reads as clean.
func TestWalker_ProjectMode_AnalyseLocalRoot_IngestFailureDegradesWalk(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(t, "example.com/dep", "v1.0.0", "module example.com/dep\ngo 1.21\n", blobs)

	wf := newWalkerFetcher()
	wf.addRecord(t, "example.com/dep", "v1.0.0")

	lf := newFakeLocalFetcher()
	lf.addError("example.com/project", coordinate.LocalVersion, errors.New("zip create failed"))

	mainGoMod := []byte("module example.com/project\ngo 1.21\nrequire example.com/dep v1.0.0\n")
	target := coordinatetest.MustNew("example.com/project", coordinate.LocalVersion)

	w := buildWalkerWithLocal(rf, wf, lf, blobs, 2)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target:           target,
		ProjectMode:      true,
		MainModuleGoMod:  mainGoMod,
		AnalyseLocalRoot: true,
		ProjectDir:       "/work/project",
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if outcome.OverallStatus != domain.WalkPartial {
		t.Fatalf("status = %s, want partial", outcome.OverallStatus)
	}
	tr := outcome.PerNodeResults[target]
	if tr.Status != domain.NodeSucceeded {
		t.Errorf("root status = %s, want succeeded: the go.mod was read and the graph resolved", tr.Status)
	}
	if tr.Error == nil || tr.Error.Type != "local_root_ingest_failed" {
		t.Errorf("root error = %+v, want type local_root_ingest_failed", tr.Error)
	}
	// The dependency closure the run paid for survives the degradation.
	dep := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	if dr, ok := outcome.PerNodeResults[dep]; !ok || dr.Status != domain.NodeSucceeded {
		t.Errorf("dependency result = %+v (present=%v), want succeeded", dr, ok)
	}
	if len(outcome.Graph.Nodes) == 0 {
		t.Error("graph has no nodes: a failed root ingest discarded the resolved graph")
	}
}

// Local-root analysis is only meaningful with a known working tree. A missing
// project directory is a configuration failure that must be stated, but it is
// still only the root ingest that did not happen, so it degrades the walk
// rather than discarding it.
func TestWalker_ProjectMode_AnalyseLocalRoot_MissingProjectDirDegradesWalk(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(t, "example.com/dep", "v1.0.0", "module example.com/dep\ngo 1.21\n", blobs)

	wf := newWalkerFetcher()
	wf.addRecord(t, "example.com/dep", "v1.0.0")

	mainGoMod := []byte("module example.com/project\ngo 1.21\nrequire example.com/dep v1.0.0\n")
	target := coordinatetest.MustNew("example.com/project", coordinate.LocalVersion)

	w := buildWalkerWithLocal(rf, wf, newFakeLocalFetcher(), blobs, 2)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target:           target,
		ProjectMode:      true,
		MainModuleGoMod:  mainGoMod,
		AnalyseLocalRoot: true,
		// ProjectDir deliberately empty.
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if outcome.OverallStatus != domain.WalkPartial {
		t.Fatalf("status = %s, want partial", outcome.OverallStatus)
	}
	tr := outcome.PerNodeResults[target]
	if tr.Error == nil || tr.Error.Type != "local_root_ingest_failed" {
		t.Errorf("root error = %+v, want type local_root_ingest_failed", tr.Error)
	}
}
