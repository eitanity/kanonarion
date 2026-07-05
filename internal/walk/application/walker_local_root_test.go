package application_test

import (
	"context"
	"errors"
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	application2 "github.com/eitanity/kanonarion/internal/walk/application"
	"github.com/eitanity/kanonarion/internal/walk/domain"
)

// A project walk with local-root analysis enabled ingests the working tree as
// the root's FactRecord and promotes the root node to ResolutionLocalAnalysed
// so extraction treats it as a normal analysable module.
func TestWalker_ProjectMode_AnalyseLocalRoot_PromotesRootToLocalAnalysed(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add("example.com/dep", "v1.0.0", "module example.com/dep\ngo 1.21\n", blobs)

	wf := newWalkerFetcher()
	wf.addRecord("example.com/dep", "v1.0.0")

	lf := newFakeLocalFetcher()
	lf.addRecord("example.com/project", domain2.LocalVersion)

	mainGoMod := []byte("module example.com/project\ngo 1.21\nrequire example.com/dep v1.0.0\n")
	target := domain2.ModuleCoordinate{Path: "example.com/project", Version: domain2.LocalVersion}

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

// When root ingestion fails, the walk fails: the caller explicitly asked for
// root analysis, so keeping the synthesised root success would misreport what
// actually ran.
func TestWalker_ProjectMode_AnalyseLocalRoot_IngestFailureFailsWalk(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add("example.com/dep", "v1.0.0", "module example.com/dep\ngo 1.21\n", blobs)

	wf := newWalkerFetcher()
	wf.addRecord("example.com/dep", "v1.0.0")

	lf := newFakeLocalFetcher()
	lf.addError("example.com/project", domain2.LocalVersion, errors.New("zip create failed"))

	mainGoMod := []byte("module example.com/project\ngo 1.21\nrequire example.com/dep v1.0.0\n")
	target := domain2.ModuleCoordinate{Path: "example.com/project", Version: domain2.LocalVersion}

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
	if outcome.OverallStatus != domain.WalkFailed {
		t.Fatalf("status = %s, want failed", outcome.OverallStatus)
	}
	tr := outcome.PerNodeResults[target]
	if tr.Status != domain.NodeFetchFailed {
		t.Errorf("root status = %s, want fetch_failed", tr.Status)
	}
	if tr.Error == nil || tr.Error.Type != "local_root_ingest_failed" {
		t.Errorf("root error = %+v, want type local_root_ingest_failed", tr.Error)
	}
}

// Local-root analysis is only meaningful with a known working tree; a missing
// project directory is a configuration failure, not a silent no-op.
func TestWalker_ProjectMode_AnalyseLocalRoot_MissingProjectDirFailsWalk(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add("example.com/dep", "v1.0.0", "module example.com/dep\ngo 1.21\n", blobs)

	wf := newWalkerFetcher()
	wf.addRecord("example.com/dep", "v1.0.0")

	mainGoMod := []byte("module example.com/project\ngo 1.21\nrequire example.com/dep v1.0.0\n")
	target := domain2.ModuleCoordinate{Path: "example.com/project", Version: domain2.LocalVersion}

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
	if outcome.OverallStatus != domain.WalkFailed {
		t.Fatalf("status = %s, want failed", outcome.OverallStatus)
	}
	tr := outcome.PerNodeResults[target]
	if tr.Error == nil || tr.Error.Type != "local_root_ingest_failed" {
		t.Errorf("root error = %+v, want type local_root_ingest_failed", tr.Error)
	}
}
