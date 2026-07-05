package application_test

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

func makeWalkWithModules(t *testing.T, coords ...fetchdomain.ModuleCoordinate) (walkdomain.WalkRecord, *fakeWalkStore, *fakeFacts, *fakeBlob) {
	t.Helper()
	ctx := t.Context()
	walkID := "walk-rescan-1"
	nodes := make([]walkdomain.GraphNode, len(coords))
	for i, c := range coords {
		nodes[i] = walkdomain.GraphNode{Coordinate: c}
	}
	walk := walkdomain.WalkRecord{ID: walkID, Graph: walkdomain.Graph{Nodes: nodes}}
	ws := newFakeWalkStore()
	if err := ws.PutWalk(ctx, walk); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}
	facts := newFakeFacts()
	blobs := newFakeBlob()
	for _, c := range coords {
		h, _ := blobs.Put(ctx, strings.NewReader("zip-"+c.Path))
		if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
			ModulePath: c.Path, ModuleVersion: c.Version, PipelineVersion: "v1", ContentLocation: string(h),
		}); err != nil {
			t.Fatalf("PutFetchRecord: %v", err)
		}
	}
	return walk, ws, facts, blobs
}

// TestRescan_ProducesNewScanRun verifies that Rescan creates a new WalkScanRun
// and does not modify any prior scan runs.
func TestRescan_ProducesNewScanRun(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)

	target := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	walk, ws, facts, blobs := makeWalkWithModules(t, target)

	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{}
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Source: "test", Version: "v1"}}
	clock1 := fixedClock{t: now}
	clock2 := fixedClock{t: now.Add(time.Hour)}

	moduleUC1 := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, ws, scanner, db, nil, clock1, "v1", "v1", slog.Default(),
	)

	// Perform an initial scan to establish a prior run.
	walkUC := application.NewScanWalkUseCase(ws, vulnStore, moduleUC1, nil, clock1, "v1", slog.Default())
	firstRun, err := walkUC.Scan(ctx, application.ScanWalkParams{WalkID: walk.ID, Operator: "op"})
	if err != nil {
		t.Fatalf("initial Scan: %v", err)
	}

	// Now rescan with a newer snapshot using a later clock so the run ID differs.
	db.snapshot = domain.DatabaseSnapshot{Source: "test", Version: "v2"}
	moduleUC2 := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, ws, scanner, db, nil, clock2, "v1", "v1", slog.Default(),
	)
	rescanner := application.NewRescanWalkUseCase(ws, vulnStore, moduleUC2, nil, clock2, "v1", slog.Default())
	secondRun, err := rescanner.Rescan(ctx, application.RescanRequest{WalkID: walk.ID, Operator: "op"})
	if err != nil {
		t.Fatalf("Rescan: %v", err)
	}

	if secondRun.ID == firstRun.ID {
		t.Error("expected a new run ID, got the same as the first run")
	}
	if secondRun.Snapshot.Version != "v2" {
		t.Errorf("expected snapshot v2, got %s", secondRun.Snapshot.Version)
	}

	// Prior run must still exist unchanged.
	persisted, ok, err := vulnStore.GetWalkScanRun(ctx, firstRun.ID)
	if err != nil || !ok {
		t.Fatal("first run was removed from the store")
	}
	if persisted.Snapshot.Version != "v1" {
		t.Errorf("first run snapshot was mutated: got %s", persisted.Snapshot.Version)
	}

	// Both runs must be listed in history.
	runs, err := vulnStore.ListWalkScanRuns(ctx, walk.ID)
	if err != nil {
		t.Fatalf("ListWalkScanRuns: %v", err)
	}
	if len(runs) != 2 {
		t.Errorf("expected 2 scan runs in history, got %d", len(runs))
	}
}

// TestRescan_FreshSnapshotFetched verifies that when no snapshot is pinned,
// Rescan fetches a fresh one from the database port.
func TestRescan_FreshSnapshotFetched(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)

	target := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	walk, ws, facts, blobs := makeWalkWithModules(t, target)

	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{}
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Source: "osv", Version: "fresh-1"}}
	clock := fixedClock{t: now}

	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, ws, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	rescanner := application.NewRescanWalkUseCase(ws, vulnStore, moduleUC, nil, clock, "v1", slog.Default())

	run, err := rescanner.Rescan(ctx, application.RescanRequest{WalkID: walk.ID})
	if err != nil {
		t.Fatalf("Rescan: %v", err)
	}
	if run.Snapshot.Version != "fresh-1" {
		t.Errorf("expected snapshot fresh-1, got %s", run.Snapshot.Version)
	}
}

// TestRescan_PinnedSnapshot verifies that when a snapshot is explicitly provided,
// Rescan uses it without fetching from the network.
func TestRescan_PinnedSnapshot(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)

	target := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	walk, ws, facts, blobs := makeWalkWithModules(t, target)

	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{}
	// db.snapshot would be "network" but we pin a different one.
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Source: "osv", Version: "network"}}
	clock := fixedClock{t: now}

	pinned := domain.DatabaseSnapshot{Source: "osv", Version: "pinned-42"}

	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, ws, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	rescanner := application.NewRescanWalkUseCase(ws, vulnStore, moduleUC, nil, clock, "v1", slog.Default())

	run, err := rescanner.Rescan(ctx, application.RescanRequest{WalkID: walk.ID, Snapshot: &pinned})
	if err != nil {
		t.Fatalf("Rescan: %v", err)
	}
	if run.Snapshot.Version != "pinned-42" {
		t.Errorf("expected pinned-42, got %s", run.Snapshot.Version)
	}
}

// TestRescan_UnknownWalk verifies that Rescan returns an error for a missing walk.
func TestRescan_UnknownWalk(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)

	ws := newFakeWalkStore()
	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{}
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Source: "test", Version: "v1"}}
	clock := fixedClock{t: now}
	facts := newFakeFacts()
	blobs := newFakeBlob()

	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, ws, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	rescanner := application.NewRescanWalkUseCase(ws, vulnStore, moduleUC, nil, clock, "v1", slog.Default())

	_, err := rescanner.Rescan(ctx, application.RescanRequest{WalkID: "nonexistent"})
	if err == nil {
		t.Fatal("expected error for unknown walk, got nil")
	}
}
