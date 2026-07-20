package application_test

import (
	"context"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// seedScanRun stores a WalkScanRun and its per-module VulnerabilityRecords in the fake store.
func seedScanRun(t *testing.T, ctx context.Context, store *fakeVulnStore, run domain.WalkScanRun, records []domain.VulnerabilityRecord) {
	t.Helper()
	if err := store.PutWalkScanRun(ctx, run); err != nil {
		t.Fatalf("PutWalkScanRun: %v", err)
	}
	for _, r := range records {
		if err := store.PutVulnerabilityRecord(ctx, r); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
	}
	// Wire the fake store's ListVulnerabilityRecords to return these records for the run.
	store.SetRunRecords(run.ID, records)
}

func makeRun(id, walkID string, snap domain.DatabaseSnapshot) domain.WalkScanRun {
	return domain.WalkScanRun{
		ID:               id,
		WalkID:           walkID,
		Snapshot:         snap,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{},
		StartedAt:        time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		CompletedAt:      time.Date(2024, 1, 1, 0, 1, 0, 0, time.UTC),
		OverallStatus:    domain.WalkStatusAllClean,
		PipelineVersion:  "v1",
	}
}

func makeRecord(coord coordinate.ModuleCoordinate, walkID string, findings ...domain.VulnerabilityFinding) domain.VulnerabilityRecord {
	status := domain.StatusClean
	if len(findings) > 0 {
		status = domain.StatusAffected
	}
	return domain.VulnerabilityRecord{
		Coordinate:      coord,
		WalkID:          walkID,
		Findings:        findings,
		OverallStatus:   status,
		PipelineVersion: "v1",
	}
}

func makeFinding(id, summary string) domain.VulnerabilityFinding {
	return domain.VulnerabilityFinding{ID: id, Summary: summary}
}

func makeFindingWithReachability(id, summary string, reachable bool) domain.VulnerabilityFinding {
	return domain.VulnerabilityFinding{
		ID:      id,
		Summary: summary,
		Reachable: &domain.ReachabilityResult{
			IsReachable: reachable,
		},
	}
}

// TestDiff_NoDifferences verifies that identical scan runs produce an empty diff.
func TestDiff_NoDifferences(t *testing.T) {
	ctx := t.Context()
	store := newFakeVulnStore()
	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	snap := domain.DatabaseSnapshot{Source: "test", Version: "v1"}

	rec := makeRecord(coord, "walk-1", makeFinding("VULN-1", "bad bug"))
	runA := makeRun("run-a", "walk-1", snap)
	runB := makeRun("run-b", "walk-1", snap)

	seedScanRun(t, ctx, store, runA, []domain.VulnerabilityRecord{rec})
	seedScanRun(t, ctx, store, runB, []domain.VulnerabilityRecord{rec})

	uc := application.NewDiffScanRunsUseCase(store)
	diff, err := uc.Diff(ctx, "run-a", "run-b")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	if len(diff.NewFindings) != 0 {
		t.Errorf("expected 0 new findings, got %d", len(diff.NewFindings))
	}
	if len(diff.ResolvedFindings) != 0 {
		t.Errorf("expected 0 resolved findings, got %d", len(diff.ResolvedFindings))
	}
	if len(diff.ReachabilityChanges) != 0 {
		t.Errorf("expected 0 reachability changes, got %d", len(diff.ReachabilityChanges))
	}
}

// TestDiff_NewFinding verifies that a finding in B but not A is reported as new.
func TestDiff_NewFinding(t *testing.T) {
	ctx := t.Context()
	store := newFakeVulnStore()
	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	snapA := domain.DatabaseSnapshot{Source: "test", Version: "v1"}
	snapB := domain.DatabaseSnapshot{Source: "test", Version: "v2"}

	runA := makeRun("run-a", "walk-1", snapA)
	runB := makeRun("run-b", "walk-1", snapB)

	seedScanRun(t, ctx, store, runA, []domain.VulnerabilityRecord{
		makeRecord(coord, "walk-1"), // clean in A
	})
	seedScanRun(t, ctx, store, runB, []domain.VulnerabilityRecord{
		makeRecord(coord, "walk-1", makeFinding("VULN-2", "new bug")), // affected in B
	})

	uc := application.NewDiffScanRunsUseCase(store)
	diff, err := uc.Diff(ctx, "run-a", "run-b")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	if len(diff.NewFindings) != 1 {
		t.Fatalf("expected 1 new finding, got %d", len(diff.NewFindings))
	}
	if diff.NewFindings[0].Finding.ID != "VULN-2" {
		t.Errorf("expected VULN-2, got %s", diff.NewFindings[0].Finding.ID)
	}
	if len(diff.ResolvedFindings) != 0 {
		t.Errorf("expected 0 resolved findings, got %d", len(diff.ResolvedFindings))
	}
}

// TestDiff_ResolvedFinding verifies that a finding in A but not B is reported as resolved.
func TestDiff_ResolvedFinding(t *testing.T) {
	ctx := t.Context()
	store := newFakeVulnStore()
	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	snapA := domain.DatabaseSnapshot{Source: "test", Version: "v1"}
	snapB := domain.DatabaseSnapshot{Source: "test", Version: "v2"}

	runA := makeRun("run-a", "walk-1", snapA)
	runB := makeRun("run-b", "walk-1", snapB)

	seedScanRun(t, ctx, store, runA, []domain.VulnerabilityRecord{
		makeRecord(coord, "walk-1", makeFinding("VULN-OLD", "old bug")),
	})
	seedScanRun(t, ctx, store, runB, []domain.VulnerabilityRecord{
		makeRecord(coord, "walk-1"), // clean in B
	})

	uc := application.NewDiffScanRunsUseCase(store)
	diff, err := uc.Diff(ctx, "run-a", "run-b")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	if len(diff.ResolvedFindings) != 1 {
		t.Fatalf("expected 1 resolved finding, got %d", len(diff.ResolvedFindings))
	}
	if diff.ResolvedFindings[0].Finding.ID != "VULN-OLD" {
		t.Errorf("expected VULN-OLD, got %s", diff.ResolvedFindings[0].Finding.ID)
	}
	if len(diff.NewFindings) != 0 {
		t.Errorf("expected 0 new findings, got %d", len(diff.NewFindings))
	}
}

// TestDiff_ReachabilityChange verifies that a finding present in both runs with
// changed reachability is reported in ReachabilityChanges.
func TestDiff_ReachabilityChange(t *testing.T) {
	ctx := t.Context()
	store := newFakeVulnStore()
	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	snap := domain.DatabaseSnapshot{Source: "test", Version: "v1"}

	findingA := domain.VulnerabilityFinding{
		ID:        "VULN-3",
		Summary:   "reachable bug",
		Reachable: &domain.ReachabilityResult{IsReachable: false, Confidence: domain.ConfidenceHigh},
	}
	findingB := domain.VulnerabilityFinding{
		ID:        "VULN-3",
		Summary:   "reachable bug",
		Reachable: &domain.ReachabilityResult{IsReachable: true, Confidence: domain.ConfidenceHigh},
	}

	runA := makeRun("run-a", "walk-1", snap)
	runB := makeRun("run-b", "walk-1", snap)

	seedScanRun(t, ctx, store, runA, []domain.VulnerabilityRecord{makeRecord(coord, "walk-1", findingA)})
	seedScanRun(t, ctx, store, runB, []domain.VulnerabilityRecord{makeRecord(coord, "walk-1", findingB)})

	uc := application.NewDiffScanRunsUseCase(store)
	diff, err := uc.Diff(ctx, "run-a", "run-b")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	if len(diff.ReachabilityChanges) != 1 {
		t.Fatalf("expected 1 reachability change, got %d", len(diff.ReachabilityChanges))
	}
	c := diff.ReachabilityChanges[0]
	if c.WasReachable {
		t.Error("expected WasReachable=false")
	}
	if !c.IsReachable {
		t.Error("expected IsReachable=true")
	}
	if len(diff.NewFindings) != 0 {
		t.Errorf("expected 0 new findings, got %d", len(diff.NewFindings))
	}
}

// TestDiff_DifferentWalks verifies that diffing runs from different walks returns an error.
func TestDiff_DifferentWalks(t *testing.T) {
	ctx := t.Context()
	store := newFakeVulnStore()
	snap := domain.DatabaseSnapshot{Source: "test", Version: "v1"}

	runA := makeRun("run-a", "walk-1", snap)
	runB := makeRun("run-b", "walk-2", snap)

	seedScanRun(t, ctx, store, runA, nil)
	seedScanRun(t, ctx, store, runB, nil)

	uc := application.NewDiffScanRunsUseCase(store)
	_, err := uc.Diff(ctx, "run-a", "run-b")
	if err == nil {
		t.Fatal("expected error for runs from different walks, got nil")
	}
}

// TestDiff_MissingRun verifies that diffing with a non-existent run ID returns an error.
func TestDiff_MissingRun(t *testing.T) {
	ctx := t.Context()
	store := newFakeVulnStore()
	snap := domain.DatabaseSnapshot{Source: "test", Version: "v1"}
	runA := makeRun("run-a", "walk-1", snap)
	seedScanRun(t, ctx, store, runA, nil)

	uc := application.NewDiffScanRunsUseCase(store)
	_, err := uc.Diff(ctx, "run-a", "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing run, got nil")
	}
}

// TestDiff_SortingPathGreater verifies that compareFindingDelta returns 1 when
// a.Coordinate.Path > b.Coordinate.Path (the "return 1" branch).
func TestDiff_SortingPathGreater(t *testing.T) {
	ctx := t.Context()
	store := newFakeVulnStore()
	coordZ := coordinate.ModuleCoordinate{Path: "github.com/zzz/pkg", Version: "v1.0.0"}
	coordA := coordinate.ModuleCoordinate{Path: "github.com/aaa/pkg", Version: "v1.0.0"}
	snap := domain.DatabaseSnapshot{Source: "test", Version: "v1"}

	runA := makeRun("run-a", "walk-1", snap)
	runB := makeRun("run-b", "walk-1", snap)

	seedScanRun(t, ctx, store, runA, []domain.VulnerabilityRecord{})
	seedScanRun(t, ctx, store, runB, []domain.VulnerabilityRecord{
		makeRecord(coordZ, "walk-1", makeFinding("VULN-Z", "z bug")),
		makeRecord(coordA, "walk-1", makeFinding("VULN-A", "a bug")),
	})

	uc := application.NewDiffScanRunsUseCase(store)
	diff, err := uc.Diff(ctx, "run-a", "run-b")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	if len(diff.NewFindings) != 2 {
		t.Fatalf("expected 2 new findings, got %d", len(diff.NewFindings))
	}
	// After sorting, aaa should come before zzz.
	if diff.NewFindings[0].Coordinate.Path != "github.com/aaa/pkg" {
		t.Errorf("expected aaa first, got %s", diff.NewFindings[0].Coordinate.Path)
	}
	if diff.NewFindings[1].Coordinate.Path != "github.com/zzz/pkg" {
		t.Errorf("expected zzz second, got %s", diff.NewFindings[1].Coordinate.Path)
	}
}

// TestDiff_SortingFindingIDOrder verifies that compareFindingDelta sorts by
// finding ID when paths are equal (covers both ID < and ID > branches).
func TestDiff_SortingFindingIDOrder(t *testing.T) {
	ctx := t.Context()
	store := newFakeVulnStore()
	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	snap := domain.DatabaseSnapshot{Source: "test", Version: "v1"}

	runA := makeRun("run-a", "walk-1", snap)
	runB := makeRun("run-b", "walk-1", snap)

	seedScanRun(t, ctx, store, runA, []domain.VulnerabilityRecord{})
	seedScanRun(t, ctx, store, runB, []domain.VulnerabilityRecord{
		makeRecord(coord, "walk-1",
			makeFinding("VULN-Z", "z bug"),
			makeFinding("VULN-A", "a bug"),
		),
	})

	uc := application.NewDiffScanRunsUseCase(store)
	diff, err := uc.Diff(ctx, "run-a", "run-b")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	if len(diff.NewFindings) != 2 {
		t.Fatalf("expected 2 new findings, got %d", len(diff.NewFindings))
	}
	// After sorting by ID, VULN-A should come before VULN-Z.
	if diff.NewFindings[0].Finding.ID != "VULN-A" {
		t.Errorf("expected VULN-A first, got %s", diff.NewFindings[0].Finding.ID)
	}
	if diff.NewFindings[1].Finding.ID != "VULN-Z" {
		t.Errorf("expected VULN-Z second, got %s", diff.NewFindings[1].Finding.ID)
	}
}

// TestDiff_ReachabilityNilToNonNilResolved verifies that a finding where
// reachability goes from nil (A) to non-nil (B) is treated as a reachability change.
func TestDiff_ReachabilityNilToNonNilResolved(t *testing.T) {
	ctx := t.Context()
	store := newFakeVulnStore()
	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	snap := domain.DatabaseSnapshot{Source: "test", Version: "v1"}

	findingA := makeFinding("VULN-X", "some bug") // no reachability
	findingB := makeFindingWithReachability("VULN-X", "some bug", true)

	runA := makeRun("run-a", "walk-1", snap)
	runB := makeRun("run-b", "walk-1", snap)

	seedScanRun(t, ctx, store, runA, []domain.VulnerabilityRecord{makeRecord(coord, "walk-1", findingA)})
	seedScanRun(t, ctx, store, runB, []domain.VulnerabilityRecord{makeRecord(coord, "walk-1", findingB)})

	uc := application.NewDiffScanRunsUseCase(store)
	diff, err := uc.Diff(ctx, "run-a", "run-b")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	if len(diff.ReachabilityChanges) != 1 {
		t.Fatalf("expected 1 reachability change, got %d", len(diff.ReachabilityChanges))
	}
	if diff.ReachabilityChanges[0].WasReachable {
		t.Error("expected WasReachable=false (nil reachability in A)")
	}
	if !diff.ReachabilityChanges[0].IsReachable {
		t.Error("expected IsReachable=true")
	}
}
