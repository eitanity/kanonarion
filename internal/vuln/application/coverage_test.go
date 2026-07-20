package application_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// helpers shared across coverage tests

var errStore = errors.New("store error")

func makeScanWalkUC(t *testing.T, walkStore *fakeWalkStore, vulnStore *fakeVulnStore, db *fakeDatabase) *application.ScanWalkUseCase {
	t.Helper()
	facts := newFakeFacts()
	blobs := newFakeBlob()
	scanner := &fakeScanner{results: map[string]domain.VulnerabilityRecord{}}
	clock := fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	return application.NewScanWalkUseCase(walkStore, vulnStore, moduleUC, nil, clock, "v1", slog.Default())
}

func seedWalk(t *testing.T, walkStore *fakeWalkStore, walkID string, coords ...coordinate.ModuleCoordinate) {
	t.Helper()
	nodes := make([]walkdomain.GraphNode, len(coords))
	for i, c := range coords {
		nodes[i] = walkdomain.GraphNode{Coordinate: c}
	}
	if err := walkStore.PutWalk(t.Context(), walkdomain.WalkRecord{
		ID:    walkID,
		Graph: walkdomain.Graph{Nodes: nodes},
	}); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}
}

// --- ScanWalk error paths ---

func TestScanWalk_GetWalkError(t *testing.T) {
	walkStore := newFakeWalkStore()
	walkStore.errOnGet = errStore
	vulnStore := newFakeVulnStore()
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Source: "s", Version: "v1"}}

	uc := makeScanWalkUC(t, walkStore, vulnStore, db)
	_, err := uc.Scan(t.Context(), application.ScanWalkParams{WalkID: "w1"})
	if err == nil {
		t.Fatal("expected error from GetWalk, got nil")
	}
}

func TestScanWalk_GetLatestSnapshotError(t *testing.T) {
	walkStore := newFakeWalkStore()
	coord := coordinate.ModuleCoordinate{Path: "github.com/a/b", Version: "v1.0.0"}
	seedWalk(t, walkStore, "w1", coord)

	vulnStore := newFakeVulnStore()
	vulnStore.errOnGetLatestSnap = errStore
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Source: "s", Version: "v1"}}

	uc := makeScanWalkUC(t, walkStore, vulnStore, db)
	_, err := uc.Scan(t.Context(), application.ScanWalkParams{WalkID: "w1"})
	if err == nil {
		t.Fatal("expected error from GetLatestDatabaseSnapshot, got nil")
	}
}

func TestScanWalk_DatabaseSnapshotFetchError(t *testing.T) {
	walkStore := newFakeWalkStore()
	coord := coordinate.ModuleCoordinate{Path: "github.com/a/b", Version: "v1.0.0"}
	seedWalk(t, walkStore, "w1", coord)

	vulnStore := newFakeVulnStore()
	db := &fakeDatabase{err: errStore}

	uc := makeScanWalkUC(t, walkStore, vulnStore, db)
	_, err := uc.Scan(t.Context(), application.ScanWalkParams{WalkID: "w1"})
	if err == nil {
		t.Fatal("expected error from database.Snapshot, got nil")
	}
}

func TestScanWalk_PutSnapshotError(t *testing.T) {
	walkStore := newFakeWalkStore()
	coord := coordinate.ModuleCoordinate{Path: "github.com/a/b", Version: "v1.0.0"}
	seedWalk(t, walkStore, "w1", coord)

	vulnStore := newFakeVulnStore()
	vulnStore.errOnPutSnap = errStore
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Source: "s", Version: "v1"}, content: "data"}

	uc := makeScanWalkUC(t, walkStore, vulnStore, db)
	_, err := uc.Scan(t.Context(), application.ScanWalkParams{WalkID: "w1"})
	if err == nil {
		t.Fatal("expected error from PutDatabaseSnapshot, got nil")
	}
}

func TestScanWalk_PutWalkScanRunError(t *testing.T) {
	walkStore := newFakeWalkStore()
	coord := coordinate.ModuleCoordinate{Path: "github.com/a/b", Version: "v1.0.0"}
	seedWalk(t, walkStore, "w1", coord)

	vulnStore := newFakeVulnStore()
	vulnStore.errOnPutRun = errStore
	snap := domain.DatabaseSnapshot{Source: "s", Version: "v1"}

	facts := newFakeFacts()
	blobs := newFakeBlob()
	h, _ := blobs.Put(t.Context(), strings.NewReader("zip"))
	if err := facts.PutFetchRecord(t.Context(), fetchdomain.FactRecord{
		ModulePath: coord.Path, ModuleVersion: coord.Version, PipelineVersion: "v1", ContentLocation: string(h),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}
	scanner := &fakeScanner{results: map[string]domain.VulnerabilityRecord{}}
	clock := fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	db := &fakeDatabase{snapshot: snap}
	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	uc := application.NewScanWalkUseCase(walkStore, vulnStore, moduleUC, nil, clock, "v1", slog.Default())

	_, err := uc.Scan(t.Context(), application.ScanWalkParams{WalkID: "w1", Snapshot: &snap})
	if err == nil {
		t.Fatal("expected error from PutWalkScanRun, got nil")
	}
}

// --- Rescan error path ---

func TestRescan_DatabaseSnapshotFetchError(t *testing.T) {
	walkStore := newFakeWalkStore()
	coord := coordinate.ModuleCoordinate{Path: "github.com/a/b", Version: "v1.0.0"}
	seedWalk(t, walkStore, "w1", coord)

	vulnStore := newFakeVulnStore()
	db := &fakeDatabase{err: errStore}
	facts := newFakeFacts()
	blobs := newFakeBlob()
	clock := fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	scanner := &fakeScanner{results: map[string]domain.VulnerabilityRecord{}}
	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	uc := application.NewRescanWalkUseCase(walkStore, vulnStore, moduleUC, nil, clock, "v1", slog.Default())

	_, err := uc.Rescan(t.Context(), application.RescanRequest{WalkID: "w1"})
	if err == nil {
		t.Fatal("expected error from database.Snapshot in rescan, got nil")
	}
}

// --- Diff error paths ---

func makeDiffUC(vulnStore *fakeVulnStore) *application.DiffScanRunsUseCase {
	return application.NewDiffScanRunsUseCase(vulnStore)
}

func TestDiff_GetRunAError(t *testing.T) {
	vulnStore := newFakeVulnStore()
	vulnStore.errOnGetRun = errStore

	uc := makeDiffUC(vulnStore)
	_, err := uc.Diff(t.Context(), "run-a", "run-b")
	if err == nil {
		t.Fatal("expected error from GetWalkScanRun(A), got nil")
	}
}

func TestDiff_RunANotFound(t *testing.T) {
	vulnStore := newFakeVulnStore()
	// run-a not seeded, run-b not seeded — first lookup returns not-found
	uc := makeDiffUC(vulnStore)
	_, err := uc.Diff(t.Context(), "run-a", "run-b")
	if err == nil {
		t.Fatal("expected error for missing run A, got nil")
	}
}

func TestDiff_RunBNotFound(t *testing.T) {
	ctx := t.Context()
	snap := domain.DatabaseSnapshot{Source: "s", Version: "v1"}
	vulnStore := newFakeVulnStore()
	runA := makeRun("run-a", "walk-1", snap)
	seedScanRun(t, ctx, vulnStore, runA, nil)
	// run-b not seeded

	uc := makeDiffUC(vulnStore)
	_, err := uc.Diff(ctx, "run-a", "run-b")
	if err == nil {
		t.Fatal("expected error for missing run B, got nil")
	}
}

func TestDiff_ListRecordsAError(t *testing.T) {
	ctx := t.Context()
	snap := domain.DatabaseSnapshot{Source: "s", Version: "v1"}
	vulnStore := newFakeVulnStore()

	runA := makeRun("run-a", "walk-1", snap)
	runB := makeRun("run-b", "walk-1", snap)
	seedScanRun(t, ctx, vulnStore, runA, nil)
	seedScanRun(t, ctx, vulnStore, runB, nil)

	vulnStore.errOnListRecords = errStore

	uc := makeDiffUC(vulnStore)
	_, err := uc.Diff(ctx, "run-a", "run-b")
	if err == nil {
		t.Fatal("expected error from ListVulnerabilityRecords, got nil")
	}
}

func TestDiff_ListRecordsBError(t *testing.T) {
	ctx := t.Context()
	snap := domain.DatabaseSnapshot{Source: "s", Version: "v1"}

	// Use a store that errors only on the second call to ListVulnerabilityRecords
	vulnStore := newFakeVulnStore()
	runA := makeRun("run-a", "walk-1", snap)
	runB := makeRun("run-b", "walk-1", snap)
	seedScanRun(t, ctx, vulnStore, runA, nil)
	seedScanRun(t, ctx, vulnStore, runB, nil)

	wrapped := &listRecordsErrAfterN{fakeVulnStore: vulnStore, failAfter: 1, err: errStore}
	uc := application.NewDiffScanRunsUseCase(wrapped)
	_, err := uc.Diff(ctx, "run-a", "run-b")
	if err == nil {
		t.Fatal("expected error from ListVulnerabilityRecords(B), got nil")
	}
}

// listRecordsErrAfterN wraps fakeVulnStore and returns an error after N successful calls.
type listRecordsErrAfterN struct {
	*fakeVulnStore
	failAfter int
	calls     int
	err       error
}

func (l *listRecordsErrAfterN) ListVulnerabilityRecords(ctx context.Context, runID string) ([]domain.VulnerabilityRecord, error) {
	l.calls++
	if l.calls > l.failAfter {
		return nil, l.err
	}
	return l.fakeVulnStore.ListVulnerabilityRecords(ctx, runID)
}

// --- compareFindingDelta (sort path) ---

func TestDiff_SortingMultipleFindings(t *testing.T) {
	ctx := t.Context()
	snap := domain.DatabaseSnapshot{Source: "s", Version: "v1"}
	vulnStore := newFakeVulnStore()

	coordA := coordinate.ModuleCoordinate{Path: "github.com/z/z", Version: "v1.0.0"}
	coordB := coordinate.ModuleCoordinate{Path: "github.com/a/a", Version: "v1.0.0"}

	runA := makeRun("run-a", "walk-1", snap)
	runB := makeRun("run-b", "walk-1", snap)
	seedScanRun(t, ctx, vulnStore, runA, nil)

	recsB := []domain.VulnerabilityRecord{
		makeRecord(coordA, "walk-1", makeFinding("CVE-Z", "z vuln")),
		makeRecord(coordB, "walk-1", makeFinding("CVE-A", "a vuln")),
	}
	seedScanRun(t, ctx, vulnStore, runB, recsB)

	uc := makeDiffUC(vulnStore)
	diff, err := uc.Diff(ctx, "run-a", "run-b")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(diff.NewFindings) != 2 {
		t.Fatalf("expected 2 new findings, got %d", len(diff.NewFindings))
	}
	// After sort, coordB (github.com/a/a) should come before coordA (github.com/z/z)
	if diff.NewFindings[0].Coordinate.Path != coordB.Path {
		t.Errorf("expected first finding from %s, got %s", coordB.Path, diff.NewFindings[0].Coordinate.Path)
	}
}

// --- scan_module: module not fetched ---

func TestScanModule_ModuleNotFetched(t *testing.T) {
	walkStore := newFakeWalkStore()
	vulnStore := newFakeVulnStore()
	facts := newFakeFacts() // empty — no fetch record
	blobs := newFakeBlob()
	scanner := &fakeScanner{results: map[string]domain.VulnerabilityRecord{}}
	clock := fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	snap := domain.DatabaseSnapshot{Source: "s", Version: "v1"}
	db := &fakeDatabase{snapshot: snap}

	uc := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	coord := coordinate.ModuleCoordinate{Path: "github.com/missing/mod", Version: "v1.0.0"}
	rec, err := uc.Scan(t.Context(), application.ScanModuleParams{
		Coordinate: coord,
		WalkID:     "w1",
		Snapshot:   &snap,
	})
	if err != nil {
		t.Fatalf("unexpected error for unfetched module: %v", err)
	}
	// Unfetched modules fall back to OSV metadata-only scan (shallow walk support).
	if rec.UnscannableReason == "" {
		t.Error("expected UnscannableReason for metadata-only record, got empty")
	}
	if rec.Coordinate != coord {
		t.Errorf("Coordinate = %v, want %v", rec.Coordinate, coord)
	}
}

func TestScanModule_MetadataOnly_WithVulns(t *testing.T) {
	walkStore := newFakeWalkStore()
	vulnStore := newFakeVulnStore()
	facts := newFakeFacts() // no fetch record — shallow walk node
	blobs := newFakeBlob()
	scanner := &fakeScanner{results: map[string]domain.VulnerabilityRecord{}}
	clock := fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	snap := domain.DatabaseSnapshot{Source: "osv", Version: "v2"}

	modCoord := coordinate.ModuleCoordinate{Path: "github.com/vuln/mod", Version: "v1.0.0"}
	db := &fakeDatabase{
		snapshot: snap,
		vulnerables: map[coordinate.ModuleCoordinate][]string{
			modCoord: {"GO-2024-0001", "GO-2024-0002"},
		},
	}

	uc := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	rec, err := uc.Scan(t.Context(), application.ScanModuleParams{
		Coordinate: modCoord,
		WalkID:     "w1",
		Snapshot:   &snap,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.OverallStatus != domain.StatusAffected {
		t.Errorf("status = %q, want %q", rec.OverallStatus, domain.StatusAffected)
	}
	if len(rec.Findings) != 2 {
		t.Errorf("findings count = %d, want 2", len(rec.Findings))
	}
	if rec.UnscannableReason == "" {
		t.Error("expected UnscannableReason to be set for metadata-only record")
	}
}

func TestScanModule_MetadataOnly_Clean(t *testing.T) {
	walkStore := newFakeWalkStore()
	vulnStore := newFakeVulnStore()
	facts := newFakeFacts()
	blobs := newFakeBlob()
	scanner := &fakeScanner{results: map[string]domain.VulnerabilityRecord{}}
	clock := fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	snap := domain.DatabaseSnapshot{Source: "osv", Version: "v2"}
	db := &fakeDatabase{snapshot: snap} // no vulnerables

	uc := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	modCoord := coordinate.ModuleCoordinate{Path: "github.com/clean/mod", Version: "v1.0.0"}
	rec, err := uc.Scan(t.Context(), application.ScanModuleParams{
		Coordinate: modCoord,
		WalkID:     "w1",
		Snapshot:   &snap,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.OverallStatus != domain.StatusClean {
		t.Errorf("status = %q, want %q", rec.OverallStatus, domain.StatusClean)
	}
	if len(rec.Findings) != 0 {
		t.Errorf("findings count = %d, want 0", len(rec.Findings))
	}
}

func TestScanModule_PutVulnerabilityRecordError(t *testing.T) {
	walkStore := newFakeWalkStore()
	vulnStore := newFakeVulnStore()
	vulnStore.errOnPutRecord = errStore
	facts := newFakeFacts()
	blobs := newFakeBlob()
	coord := coordinate.ModuleCoordinate{Path: "github.com/a/b", Version: "v1.0.0"}
	h, _ := blobs.Put(t.Context(), strings.NewReader("zip"))
	if err := facts.PutFetchRecord(t.Context(), fetchdomain.FactRecord{
		ModulePath: coord.Path, ModuleVersion: coord.Version, PipelineVersion: "v1", ContentLocation: string(h),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}
	scanner := &fakeScanner{results: map[string]domain.VulnerabilityRecord{}}
	clock := fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	snap := domain.DatabaseSnapshot{Source: "s", Version: "v1"}
	db := &fakeDatabase{snapshot: snap}

	uc := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	_, err := uc.Scan(t.Context(), application.ScanModuleParams{
		Coordinate: coord,
		WalkID:     "w1",
		Snapshot:   &snap,
	})
	if err == nil {
		t.Fatal("expected error from PutVulnerabilityRecord, got nil")
	}
}

// --- scan_walk: Progress callback ---

func TestScanWalk_ProgressCallback(t *testing.T) {
	walkStore := newFakeWalkStore()
	coord := coordinate.ModuleCoordinate{Path: "github.com/a/b", Version: "v1.0.0"}
	seedWalk(t, walkStore, "w1", coord)

	vulnStore := newFakeVulnStore()
	facts := newFakeFacts()
	blobs := newFakeBlob()
	h, _ := blobs.Put(t.Context(), strings.NewReader("zip"))
	if err := facts.PutFetchRecord(t.Context(), fetchdomain.FactRecord{
		ModulePath: coord.Path, ModuleVersion: coord.Version, PipelineVersion: "v1", ContentLocation: string(h),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}
	scanner := &fakeScanner{results: map[string]domain.VulnerabilityRecord{}}
	clock := fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	snap := domain.DatabaseSnapshot{Source: "s", Version: "v1"}
	db := &fakeDatabase{snapshot: snap}
	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	uc := application.NewScanWalkUseCase(walkStore, vulnStore, moduleUC, nil, clock, "v1", slog.Default())

	var called int
	_, err := uc.Scan(t.Context(), application.ScanWalkParams{
		WalkID:   "w1",
		Snapshot: &snap,
		Progress: func(_ coordinate.ModuleCoordinate, _ domain.VulnerabilityRecord, current, total int) {
			called++
		},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if called != 1 {
		t.Errorf("expected Progress called 1 time, got %d", called)
	}
}

// --- compareFindingDelta: same path, different finding IDs ---

func TestDiff_SortingSamePathDifferentIDs(t *testing.T) {
	ctx := t.Context()
	snap := domain.DatabaseSnapshot{Source: "s", Version: "v1"}
	vulnStore := newFakeVulnStore()

	coord := coordinate.ModuleCoordinate{Path: "github.com/a/a", Version: "v1.0.0"}
	runA := makeRun("run-a", "walk-1", snap)
	runB := makeRun("run-b", "walk-1", snap)
	seedScanRun(t, ctx, vulnStore, runA, nil)

	recsB := []domain.VulnerabilityRecord{
		makeRecord(coord, "walk-1", makeFinding("CVE-Z", "z"), makeFinding("CVE-A", "a")),
	}
	seedScanRun(t, ctx, vulnStore, runB, recsB)

	uc := makeDiffUC(vulnStore)
	diff, err := uc.Diff(ctx, "run-a", "run-b")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(diff.NewFindings) != 2 {
		t.Fatalf("expected 2 new findings, got %d", len(diff.NewFindings))
	}
	if diff.NewFindings[0].Finding.ID != "CVE-A" {
		t.Errorf("expected CVE-A first, got %s", diff.NewFindings[0].Finding.ID)
	}
}

// --- reachabilityChanged nil→non-nil ---

func TestDiff_ReachabilityNilToNonNil(t *testing.T) {
	ctx := t.Context()
	snapA := domain.DatabaseSnapshot{Source: "s", Version: "v1"}
	snapB := domain.DatabaseSnapshot{Source: "s", Version: "v2"}
	vulnStore := newFakeVulnStore()

	coord := coordinate.ModuleCoordinate{Path: "github.com/a/b", Version: "v1.0.0"}
	finding := makeFinding("CVE-1", "some vuln")

	runA := makeRun("run-a", "walk-1", snapA)
	runB := makeRun("run-b", "walk-1", snapB)

	recsA := []domain.VulnerabilityRecord{makeRecord(coord, "walk-1", finding)}
	// In B, same finding but now with reachability info (nil → non-nil)
	findingWithReach := finding
	findingWithReach.Reachable = &domain.ReachabilityResult{IsReachable: true}
	recsB := []domain.VulnerabilityRecord{makeRecord(coord, "walk-1", findingWithReach)}

	seedScanRun(t, ctx, vulnStore, runA, recsA)
	seedScanRun(t, ctx, vulnStore, runB, recsB)

	uc := makeDiffUC(vulnStore)
	diff, err := uc.Diff(ctx, "run-a", "run-b")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(diff.ReachabilityChanges) != 1 {
		t.Fatalf("expected 1 reachability change, got %d", len(diff.ReachabilityChanges))
	}
	if diff.ReachabilityChanges[0].WasReachable {
		t.Error("expected WasReachable=false")
	}
	if !diff.ReachabilityChanges[0].IsReachable {
		t.Error("expected IsReachable=true")
	}
}
