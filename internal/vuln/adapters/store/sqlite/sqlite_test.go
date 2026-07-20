package sqlite_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

func newTestStore(t *testing.T) *sqlite.Store {
	t.Helper()
	db, err := sqlitestore.Open(":memory:", sqlite.Migrations())
	if err != nil {
		t.Fatalf("opening in-memory db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return sqlite.New(db)
}

func coord(path, version string) coordinate.ModuleCoordinate {
	return coordinate.ModuleCoordinate{Path: path, Version: version}
}

func snap(source, version string) domain.DatabaseSnapshot {
	return domain.DatabaseSnapshot{
		Source:      source,
		Version:     version,
		RetrievedAt: time.Now().UTC().Truncate(time.Second),
		ContentHash: "abc123",
	}
}

func TestPutAndGetVulnerabilityRecord(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	snapshot := snap("govulndb", "v2024-01-01")
	rec := domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord("github.com/foo/bar", "v1.0.0"),
		WalkID:           "walk-1",
		OverallStatus:    domain.StatusAffected,
		DatabaseSnapshot: snapshot,
		ScannedAt:        time.Now().UTC().Truncate(time.Second),
		PipelineVersion:  "v1",
		Findings: []domain.VulnerabilityFinding{
			{
				ID:            "GO-2024-0001",
				Aliases:       []string{"CVE-2024-0001"},
				Summary:       "test vuln",
				AffectedRange: "< v1.1.0",
				FixedIn:       "v1.1.0",
			},
		},
	}

	if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
		t.Fatalf("PutVulnerabilityRecord: %v", err)
	}

	got, found, err := store.GetVulnerabilityRecord(ctx, rec.Coordinate, "v1", snapshot)
	if err != nil {
		t.Fatalf("GetVulnerabilityRecord: %v", err)
	}
	if !found {
		t.Fatal("expected record to be found")
	}
	if got.OverallStatus != domain.StatusAffected {
		t.Errorf("status: got %s, want %s", got.OverallStatus, domain.StatusAffected)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("findings: got %d, want 1", len(got.Findings))
	}
	if got.Findings[0].ID != "GO-2024-0001" {
		t.Errorf("finding ID: got %s, want GO-2024-0001", got.Findings[0].ID)
	}
}

func TestPutVulnerabilityRecord_FirstScannedAtImmutableOnReScan(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	snapshot := snap("govulndb", "v2024-01-01")
	c := coord("github.com/foo/bar", "v1.0.0")
	first := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	later := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

	rec := domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       c,
		WalkID:           "walk-1",
		OverallStatus:    domain.StatusClean,
		DatabaseSnapshot: snapshot,
		ScannedAt:        first,
		FirstScannedAt:   first,
		PipelineVersion:  "v1",
	}
	if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
		t.Fatalf("first PutVulnerabilityRecord: %v", err)
	}

	// A later run re-validates the same (module, version, pipeline, snapshot):
	// scanned_at advances and a fresh record even proposes a new first-seen, but
	// the store must keep the original anchor.
	rescan := rec
	rescan.WalkID = "walk-2"
	rescan.ScannedAt = later
	rescan.FirstScannedAt = later
	if err := store.PutVulnerabilityRecord(ctx, rescan); err != nil {
		t.Fatalf("re-scan PutVulnerabilityRecord: %v", err)
	}

	got, found, err := store.GetVulnerabilityRecord(ctx, c, "v1", snapshot)
	if err != nil {
		t.Fatalf("GetVulnerabilityRecord: %v", err)
	}
	if !found {
		t.Fatal("expected record to be found")
	}
	if !got.FirstScannedAt.Equal(first) {
		t.Errorf("first_scanned_at moved: got %s, want stable %s", got.FirstScannedAt, first)
	}
	if !got.ScannedAt.Equal(later) {
		t.Errorf("scanned_at did not advance: got %s, want %s", got.ScannedAt, later)
	}
	if got.WalkID != "walk-2" {
		t.Errorf("walk_id not re-attributed: got %s, want walk-2", got.WalkID)
	}
}

func TestGetVulnerabilityRecord_NotFound(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	_, found, err := store.GetVulnerabilityRecord(ctx, coord("github.com/missing/mod", "v1.0.0"), "v1", snap("govulndb", "v1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("expected not found")
	}
}

func TestListVulnerabilityRecordsByFindingID(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	snapshot := snap("govulndb", "v2024-01-01")
	rec := domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord("github.com/foo/bar", "v1.0.0"),
		WalkID:           "walk-1",
		OverallStatus:    domain.StatusAffected,
		DatabaseSnapshot: snapshot,
		ScannedAt:        time.Now().UTC().Truncate(time.Second),
		PipelineVersion:  "v1",
		Findings: []domain.VulnerabilityFinding{
			{
				ID:            "GO-2024-0001",
				Aliases:       []string{"CVE-2024-0001", "GHSA-xxxx-yyyy-zzzz"},
				Summary:       "test vuln",
				AffectedRange: "< v1.1.0",
			},
		},
	}
	if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
		t.Fatalf("PutVulnerabilityRecord: %v", err)
	}

	// Query by primary ID
	records, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2024-0001")
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordsByFindingID: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}

	// Query by alias
	records, err = store.ListVulnerabilityRecordsByFindingID(ctx, "CVE-2024-0001")
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordsByFindingID by alias: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records by alias, want 1", len(records))
	}

	// Query for unknown ID
	records, err = store.ListVulnerabilityRecordsByFindingID(ctx, "GO-9999-9999")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("got %d records, want 0", len(records))
	}
}

func TestPutAndGetWalkScanRun(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	run := domain.WalkScanRun{
		ID:              "run-1",
		WalkID:          "walk-1",
		Snapshot:        snap("govulndb", "v2024-01-01"),
		OverallStatus:   domain.WalkStatusAllClean,
		Operator:        "tester",
		StartedAt:       time.Now().UTC().Truncate(time.Second),
		CompletedAt:     time.Now().UTC().Truncate(time.Second),
		PipelineVersion: "v1",
		ContentHash:     "hash1",
	}

	if err := store.PutWalkScanRun(ctx, run); err != nil {
		t.Fatalf("PutWalkScanRun: %v", err)
	}

	got, found, err := store.GetWalkScanRun(ctx, "run-1")
	if err != nil {
		t.Fatalf("GetWalkScanRun: %v", err)
	}
	if !found {
		t.Fatal("expected run to be found")
	}
	if got.WalkID != "walk-1" {
		t.Errorf("walk ID: got %s, want walk-1", got.WalkID)
	}
	if got.OverallStatus != domain.WalkStatusAllClean {
		t.Errorf("status: got %s, want %s", got.OverallStatus, domain.WalkStatusAllClean)
	}
}

func TestListWalkScanRuns(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	for i, id := range []string{"run-1", "run-2"} {
		run := domain.WalkScanRun{
			ID:              id,
			WalkID:          "walk-1",
			Snapshot:        snap("govulndb", "v2024-01-01"),
			OverallStatus:   domain.WalkStatusAllClean,
			Operator:        "tester",
			StartedAt:       time.Now().UTC().Add(time.Duration(i) * time.Second).Truncate(time.Second),
			CompletedAt:     time.Now().UTC().Add(time.Duration(i) * time.Second).Truncate(time.Second),
			PipelineVersion: "v1",
			ContentHash:     "hash" + id,
		}
		if err := store.PutWalkScanRun(ctx, run); err != nil {
			t.Fatalf("PutWalkScanRun %s: %v", id, err)
		}
	}

	runs, err := store.ListWalkScanRuns(ctx, "walk-1")
	if err != nil {
		t.Fatalf("ListWalkScanRuns: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("got %d runs, want 2", len(runs))
	}
}

func TestPutAndListDatabaseSnapshots(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	s1 := snap("govulndb", "v2024-01-01")
	s2 := snap("govulndb", "v2024-02-01")
	s2.RetrievedAt = s2.RetrievedAt.Add(24 * time.Hour)

	for _, s := range []domain.DatabaseSnapshot{s1, s2} {
		if err := store.PutDatabaseSnapshot(ctx, s, bytes.NewReader([]byte("content"))); err != nil {
			t.Fatalf("PutDatabaseSnapshot: %v", err)
		}
	}

	snapshots, err := store.ListDatabaseSnapshots(ctx)
	if err != nil {
		t.Fatalf("ListDatabaseSnapshots: %v", err)
	}
	if len(snapshots) != 2 {
		t.Fatalf("got %d snapshots, want 2", len(snapshots))
	}
}

func TestGetLatestDatabaseSnapshot_Empty(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	_, found, err := store.GetLatestDatabaseSnapshot(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("expected not found on empty store")
	}
}

func TestListVulnerabilityRecords(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	snapshot := snap("govulndb", "v2024-01-01")

	// Put two vulnerability records and collect their coordinates.
	modules := []string{"github.com/foo/bar", "github.com/baz/qux"}
	perModule := make(map[coordinate.ModuleCoordinate]string, len(modules))
	for _, path := range modules {
		c := coord(path, "v1.0.0")
		rec := domain.VulnerabilityRecord{
			Ecosystem:        fetchdomain.EcosystemGo,
			Coordinate:       c,
			WalkID:           "walk-1",
			OverallStatus:    domain.StatusClean,
			DatabaseSnapshot: snapshot,
			ScannedAt:        time.Now().UTC().Truncate(time.Second),
			PipelineVersion:  "v1",
		}
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord %s: %v", path, err)
		}
		perModule[c] = "hash-" + path
	}

	// Put the scan run with PerModuleResults so walk_scan_run_modules is populated.
	run := domain.WalkScanRun{
		ID:               "run-1",
		WalkID:           "walk-1",
		Snapshot:         snapshot,
		PerModuleResults: perModule,
		OverallStatus:    domain.WalkStatusAffected,
		Operator:         "tester",
		StartedAt:        time.Now().UTC().Truncate(time.Second),
		CompletedAt:      time.Now().UTC().Truncate(time.Second),
		PipelineVersion:  "v1",
		ContentHash:      "hash1",
	}
	if err := store.PutWalkScanRun(ctx, run); err != nil {
		t.Fatalf("PutWalkScanRun: %v", err)
	}

	records, err := store.ListVulnerabilityRecords(ctx, "run-1")
	if err != nil {
		t.Fatalf("ListVulnerabilityRecords: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
}
