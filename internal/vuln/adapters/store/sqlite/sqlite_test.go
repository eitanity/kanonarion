package sqlite_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
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
	return coordinatetest.MustNew(path, version)
}

func snap(source, version string) domain.DatabaseSnapshot {
	return domain.DatabaseSnapshot{
		Source:      source,
		Version:     version,
		RetrievedAt: time.Now().UTC().Truncate(time.Second),
		ContentHash: "abc123",
	}
}

// seal stamps rec with its content hash, as every production write path does.
// The store refuses an unsealed record, so a test that writes one is testing a
// write that cannot happen.
func seal(t *testing.T, rec domain.VulnerabilityRecord) domain.VulnerabilityRecord {
	t.Helper()
	sealed, err := domain.VulnerabilityRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("sealing record: %v", err)
	}
	return sealed
}

// sealRun is seal for a walk scan run.
func sealRun(t *testing.T, run domain.WalkScanRun) domain.WalkScanRun {
	t.Helper()
	sealed, err := domain.WalkScanRunHasher{}.SetContentHash(run)
	if err != nil {
		t.Fatalf("sealing run: %v", err)
	}
	return sealed
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

	if err := store.PutVulnerabilityRecord(ctx, seal(t, rec)); err != nil {
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
	if err := store.PutVulnerabilityRecord(ctx, seal(t, rec)); err != nil {
		t.Fatalf("first PutVulnerabilityRecord: %v", err)
	}

	// A later run re-validates the same (module, version, pipeline, snapshot):
	// scanned_at advances and a fresh record even proposes a new first-seen, but
	// the store must keep the original anchor.
	rescan := rec
	rescan.WalkID = "walk-2"
	rescan.ScannedAt = later
	rescan.FirstScannedAt = later
	if err := store.PutVulnerabilityRecord(ctx, seal(t, rescan)); err != nil {
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
	if err := store.PutVulnerabilityRecord(ctx, seal(t, rec)); err != nil {
		t.Fatalf("PutVulnerabilityRecord: %v", err)
	}

	// Query by primary ID
	records, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2024-0001", "")
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordsByFindingID: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}

	// Query by alias
	records, err = store.ListVulnerabilityRecordsByFindingID(ctx, "CVE-2024-0001", "")
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordsByFindingID by alias: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records by alias, want 1", len(records))
	}

	// Query for unknown ID
	records, err = store.ListVulnerabilityRecordsByFindingID(ctx, "GO-9999-9999", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("got %d records, want 0", len(records))
	}
}

// findingRecord builds a sealed record carrying one finding, so the by-finding
// tests below differ only in coordinate and walk.
func findingRecord(t *testing.T, path, version, walkID, findingID string, snapshot domain.DatabaseSnapshot) domain.VulnerabilityRecord {
	t.Helper()
	return seal(t, domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord(path, version),
		WalkID:           walkID,
		OverallStatus:    domain.StatusAffected,
		DatabaseSnapshot: snapshot,
		ScannedAt:        time.Now().UTC().Truncate(time.Second),
		PipelineVersion:  "v1",
		Findings: []domain.VulnerabilityFinding{
			{ID: findingID, Summary: "test vuln", AffectedRange: "< v1.1.0"},
		},
	})
}

// scanRun builds a sealed run for walkID covering the given coordinates.
func scanRun(t *testing.T, id, walkID string, snapshot domain.DatabaseSnapshot, coords ...coordinate.ModuleCoordinate) domain.WalkScanRun {
	t.Helper()
	per := make(map[coordinate.ModuleCoordinate]string, len(coords))
	for _, c := range coords {
		per[c] = "hash-" + c.Version()
	}
	now := time.Now().UTC().Truncate(time.Second)
	return sealRun(t, domain.WalkScanRun{
		ID:               id,
		WalkID:           walkID,
		Snapshot:         snapshot,
		PerModuleResults: per,
		StartedAt:        now,
		CompletedAt:      now,
		OverallStatus:    domain.WalkStatusAffected,
		Operator:         "tester",
		PipelineVersion:  "v1",
	})
}

// One coordinate scanned under two generations yields one row. Reporting both
// made the command answer Affected and Clean for the same module version in one
// listing, with nothing to rank the two.
//
// The survivor is the finding, not the newest scan: a later all-clear says the
// module was clean when that scan ran, which does not retract an earlier
// finding. Retracting is the withdrawn-advisory work's job, and a Clean row must
// not do it by accident.
func TestListVulnerabilityRecordsByFindingID_LaterCleanDoesNotRetractEarlierFinding(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	affected := findingRecord(t, "github.com/foo/bar", "v1.0.0", "walk-1", "GO-2024-0001", snap("govulndb", "v2024-01-01"))
	affected.ScannedAt = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	affected.OverallStatus = domain.StatusAffected
	affected = seal(t, affected)

	laterClean := findingRecord(t, "github.com/foo/bar", "v1.0.0", "walk-1", "GO-2024-0001", snap("govulndb", "v2024-06-01"))
	laterClean.ScannedAt = time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	laterClean.OverallStatus = domain.StatusClean
	laterClean = seal(t, laterClean)

	for _, rec := range []domain.VulnerabilityRecord{affected, laterClean} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
	}

	got, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2024-0001", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1 per coordinate", len(got))
	}
	if got[0].OverallStatus != domain.StatusAffected {
		t.Errorf("status: got %s, want the finding to survive the later all-clear (%s)", got[0].OverallStatus, domain.StatusAffected)
	}
}

// Among records that agree on the verdict, the newest scan is the one reported.
func TestListVulnerabilityRecordsByFindingID_NewestWinsAmongEqualVerdicts(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	older := findingRecord(t, "github.com/foo/bar", "v1.0.0", "walk-1", "GO-2024-0001", snap("govulndb", "v2024-01-01"))
	older.ScannedAt = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	older = seal(t, older)

	newer := findingRecord(t, "github.com/foo/bar", "v1.0.0", "walk-1", "GO-2024-0001", snap("govulndb", "v2024-06-01"))
	newer.ScannedAt = time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	newer = seal(t, newer)

	for _, rec := range []domain.VulnerabilityRecord{older, newer} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
	}

	got, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2024-0001", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1 per coordinate", len(got))
	}
	if !got[0].ScannedAt.Equal(newer.ScannedAt) {
		t.Errorf("scanned_at: got %s, want the newer scan %s", got[0].ScannedAt, newer.ScannedAt)
	}
}

// A record whose newest scan predates a pipeline bump must still be reported.
// Pinning the reader's current pipeline version would have silently dropped 39%
// of the findings in a working store.
func TestListVulnerabilityRecordsByFindingID_OlderPipelineGenerationStillAnswers(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	stale := findingRecord(t, "github.com/foo/bar", "v1.0.0", "walk-1", "GO-2024-0001", snap("govulndb", "v2024-01-01"))
	stale.PipelineVersion = "v10" // superseded; nothing has re-scanned this module since.
	stale = seal(t, stale)
	if err := store.PutVulnerabilityRecord(ctx, stale); err != nil {
		t.Fatalf("PutVulnerabilityRecord: %v", err)
	}

	got, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2024-0001", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want the superseded-generation record reported, not dropped", len(got))
	}
}

// Generations are ranked numerically, so v9 does not outrank v14 the way a text
// compare would when two scans share a timestamp.
func TestListVulnerabilityRecordsByFindingID_PipelineTieBreakIsNumeric(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	sameInstant := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

	// Both Affected, so the verdict rank cannot decide and the generation must.
	old := findingRecord(t, "github.com/foo/bar", "v1.0.0", "walk-1", "GO-2024-0001", snap("govulndb", "v2024-01-01"))
	old.PipelineVersion = "v9"
	old.ScannedAt = sameInstant
	old = seal(t, old)

	current := findingRecord(t, "github.com/foo/bar", "v1.0.0", "walk-1", "GO-2024-0001", snap("govulndb", "v2024-06-01"))
	current.PipelineVersion = "v14"
	current.ScannedAt = sameInstant
	current = seal(t, current)

	for _, rec := range []domain.VulnerabilityRecord{old, current} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
	}

	got, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2024-0001", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].PipelineVersion != "v14" {
		t.Errorf("tie-break picked pipeline %s, want v14", got[0].PipelineVersion)
	}
}

// A by-finding query scoped to a walk answers for that walk's modules only. The
// unscoped answer spans every stored version, including one that a later build
// patched out — reporting that version as affected is a false security claim.
func TestListVulnerabilityRecordsByFindingID_ScopedToWalk(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)
	snapshot := snap("govulndb", "v2024-01-01")

	old := findingRecord(t, "github.com/foo/bar", "v1.0.0", "walk-1", "GO-2024-0001", snapshot)
	current := findingRecord(t, "github.com/foo/bar", "v1.2.0", "walk-2", "GO-2024-0001", snapshot)
	for _, rec := range []domain.VulnerabilityRecord{old, current} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
	}
	if err := store.PutWalkScanRun(ctx, scanRun(t, "run-1", "walk-1", snapshot, old.Coordinate)); err != nil {
		t.Fatalf("PutWalkScanRun run-1: %v", err)
	}
	if err := store.PutWalkScanRun(ctx, scanRun(t, "run-2", "walk-2", snapshot, current.Coordinate)); err != nil {
		t.Fatalf("PutWalkScanRun run-2: %v", err)
	}

	unscoped, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2024-0001", "")
	if err != nil {
		t.Fatalf("unscoped: %v", err)
	}
	if len(unscoped) != 2 {
		t.Fatalf("unscoped: got %d records, want 2", len(unscoped))
	}

	scoped, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2024-0001", "walk-2")
	if err != nil {
		t.Fatalf("scoped: %v", err)
	}
	if len(scoped) != 1 {
		t.Fatalf("scoped: got %d records, want 1", len(scoped))
	}
	if got := scoped[0].Coordinate.Version(); got != "v1.2.0" {
		t.Errorf("scoped to walk-2: got version %s, want v1.2.0", got)
	}
}

// walk_id on vulnerability_records is provenance for the last walk that
// triggered the scan, so a record two walks share names only one of them.
// Scoping must go through the run membership index, or the other walk loses a
// module it demonstrably contains.
func TestListVulnerabilityRecordsByFindingID_WalkScopeIgnoresRecordProvenance(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)
	snapshot := snap("govulndb", "v2024-01-01")

	// Stored under walk-2, so vr.walk_id says "walk-2" ...
	rec := findingRecord(t, "github.com/foo/bar", "v1.0.0", "walk-2", "GO-2024-0001", snapshot)
	if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
		t.Fatalf("PutVulnerabilityRecord: %v", err)
	}
	// ... but walk-1's scan run covered the same module.
	if err := store.PutWalkScanRun(ctx, scanRun(t, "run-1", "walk-1", snapshot, rec.Coordinate)); err != nil {
		t.Fatalf("PutWalkScanRun run-1: %v", err)
	}
	// Two runs of walk-1 cover it, which must not duplicate the record.
	if err := store.PutWalkScanRun(ctx, scanRun(t, "run-1b", "walk-1", snapshot, rec.Coordinate)); err != nil {
		t.Fatalf("PutWalkScanRun run-1b: %v", err)
	}

	scoped, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2024-0001", "walk-1")
	if err != nil {
		t.Fatalf("scoped: %v", err)
	}
	if len(scoped) != 1 {
		t.Fatalf("scoped to walk-1: got %d records, want 1", len(scoped))
	}
}

// An unknown walk is an error, not an empty result: "no modules affected" for a
// walk that was never scanned reads as an all-clear it has no basis for.
func TestListVulnerabilityRecordsByFindingID_UnknownWalkIsError(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)
	snapshot := snap("govulndb", "v2024-01-01")

	rec := findingRecord(t, "github.com/foo/bar", "v1.0.0", "walk-1", "GO-2024-0001", snapshot)
	if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
		t.Fatalf("PutVulnerabilityRecord: %v", err)
	}

	got, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2024-0001", "walk-never-scanned")
	if err == nil {
		t.Fatalf("expected an error for an unscanned walk, got %d records", len(got))
	}
	if !strings.Contains(err.Error(), "walk-never-scanned") {
		t.Errorf("error should name the walk, got: %v", err)
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

	if err := store.PutWalkScanRun(ctx, sealRun(t, run)); err != nil {
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
		if err := store.PutWalkScanRun(ctx, sealRun(t, run)); err != nil {
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

	const body = "content"
	// The store seals a snapshot against the bytes it stores, so a caller-declared
	// hash has to be the real one; "abc123" from the shared helper is not.
	want := domain.HashSnapshotContent([]byte(body))

	s1 := snap("govulndb", "v2024-01-01")
	s1.ContentHash = want
	s2 := snap("govulndb", "v2024-02-01")
	s2.ContentHash = ""
	s2.RetrievedAt = s2.RetrievedAt.Add(24 * time.Hour)

	for _, s := range []domain.DatabaseSnapshot{s1, s2} {
		if err := store.PutDatabaseSnapshot(ctx, s, bytes.NewReader([]byte(body))); err != nil {
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
	// Both are sealed: the one that declared its hash and the one that did not.
	for _, s := range snapshots {
		if s.ContentHash != want {
			t.Errorf("snapshot %s@%s content hash = %q, want %q", s.Source, s.Version, s.ContentHash, want)
		}
	}
}

// TestPutDatabaseSnapshot_RefusesDeclaredHashMismatch pins the write leg: a
// caller asserting which bytes it fetched is checked against the bytes that
// actually arrived, rather than having its claim overwritten silently.
func TestPutDatabaseSnapshot_RefusesDeclaredHashMismatch(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	s := snap("govulndb", "v2024-01-01")
	s.ContentHash = domain.HashSnapshotContent([]byte("the bytes I fetched"))

	err := store.PutDatabaseSnapshot(ctx, s, bytes.NewReader([]byte("different bytes")))
	if !errors.Is(err, ports.ErrVulnIntegrity) {
		t.Fatalf("PutDatabaseSnapshot(mismatched hash) error = %v, want ErrVulnIntegrity", err)
	}
}

// TestGetDatabaseSnapshot_RefusesTamperedBlob pins the read leg: the advisory
// database is the evidence every finding derives from, so a blob that no longer
// matches its stored hash is refused rather than fed to a scan. It is reported
// as an integrity failure, not as absence — absence would trigger a silent
// re-fetch that overwrites the evidence of the tamper.
func TestGetDatabaseSnapshot_RefusesTamperedBlob(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	s := snap("govulndb", "v2024-01-01")
	s.ContentHash = ""
	if err := store.PutDatabaseSnapshot(ctx, s, bytes.NewReader([]byte("honest advisories"))); err != nil {
		t.Fatalf("PutDatabaseSnapshot: %v", err)
	}

	if _, err := store.InternalDB().DB().ExecContext(ctx,
		`UPDATE vulnerability_snapshots SET content = ? WHERE source = ? AND version = ?`,
		[]byte("swapped advisories"), s.Source, s.Version); err != nil {
		t.Fatalf("tampering with the stored blob: %v", err)
	}

	if _, err := store.GetDatabaseSnapshot(ctx, s); !errors.Is(err, ports.ErrVulnIntegrity) {
		t.Fatalf("GetDatabaseSnapshot(tampered) error = %v, want ErrVulnIntegrity", err)
	}
}

// TestGetLatestDatabaseSnapshot_CarriesContentHash covers the read that used to
// drop the column: a cached snapshot flows straight into the records built
// against it, so a hash omitted here was a hash absent from every one of them.
func TestGetLatestDatabaseSnapshot_CarriesContentHash(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	const body = "advisory database bytes"
	s := snap("govulndb", "v2024-01-01")
	s.ContentHash = ""
	if err := store.PutDatabaseSnapshot(ctx, s, bytes.NewReader([]byte(body))); err != nil {
		t.Fatalf("PutDatabaseSnapshot: %v", err)
	}

	latest, found, err := store.GetLatestDatabaseSnapshot(ctx)
	if err != nil || !found {
		t.Fatalf("GetLatestDatabaseSnapshot() = found %v, err %v", found, err)
	}
	if want := domain.HashSnapshotContent([]byte(body)); latest.ContentHash != want {
		t.Fatalf("latest snapshot content hash = %q, want %q", latest.ContentHash, want)
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
		if err := store.PutVulnerabilityRecord(ctx, seal(t, rec)); err != nil {
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
	if err := store.PutWalkScanRun(ctx, sealRun(t, run)); err != nil {
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
