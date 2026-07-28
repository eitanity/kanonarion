package sqlite_test

import (
	"path/filepath"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// ledgerSnapshot is the one advisory database every test here scans against, so
// re-scans land on the same composition group.
func ledgerSnapshot() domain.DatabaseSnapshot {
	return domain.DatabaseSnapshot{
		Source:      "govulndb",
		Version:     "2026-07-17T19:42:05Z",
		RetrievedAt: time.Date(2026, 7, 17, 19, 42, 5, 0, time.UTC),
		ContentHash: "sha256:snapshot",
	}
}

func ledgerRecord(t *testing.T, rooting domain.Rooting, scannedAt time.Time, status domain.VulnerabilityStatus) domain.VulnerabilityRecord {
	t.Helper()
	return seal(t, domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord("github.com/foo/bar", "v1.0.0"),
		WalkID:           "walk-1",
		OverallStatus:    status,
		DatabaseSnapshot: ledgerSnapshot(),
		ScannedAt:        scannedAt,
		FirstScannedAt:   scannedAt,
		PipelineVersion:  "v16",
		Rooting:          rooting,
	})
}

// The observable the conversion exists for, at the store: a re-measurement
// appends, both records survive, and a read returns the composition rather than
// whichever write happened to be last.
func TestPutVulnerabilityRecord_ReMeasurementAppends(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	first := ledgerRecord(t, domain.RootingIsolated, time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC), domain.StatusAffected)
	second := ledgerRecord(t, domain.RootingIsolated, time.Date(2026, 7, 18, 20, 0, 0, 0, time.UTC), domain.StatusClean)

	for _, rec := range []domain.VulnerabilityRecord{first, second} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
	}

	history, err := store.ListVulnerabilityRecordsForModule(ctx, first.Coordinate, first.PipelineVersion)
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordsForModule: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("ledger holds %d generations, want 2 — the second write overwrote the first", len(history))
	}

	// Composition, not recency: the unexplained all-clear does not retire the
	// finding-bearing record merely by running later.
	served, ok, err := store.GetVulnerabilityRecord(ctx, first.Coordinate, first.PipelineVersion, ledgerSnapshot())
	if err != nil || !ok {
		t.Fatalf("GetVulnerabilityRecord = found %v, err %v", ok, err)
	}
	if served.ContentHash != first.ContentHash {
		t.Fatalf("served %s, want the finding-bearing generation", served.OverallStatus)
	}
}

// A byte-identical record written twice is one measurement, not two. It must be
// a no-op rather than an error, or a retried write would fail a run that had
// already succeeded.
func TestPutVulnerabilityRecord_IdenticalReWriteIsANoOp(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	rec := ledgerRecord(t, domain.RootingIsolated, time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC), domain.StatusClean)
	for range 3 {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
	}

	history, err := store.ListVulnerabilityRecordsForModule(ctx, rec.Coordinate, rec.PipelineVersion)
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordsForModule: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("ledger holds %d rows for one measurement written three times, want 1", len(history))
	}
}

// The headline defect: before the frame was recorded, a target-rooted scan and
// an isolated scan of one coordinate under one snapshot shared a row, so
// whichever ran last silently answered for both questions. Both must now
// persist, and a frame-scoped read must serve its own.
func TestPutVulnerabilityRecord_TwoFramesBothPersist(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	isolated := ledgerRecord(t, domain.RootingIsolated, time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC), domain.StatusAffected)
	targetRooted := ledgerRecord(t, domain.RootingTargetRooted, time.Date(2026, 7, 18, 20, 0, 0, 0, time.UTC), domain.StatusClean)

	for _, rec := range []domain.VulnerabilityRecord{isolated, targetRooted} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
	}

	for _, tc := range []struct {
		rooting domain.Rooting
		want    domain.VulnerabilityRecord
	}{
		{domain.RootingIsolated, isolated},
		{domain.RootingTargetRooted, targetRooted},
	} {
		got, ok, err := store.GetVulnerabilityRecordAt(ctx, isolated.Coordinate, isolated.PipelineVersion, ledgerSnapshot(), tc.rooting)
		if err != nil || !ok {
			t.Fatalf("GetVulnerabilityRecordAt(%s) = found %v, err %v", tc.rooting, ok, err)
		}
		if got.ContentHash != tc.want.ContentHash {
			t.Fatalf("frame %s served the other frame's record (%s)", tc.rooting, got.OverallStatus)
		}
	}
}

// HasVulnerabilityRecord answers about one measurement, which is what a run
// needs to check that the records it reported were kept. Composition cannot
// answer it: the record a read serves is not necessarily the one a given run
// wrote, because an earlier generation may outrank it.
func TestHasVulnerabilityRecord_NamesTheGenerationNotTheCoordinate(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	kept := ledgerRecord(t, domain.RootingIsolated, time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC), domain.StatusAffected)
	superseded := ledgerRecord(t, domain.RootingIsolated, time.Date(2026, 7, 18, 20, 0, 0, 0, time.UTC), domain.StatusClean)
	for _, rec := range []domain.VulnerabilityRecord{kept, superseded} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
	}

	// The generation a read does NOT serve is still stored, and still answers.
	ok, err := store.HasVulnerabilityRecord(ctx, superseded.Coordinate, superseded.PipelineVersion, ledgerSnapshot(), superseded.ContentHash)
	if err != nil || !ok {
		t.Fatalf("HasVulnerabilityRecord(superseded) = %v, err %v; a stored generation must answer even when it is not served", ok, err)
	}
	ok, err = store.HasVulnerabilityRecord(ctx, kept.Coordinate, kept.PipelineVersion, ledgerSnapshot(), "a-hash-nothing-carries")
	if err != nil {
		t.Fatalf("HasVulnerabilityRecord(absent): %v", err)
	}
	if ok {
		t.Fatal("HasVulnerabilityRecord reported a generation the store does not hold")
	}
}

// TestMigration14_CarriesExistingRowsInAsTheFirstGeneration pins the conversion
// against a store shaped as it was before it: a pre-ledger row must survive the
// rebuild, still verify its content hash, and read back as a record whose frame
// is "not recorded" rather than as a frame it never stated.
func TestMigration14_CarriesExistingRowsInAsTheFirstGeneration(t *testing.T) {
	ctx := t.Context()

	// Open at migration 13 — the shape immediately before the ledger — and seed a
	// row the way the overwriting write path produced them. A file DSN, not
	// ":memory:", because the store has to be reopened at the full migration set
	// and an in-memory database does not survive the close.
	dsn := filepath.Join(t.TempDir(), "mirror.db")
	all := sqlite.Migrations()
	upTo13 := make([]sqlitestore.Migration, 0, len(all))
	for _, m := range all {
		if m.Version <= 13 {
			upTo13 = append(upTo13, m)
		}
	}
	db, err := sqlitestore.Open(dsn, upTo13)
	if err != nil {
		t.Fatalf("opening store at migration 13: %v", err)
	}

	legacy := ledgerRecord(t, domain.RootingUnrecorded, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC), domain.StatusAffected)
	blob, err := domain.VulnerabilityRecordHasher{}.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshalling legacy record: %v", err)
	}
	if _, err := db.DB().ExecContext(ctx, `
INSERT INTO vulnerability_records (
    module_path, module_version, pipeline_version, snapshot_source, snapshot_version,
    walk_id, overall_status, coverage_status, findings_status, finding_count,
    scanned_at, first_scanned_at, content_hash, serialised
) VALUES (?, ?, ?, ?, ?, 'walk-1', 'Affected', 'Analysed', 'Affected', 0,
          '2026-05-01T12:00:00Z', '2026-05-01T12:00:00Z', ?, ?)`,
		legacy.Coordinate.Path(), legacy.Coordinate.Version(), legacy.PipelineVersion,
		legacy.DatabaseSnapshot.Source, legacy.DatabaseSnapshot.Version,
		legacy.ContentHash, blob); err != nil {
		t.Fatalf("seeding pre-ledger row: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing at migration 13: %v", err)
	}

	migrated, err := sqlitestore.Open(dsn, all)
	if err != nil {
		t.Fatalf("applying migration 14: %v", err)
	}
	t.Cleanup(func() { _ = migrated.Close() })
	store := sqlite.New(migrated)

	// It survived, it still verifies (the read leg checks the seal), and it
	// states no frame.
	got, ok, err := store.GetVulnerabilityRecord(ctx, legacy.Coordinate, legacy.PipelineVersion, ledgerSnapshot())
	if err != nil || !ok {
		t.Fatalf("legacy row after migration 14: found %v, err %v", ok, err)
	}
	if got.ContentHash != legacy.ContentHash {
		t.Fatalf("migration 14 changed the stored record: %s", got.ContentHash)
	}
	if domain.RecordRooting(got).IsRecorded() {
		t.Fatalf("migration 14 invented a frame for a row that stated none: %q", domain.RecordRooting(got))
	}

	// And a scan in a stated frame appends beside it rather than replacing it.
	fresh := ledgerRecord(t, domain.RootingIsolated, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC), domain.StatusClean)
	if err := store.PutVulnerabilityRecord(ctx, fresh); err != nil {
		t.Fatalf("appending after migration: %v", err)
	}
	history, err := store.ListVulnerabilityRecordsForModule(ctx, legacy.Coordinate, legacy.PipelineVersion)
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordsForModule: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("ledger holds %d generations after migration plus one scan, want 2", len(history))
	}
}
