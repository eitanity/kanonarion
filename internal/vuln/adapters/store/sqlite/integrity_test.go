package sqlite_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

func integrityRecord() domain.VulnerabilityRecord {
	return domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord("github.com/foo/bar", "v1.0.0"),
		WalkID:           "walk-1",
		OverallStatus:    domain.StatusClean,
		DatabaseSnapshot: snap("govulndb", "v2024-01-01"),
		ScannedAt:        time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		FirstScannedAt:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion:  "v1",
	}
}

// TestPutVulnerabilityRecord_RefusesUnsealedRecord pins the write leg: a record
// whose hash does not describe its contents never reaches the table. An empty
// hash is the shape the two walk-scan paths used to persist.
func TestPutVulnerabilityRecord_RefusesUnsealedRecord(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	unsealed := integrityRecord()
	err := store.PutVulnerabilityRecord(ctx, unsealed)
	if !errors.Is(err, ports.ErrVulnIntegrity) {
		t.Fatalf("PutVulnerabilityRecord(unsealed) error = %v, want ErrVulnIntegrity", err)
	}

	// A hash that describes a different record is refused just as an absent one
	// is: the write leg checks what the hash says, not that it is non-empty.
	stale := seal(t, integrityRecord())
	stale.OverallStatus = domain.StatusAffected
	if err := store.PutVulnerabilityRecord(ctx, stale); !errors.Is(err, ports.ErrVulnIntegrity) {
		t.Fatalf("PutVulnerabilityRecord(stale hash) error = %v, want ErrVulnIntegrity", err)
	}

	// Nothing was stored by either refusal.
	if _, found, gerr := store.GetVulnerabilityRecord(ctx, unsealed.Coordinate, "v1", unsealed.DatabaseSnapshot); gerr != nil || found {
		t.Fatalf("GetVulnerabilityRecord() = found %v, err %v; want a refused write to store nothing", found, gerr)
	}
}

func TestPutWalkScanRun_RefusesUnsealedRun(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	run := domain.WalkScanRun{
		ID:              "vscan-walk-1-1",
		WalkID:          "walk-1",
		Snapshot:        snap("govulndb", "v2024-01-01"),
		StartedAt:       time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		CompletedAt:     time.Date(2024, 1, 1, 0, 1, 0, 0, time.UTC),
		PipelineVersion: "v1",
	}
	if err := store.PutWalkScanRun(ctx, run); !errors.Is(err, ports.ErrVulnIntegrity) {
		t.Fatalf("PutWalkScanRun(unsealed) error = %v, want ErrVulnIntegrity", err)
	}
}

// TestReadPaths_RefuseTamperedRecord is the point of the whole change: a record
// altered in the database after it was written is reported as a tamper by every
// read path, never as absence and never as a valid verdict. Reporting absence
// would turn a detected tamper into a silent re-scan that overwrites the
// evidence of it.
func TestReadPaths_RefuseTamperedRecord(t *testing.T) {
	ctx := t.Context()
	db, err := sqlitestore.Open(":memory:", sqlite.Migrations())
	if err != nil {
		t.Fatalf("opening in-memory db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := sqlite.New(db)

	rec := seal(t, integrityRecord())
	rec.Findings = []domain.VulnerabilityFinding{{ID: "GO-2024-0001"}}
	rec = seal(t, rec)
	if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
		t.Fatalf("PutVulnerabilityRecord: %v", err)
	}

	run := sealRun(t, domain.WalkScanRun{
		ID:               "vscan-walk-1-1",
		WalkID:           "walk-1",
		Snapshot:         rec.DatabaseSnapshot,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{rec.Coordinate: rec.ContentHash},
		StartedAt:        rec.ScannedAt,
		CompletedAt:      rec.ScannedAt,
		PipelineVersion:  "v1",
	})
	if err := store.PutWalkScanRun(ctx, run); err != nil {
		t.Fatalf("PutWalkScanRun: %v", err)
	}

	// Alter the stored body without touching the hash — exactly what a tamper
	// (or a corrupting write from outside the store) looks like.
	tampered := rec
	tampered.OverallStatus = domain.StatusAffected
	blob, err := domain.VulnerabilityRecordHasher{}.Marshal(tampered)
	if err != nil {
		t.Fatalf("marshalling tampered record: %v", err)
	}
	if _, err := db.DB().ExecContext(ctx,
		`UPDATE vulnerability_records SET serialised = ?`, blob); err != nil {
		t.Fatalf("tampering with stored record: %v", err)
	}

	t.Run("GetVulnerabilityRecord", func(t *testing.T) {
		_, found, err := store.GetVulnerabilityRecord(ctx, rec.Coordinate, "v1", rec.DatabaseSnapshot)
		assertTamperReported(t, err, found)
	})
	t.Run("GetLatestVulnerabilityRecord", func(t *testing.T) {
		_, found, err := store.GetLatestVulnerabilityRecord(ctx, rec.Coordinate, "v1")
		assertTamperReported(t, err, found)
	})
	t.Run("ListVulnerabilityRecordsForModuleInWalk", func(t *testing.T) {
		got, err := store.ListVulnerabilityRecordsForModuleInWalk(ctx, rec.Coordinate, "v1", "walk-1")
		assertTamperReported(t, err, len(got) > 0)
	})
	t.Run("ListVulnerabilityRecordsByFindingID", func(t *testing.T) {
		got, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2024-0001", "")
		assertTamperReported(t, err, len(got) > 0)
	})
	t.Run("ListVulnerabilityRecords", func(t *testing.T) {
		got, err := store.ListVulnerabilityRecords(ctx, run.ID)
		assertTamperReported(t, err, len(got) > 0)
	})
	t.Run("ListVulnerabilityRecordsForModule", func(t *testing.T) {
		got, err := store.ListVulnerabilityRecordsForModule(ctx, rec.Coordinate, "v1")
		assertTamperReported(t, err, len(got) > 0)
	})
}

func assertTamperReported(t *testing.T, err error, returned bool) {
	t.Helper()
	if !errors.Is(err, ports.ErrVulnIntegrity) {
		t.Errorf("error = %v, want ErrVulnIntegrity", err)
	}
	if returned {
		t.Error("a tampered record was returned to the caller")
	}
}

func TestGetWalkScanRun_RefusesTamperedRun(t *testing.T) {
	ctx := t.Context()
	db, err := sqlitestore.Open(":memory:", sqlite.Migrations())
	if err != nil {
		t.Fatalf("opening in-memory db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := sqlite.New(db)

	run := sealRun(t, domain.WalkScanRun{
		ID:              "vscan-walk-1-1",
		WalkID:          "walk-1",
		Snapshot:        snap("govulndb", "v2024-01-01"),
		StartedAt:       time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		CompletedAt:     time.Date(2024, 1, 1, 0, 1, 0, 0, time.UTC),
		PipelineVersion: "v1",
	})
	if err := store.PutWalkScanRun(ctx, run); err != nil {
		t.Fatalf("PutWalkScanRun: %v", err)
	}

	tampered := run
	tampered.OverallStatus = domain.WalkStatusAllClean
	blob, err := domain.WalkScanRunHasher{}.Marshal(tampered)
	if err != nil {
		t.Fatalf("marshalling tampered run: %v", err)
	}
	if _, err := db.DB().ExecContext(ctx, `UPDATE walk_scan_runs SET serialised = ?`, blob); err != nil {
		t.Fatalf("tampering with stored run: %v", err)
	}

	_, found, err := store.GetWalkScanRun(ctx, run.ID)
	assertTamperReported(t, err, found)

	runs, err := store.ListWalkScanRuns(ctx, "walk-1")
	assertTamperReported(t, err, len(runs) > 0)

	all, err := store.ListAllWalkScanRuns(ctx)
	assertTamperReported(t, err, len(all) > 0)
}

// TestStoreIntegrity_FindingsIndexAgreesWithRecords runs the findings-index
// consistency check as part of the integrity suite, over a store exercised the
// way production exercises it: several coordinates, an alias-bearing finding,
// and a re-scan of one key that retires an advisory.
//
// It belongs here rather than only beside the index's own unit tests because
// the defect it guards is the one the rest of this suite cannot see: a record
// whose content hash verifies perfectly while a stale index row says it reports
// an advisory it does not carry. Every per-record check passes on such a store.
func TestStoreIntegrity_FindingsIndexAgreesWithRecords(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	snapshot := snap("govulndb", "2026-07-17T19:42:05Z")
	put := func(path string, status domain.VulnerabilityStatus, findings ...domain.VulnerabilityFinding) {
		t.Helper()
		rec := seal(t, domain.VulnerabilityRecord{
			Ecosystem:        fetchdomain.EcosystemGo,
			Coordinate:       coord(path, "v1.0.0"),
			WalkID:           "walk-1",
			Findings:         findings,
			OverallStatus:    status,
			DatabaseSnapshot: snapshot,
			ScannedAt:        time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC),
			FirstScannedAt:   time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC),
			PipelineVersion:  "v14",
		})
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord(%s, %s): %v", path, status, err)
		}
	}

	put("github.com/foo/affected", domain.StatusAffected,
		finding("GO-2026-0001", "CVE-2026-1111"))
	put("github.com/foo/clean", domain.StatusClean)
	put("github.com/foo/unscannable", domain.StatusUnscannable)
	// The re-scan that retires an advisory — the exact shape that used to leave
	// the index asserting a finding the record no longer carries.
	put("github.com/foo/affected", domain.StatusClean)

	defects, err := store.CheckFindingsIndex(ctx)
	if err != nil {
		t.Fatalf("CheckFindingsIndex: %v", err)
	}
	if err := sqlite.FindingsIndexDefectsError(defects); err != nil {
		t.Fatalf("store integrity: %v", err)
	}
}

// TestMigration_PurgesEmptyHashRows covers the rows the unsealed write paths
// left behind: the read leg cannot return them, so the migration removes them
// rather than leaving rows every read reports as a tamper.
func TestMigration_PurgesEmptyHashRows(t *testing.T) {
	ctx := t.Context()

	// Migrate to version 8 only, then insert the legacy shape those paths wrote.
	pre := []sqlitestore.Migration{}
	for _, m := range sqlite.Migrations() {
		if m.Version <= 8 {
			pre = append(pre, m)
		}
	}
	path := t.TempDir() + "/mirror.db"
	db, err := sqlitestore.Open(path, pre)
	if err != nil {
		t.Fatalf("opening db at version 8: %v", err)
	}

	if _, err := db.DB().ExecContext(ctx, `
INSERT INTO vulnerability_records (
    module_path, module_version, pipeline_version, snapshot_source,
    snapshot_version, walk_id, overall_status, finding_count,
    scanned_at, first_scanned_at, content_hash, serialised
) VALUES ('example.com/localdep', 'v0.0.0', 'v14', 'govulndb', 'v1', 'walk-1',
          'Unscannable', 0, '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z', '', '{}');

INSERT INTO vulnerability_findings_index (
    finding_id, module_path, module_version, pipeline_version,
    snapshot_source, snapshot_version, is_reachable
) VALUES ('GO-2024-0001', 'example.com/localdep', 'v0.0.0', 'v14', 'govulndb', 'v1', NULL);
`); err != nil {
		t.Fatalf("seeding legacy empty-hash row: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing db: %v", err)
	}

	// Re-open with the full migration set, which applies version 9.
	migrated, err := sqlitestore.Open(path, sqlite.Migrations())
	if err != nil {
		t.Fatalf("applying migration 9: %v", err)
	}
	t.Cleanup(func() { _ = migrated.Close() })

	var records, index int
	if err := migrated.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM vulnerability_records WHERE content_hash = ''`).Scan(&records); err != nil {
		t.Fatalf("counting empty-hash records: %v", err)
	}
	if records != 0 {
		t.Errorf("empty-hash records after migration = %d, want 0", records)
	}
	if err := migrated.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM vulnerability_findings_index WHERE module_path = 'example.com/localdep'`).Scan(&index); err != nil {
		t.Fatalf("counting orphaned index entries: %v", err)
	}
	if index != 0 {
		t.Errorf("index entries for the purged record = %d, want 0", index)
	}
}

// assertSnapshotIntegrity pins both halves of the sentinel split for a snapshot
// failure: it answers to ErrSnapshotIntegrity, and it does NOT answer to
// ErrVulnIntegrity.
//
// The negative half is the point. A corrupt snapshot invalidates every verdict
// derived from it while a corrupt record invalidates one module's, so a caller
// that would abort the run and re-fetch the database on the first must not have
// the second match the same test. That is also why ErrSnapshotIntegrity does not
// wrap ErrVulnIntegrity — wrapping would make this assertion impossible to write.
func assertSnapshotIntegrity(t *testing.T, err error, what string) {
	t.Helper()
	if !errors.Is(err, ports.ErrSnapshotIntegrity) {
		t.Fatalf("%s error = %v, want ErrSnapshotIntegrity", what, err)
	}
	if errors.Is(err, ports.ErrVulnIntegrity) {
		t.Fatalf("%s reported a snapshot failure as a record failure: %v", what, err)
	}
}

// TestIntegritySentinels_RecordAndSnapshotAreDistinguishable is the whole point
// of the split, asserted in both directions at once: each failure answers to its
// own sentinel and to neither the other's.
//
// Stated as one test because the property is a relation between the two, not two
// independent facts — before the split both answered to ErrVulnIntegrity, and
// every individual assertion still passed.
func TestIntegritySentinels_RecordAndSnapshotAreDistinguishable(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	t.Run("a corrupt record is not a corrupt snapshot", func(t *testing.T) {
		unsealed := domain.VulnerabilityRecord{
			Ecosystem:        fetchdomain.EcosystemGo,
			Coordinate:       coord("github.com/foo/bar", "v1.0.0"),
			OverallStatus:    domain.StatusClean,
			DatabaseSnapshot: snap("govulndb", "v2024-01-01"),
			ScannedAt:        time.Now().UTC().Truncate(time.Second),
			PipelineVersion:  "v1",
		}
		err := store.PutVulnerabilityRecord(ctx, unsealed)
		if !errors.Is(err, ports.ErrVulnIntegrity) {
			t.Fatalf("error = %v, want ErrVulnIntegrity", err)
		}
		if errors.Is(err, ports.ErrSnapshotIntegrity) {
			t.Fatalf("a record failure matched the snapshot sentinel: %v", err)
		}
	})

	t.Run("a corrupt run is not a corrupt snapshot", func(t *testing.T) {
		err := store.PutWalkScanRun(ctx, domain.WalkScanRun{
			ID:               "vscan-1",
			WalkID:           "walk-1",
			Snapshot:         snap("govulndb", "v2024-01-01"),
			PerModuleResults: map[coordinate.ModuleCoordinate]string{},
		})
		if !errors.Is(err, ports.ErrVulnIntegrity) {
			t.Fatalf("error = %v, want ErrVulnIntegrity", err)
		}
		if errors.Is(err, ports.ErrSnapshotIntegrity) {
			t.Fatalf("a run failure matched the snapshot sentinel: %v", err)
		}
	})

	// A snapshot stored before hashing existed carries an empty hash. It is
	// unverifiable, which is not the same claim as corrupt, so it reads back
	// without error and matches neither sentinel.
	t.Run("an unverifiable legacy snapshot is not a failure at all", func(t *testing.T) {
		s := snap("govulndb", "v2024-02-01")
		if err := store.PutDatabaseSnapshot(ctx, s, strings.NewReader("advisories")); err != nil {
			t.Fatalf("PutDatabaseSnapshot: %v", err)
		}
		// Clear the hash the store computed on the way in, leaving the pre-hash shape.
		if _, err := store.InternalDB().DB().ExecContext(ctx,
			`UPDATE vulnerability_snapshots SET content_hash = '' WHERE source = ? AND version = ?`,
			s.Source(), s.Version()); err != nil {
			t.Fatalf("unsealing the stored snapshot: %v", err)
		}
		body, err := store.GetDatabaseSnapshot(ctx, s)
		if err != nil {
			t.Fatalf("GetDatabaseSnapshot(legacy) = %v, want it read back unverified", err)
		}
		_ = body.Close()
	})
}
