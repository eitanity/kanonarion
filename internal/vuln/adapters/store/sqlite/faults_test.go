package sqlite_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// The store's error arms cannot be reached by choosing inputs — the database has
// to actually fail. These tests induce that through SQLite itself, with an
// ABORT trigger on the statement under test or by removing the table it needs,
// so no production code carries a test-only hook. The arms matter: this store's
// contract is that a write either lands whole or reports why, and an untested
// error path is where "reports why" silently becomes "returns nil".

// abortOn installs a BEFORE-<op> trigger that aborts every such statement on
// table, so the next store call that issues one fails for real.
func abortOn(t *testing.T, store *sqlite.Store, op, table string) {
	t.Helper()
	stmt := `CREATE TRIGGER fault_` + op + `_` + table + ` BEFORE ` + op + ` ON ` + table +
		` BEGIN SELECT RAISE(ABORT, 'injected fault'); END;`
	if _, err := store.InternalDB().DB().ExecContext(context.Background(), stmt); err != nil {
		t.Fatalf("installing %s fault on %s: %v", op, table, err)
	}
}

// faultRecord is a sealed record carrying one finding with an alias, so the
// index-insert loop runs and can be made to fail.
func faultRecord(t *testing.T) domain.VulnerabilityRecord {
	t.Helper()
	return seal(t, domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord("example.com/mod", "v1.0.0"),
		WalkID:           "walk-1",
		OverallStatus:    domain.StatusAffected,
		DatabaseSnapshot: snap("govulndb", "v2024-01-01"),
		ScannedAt:        time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		FirstScannedAt:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion:  "v1",
		Findings: []domain.VulnerabilityFinding{
			{ID: "GO-2024-0001", Aliases: []string{"CVE-2024-0001"}, Summary: "s", AffectedRange: "< v2"},
		},
	})
}

// TestPutVulnerabilityRecord_ReportsEveryWriteFailure walks each statement in
// the write transaction and proves the failure is reported rather than
// swallowed, and that nothing is left behind — the transaction is what makes
// the record and its index rows land together or not at all.
func TestPutVulnerabilityRecord_ReportsEveryWriteFailure(t *testing.T) {
	for _, tc := range []struct {
		name    string
		op      string
		table   string
		wantMsg string
		// seedFirst writes the record once before the fault is installed. A row
		// trigger fires per row, so the reconciliation DELETE can only be made to
		// fail once there are index rows for it to remove — which is also the only
		// state in which that statement does any work.
		seedFirst bool
	}{
		{name: "record insert fails", op: "INSERT", table: "vulnerability_records", wantMsg: "inserting vulnerability record"},
		{name: "index reconciliation delete fails", op: "DELETE", table: "vulnerability_findings_index", wantMsg: "clearing finding index entries", seedFirst: true},
		{name: "index insert fails", op: "INSERT", table: "vulnerability_findings_index", wantMsg: "inserting finding index entry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			store := newTestStore(t)
			if tc.seedFirst {
				if err := store.PutVulnerabilityRecord(ctx, faultRecord(t)); err != nil {
					t.Fatalf("seeding the first write: %v", err)
				}
			}
			abortOn(t, store, tc.op, tc.table)

			err := store.PutVulnerabilityRecord(ctx, faultRecord(t))
			if err == nil {
				t.Fatal("PutVulnerabilityRecord() = nil, want the injected failure reported")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("error = %v, want it to name %q", err, tc.wantMsg)
			}

			// The transaction rolled back. On a first write that means nothing was
			// stored; on a re-write it means the previous state survives whole —
			// including its index rows, which the failed reconciliation had already
			// deleted inside the transaction.
			rec := faultRecord(t)
			_, found, gerr := store.GetVulnerabilityRecord(ctx, rec.Coordinate, rec.PipelineVersion, rec.DatabaseSnapshot)
			if gerr != nil {
				t.Fatalf("reading back after a failed write: %v", gerr)
			}
			if found != tc.seedFirst {
				t.Fatalf("after a failed write: found = %v, want %v — the transaction did not roll back cleanly", found, tc.seedFirst)
			}

			var indexRows int
			if err := store.InternalDB().DB().QueryRowContext(ctx,
				`SELECT COUNT(*) FROM vulnerability_findings_index`).Scan(&indexRows); err != nil {
				t.Fatalf("counting index rows: %v", err)
			}
			wantRows := 0
			if tc.seedFirst {
				wantRows = 2 // the seeded finding plus its alias
			}
			if indexRows != wantRows {
				t.Fatalf("index rows after a failed write = %d, want %d", indexRows, wantRows)
			}
		})
	}
}

// TestPutVulnerabilityRecord_ReportsFirstSeenLookupFailure covers the first
// statement inside the transaction. It runs on the transaction's handle rather
// than the store's own, because the pool holds a single connection — so this
// arm is also the one that would surface a regression back to `s.db.DB()` as an
// error instead of as a hang.
func TestPutVulnerabilityRecord_ReportsFirstSeenLookupFailure(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	if _, err := store.InternalDB().DB().ExecContext(ctx, `DROP TABLE vulnerability_records`); err != nil {
		t.Fatalf("removing the records table: %v", err)
	}

	err := store.PutVulnerabilityRecord(ctx, faultRecord(t))
	if err == nil || !strings.Contains(err.Error(), "querying first_scanned_at") {
		t.Fatalf("PutVulnerabilityRecord() error = %v, want the first-seen lookup failure reported", err)
	}
}

// TestPutVulnerabilityRecord_ReportsTransactionStartFailure covers the arm
// before any statement runs.
func TestPutVulnerabilityRecord_ReportsTransactionStartFailure(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)
	if err := store.InternalDB().Close(); err != nil {
		t.Fatalf("closing the database: %v", err)
	}

	err := store.PutVulnerabilityRecord(ctx, faultRecord(t))
	if err == nil || !strings.Contains(err.Error(), "beginning transaction") {
		t.Fatalf("PutVulnerabilityRecord() error = %v, want the transaction-start failure reported", err)
	}
}

// TestPutVulnerabilityRecord_IndexesReachability covers the reachability arm of
// the index write. The column is what lets a consumer distinguish a reachable
// finding from a merely present one, and nil (never analysed) is a third state
// that must not collapse into "not reachable".
func TestPutVulnerabilityRecord_IndexesReachability(t *testing.T) {
	reachable := &domain.ReachabilityResult{IsReachable: true, Confidence: domain.ConfidenceHigh}
	unreachable := &domain.ReachabilityResult{IsReachable: false, Confidence: domain.ConfidenceHigh}

	for _, tc := range []struct {
		name string
		r    *domain.ReachabilityResult
		want any
	}{
		{"reachable", reachable, int64(1)},
		{"not reachable", unreachable, int64(0)},
		{"never analysed", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			store := newTestStore(t)

			rec := faultRecord(t)
			rec.Findings[0].Reachable = tc.r
			rec = seal(t, rec)
			if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
				t.Fatalf("PutVulnerabilityRecord: %v", err)
			}

			var got any
			if err := store.InternalDB().DB().QueryRowContext(ctx,
				`SELECT is_reachable FROM vulnerability_findings_index WHERE finding_id = 'GO-2024-0001'`).Scan(&got); err != nil {
				t.Fatalf("reading is_reachable: %v", err)
			}
			if got != tc.want {
				t.Fatalf("is_reachable = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// TestPutVulnerabilityRecord_FirstSeenAnchorEdges covers the two arms that
// decide whether a stored anchor stands. Both concern a row that predates the
// anchor or carries an unreadable one, where the wrong answer would silently
// move a first-seen date that is supposed to be immutable.
func TestPutVulnerabilityRecord_FirstSeenAnchorEdges(t *testing.T) {
	// The seeded row is a real, sealed record rather than a placeholder blob.
	// Since the table became a ledger it survives the caller's own append as a
	// second generation, and every read decodes and verifies every generation —
	// so a stub blob would fail the read for the right reason and hide the anchor
	// behaviour this test is about.
	seedRow := func(t *testing.T, store *sqlite.Store, anchor string) domain.VulnerabilityRecord {
		t.Helper()
		rec := faultRecord(t)
		legacy := rec
		legacy.WalkID = "legacy-walk"
		legacy.ScannedAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		legacy, err := domain.VulnerabilityRecordHasher{}.SetContentHash(legacy)
		if err != nil {
			t.Fatalf("sealing legacy row: %v", err)
		}
		blob, err := domain.VulnerabilityRecordHasher{}.Marshal(legacy)
		if err != nil {
			t.Fatalf("marshalling legacy row: %v", err)
		}
		if _, err := store.InternalDB().DB().ExecContext(t.Context(), `
INSERT INTO vulnerability_records (
    module_path, module_version, pipeline_version, snapshot_source, snapshot_version,
    walk_id, overall_status, coverage_status, findings_status, finding_count,
    scanned_at, first_scanned_at, content_hash, serialised
) VALUES (?, ?, ?, ?, ?, 'w', 'Clean', 'Analysed', 'Clean', 0,
          '2020-01-01T00:00:00Z', ?, ?, ?)`,
			rec.Coordinate.Path(), rec.Coordinate.Version(), rec.PipelineVersion,
			rec.DatabaseSnapshot.Source, rec.DatabaseSnapshot.Version, anchor,
			legacy.ContentHash, blob); err != nil {
			t.Fatalf("seeding legacy row: %v", err)
		}
		return rec
	}

	// A pre-anchor legacy row stores an empty anchor. The caller's own value
	// stands as the first insert rather than being overwritten with the zero time.
	t.Run("empty stored anchor lets the caller's stand", func(t *testing.T) {
		ctx := t.Context()
		store := newTestStore(t)
		rec := seedRow(t, store, "")

		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
		got, found, err := store.GetVulnerabilityRecord(ctx, rec.Coordinate, rec.PipelineVersion, rec.DatabaseSnapshot)
		if err != nil || !found {
			t.Fatalf("GetVulnerabilityRecord() = found %v, err %v", found, err)
		}
		if !got.FirstScannedAt.Equal(rec.FirstScannedAt) {
			t.Fatalf("first scanned at = %s, want the caller's %s", got.FirstScannedAt, rec.FirstScannedAt)
		}
	})

	// An unparseable anchor is reported, never silently treated as absent — that
	// would move an immutable date on the strength of a corrupt value.
	t.Run("unparseable stored anchor is reported", func(t *testing.T) {
		ctx := t.Context()
		store := newTestStore(t)
		rec := seedRow(t, store, "not-a-timestamp")

		err := store.PutVulnerabilityRecord(ctx, rec)
		if err == nil || !strings.Contains(err.Error(), "parsing first_scanned_at") {
			t.Fatalf("PutVulnerabilityRecord() error = %v, want the unparseable anchor reported", err)
		}
	})
}

// TestGetDatabaseSnapshot_RefusesADifferentSnapshotThanAsked covers the arm that
// checks the caller's own expectation. Answering a question about one snapshot
// with the bytes of another is the failure the content hash exists to prevent,
// and it is not caught by verifying the blob against the store's own hash —
// those bytes are internally consistent, just not the ones asked for.
func TestGetDatabaseSnapshot_RefusesADifferentSnapshotThanAsked(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	s := snap("govulndb", "v2024-01-01")
	s.ContentHash = ""
	if err := store.PutDatabaseSnapshot(ctx, s, strings.NewReader("the advisories the store holds")); err != nil {
		t.Fatalf("PutDatabaseSnapshot: %v", err)
	}

	asked := s
	asked.ContentHash = domain.HashSnapshotContent([]byte("the advisories the caller expected"))

	_, err := store.GetDatabaseSnapshot(ctx, asked)
	assertSnapshotIntegrity(t, err, "GetDatabaseSnapshot(other snapshot)")
}

// TestGetDatabaseSnapshot_AbsentIsAbsent keeps the distinction the read leg
// draws: a snapshot that is not there is reported as missing, not as an
// integrity failure.
func TestGetDatabaseSnapshot_AbsentIsAbsent(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	_, err := store.GetDatabaseSnapshot(ctx, snap("govulndb", "v2024-01-01"))
	if err == nil || !strings.Contains(err.Error(), "snapshot not found") {
		t.Fatalf("GetDatabaseSnapshot(absent) error = %v, want a not-found report", err)
	}
	// Neither sentinel: absence is not corruption, of either kind.
	if errors.Is(err, ports.ErrVulnIntegrity) || errors.Is(err, ports.ErrSnapshotIntegrity) {
		t.Fatal("an absent snapshot was reported as an integrity failure")
	}
}

// TestPutDatabaseSnapshot_ReportsReadAndWriteFailures covers the two arms either
// side of the hashing step.
func TestPutDatabaseSnapshot_ReportsReadAndWriteFailures(t *testing.T) {
	t.Run("unreadable content", func(t *testing.T) {
		ctx := t.Context()
		store := newTestStore(t)
		err := store.PutDatabaseSnapshot(ctx, snap("govulndb", "v1"), failingReader{})
		if err == nil || !strings.Contains(err.Error(), "reading snapshot content") {
			t.Fatalf("PutDatabaseSnapshot() error = %v, want the read failure reported", err)
		}
	})

	t.Run("insert fails", func(t *testing.T) {
		ctx := t.Context()
		store := newTestStore(t)
		abortOn(t, store, "INSERT", "vulnerability_snapshots")
		// No declared hash: the store seals from the bytes, so the write reaches
		// the insert rather than being refused for a mismatch first.
		s := snap("govulndb", "v1")
		s.ContentHash = ""
		err := store.PutDatabaseSnapshot(ctx, s, strings.NewReader("body"))
		if err == nil || !strings.Contains(err.Error(), "inserting database snapshot") {
			t.Fatalf("PutDatabaseSnapshot() error = %v, want the insert failure reported", err)
		}
	})
}

// failingReader is a content body that cannot be read, standing in for a
// truncated download or a closed network stream.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("stream broke") }

// TestGetLatestDatabaseSnapshot_ReportsAnUnparseableTimestamp covers the parse
// arm: a corrupt retrieved_at is reported rather than returned as the zero time,
// which would present a snapshot as retrieved in year zero and make every
// staleness judgement wrong.
func TestGetLatestDatabaseSnapshot_ReportsAnUnparseableTimestamp(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	if _, err := store.InternalDB().DB().ExecContext(ctx, `
INSERT INTO vulnerability_snapshots (source, version, retrieved_at, content_hash, content)
VALUES ('govulndb', 'v1', 'not-a-timestamp', 'sha256:x', 'body')`); err != nil {
		t.Fatalf("seeding a corrupt timestamp: %v", err)
	}

	_, _, err := store.GetLatestDatabaseSnapshot(ctx)
	if err == nil || !strings.Contains(err.Error(), "parsing snapshot time") {
		t.Fatalf("GetLatestDatabaseSnapshot() error = %v, want the parse failure reported", err)
	}
}

// TestCheckFindingsIndex_UndecodableRecordIsADefect covers the arm where the
// joined record cannot be read at all. Treating that as agreement would be the
// worst available answer: the check would pass precisely where the record's own
// contents are unknown.
func TestCheckFindingsIndex_UndecodableRecordIsADefect(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	if _, err := store.InternalDB().DB().ExecContext(ctx, `
INSERT INTO vulnerability_records (
    module_path, module_version, pipeline_version, snapshot_source, snapshot_version,
    walk_id, overall_status, coverage_status, findings_status, finding_count,
    scanned_at, first_scanned_at, content_hash, serialised
) VALUES ('example.com/mod', 'v1.0.0', 'v1', 'govulndb', 'v1', 'w', 'Clean', 'Analysed', 'Clean', 0,
          '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z', 'h', 'not json at all');

INSERT INTO vulnerability_findings_index (
    finding_id, module_path, module_version, pipeline_version,
    snapshot_source, snapshot_version, is_reachable
) VALUES ('GO-2024-0001', 'example.com/mod', 'v1.0.0', 'v1', 'govulndb', 'v1', NULL),
        ('CVE-2024-0001', 'example.com/mod', 'v1.0.0', 'v1', 'govulndb', 'v1', NULL);`); err != nil {
		t.Fatalf("seeding an undecodable record: %v", err)
	}

	defects, err := store.CheckFindingsIndex(ctx)
	if err != nil {
		t.Fatalf("CheckFindingsIndex: %v", err)
	}
	// Both index rows are reported, and the record is decoded once for the pair.
	if len(defects) != 2 {
		t.Fatalf("CheckFindingsIndex found %d defect(s), want 2: %v", len(defects), defects)
	}
	for _, d := range defects {
		if !strings.Contains(d.String(), "could not be decoded") {
			t.Fatalf("defect reason = %q, want it to name the undecodable record", d.String())
		}
	}
}

// TestCheckFindingsIndex_ReportsQueryFailure covers the sweep's own error arm: a
// consistency check that cannot run must say so, never return "no defects".
func TestCheckFindingsIndex_ReportsQueryFailure(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	if _, err := store.InternalDB().DB().ExecContext(ctx, `DROP TABLE vulnerability_findings_index`); err != nil {
		t.Fatalf("removing the index table: %v", err)
	}

	defects, err := store.CheckFindingsIndex(ctx)
	if err == nil {
		t.Fatalf("CheckFindingsIndex() = %v, nil; want the query failure reported rather than a clean bill", defects)
	}
	if !strings.Contains(err.Error(), "querying findings index for consistency") {
		t.Fatalf("error = %v, want it to name the failed sweep", err)
	}
}
