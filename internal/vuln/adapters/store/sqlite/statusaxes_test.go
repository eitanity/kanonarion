package sqlite_test

import (
	"fmt"
	"io"
	"path/filepath"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// axisRecord builds a sealed record that carries findingID — so it is indexed
// under it — with an explicit collapsed status and scan time. Carrying the
// finding while reporting a coverage failure is the shape the collapsed status
// could not express: the advisory was matched, and whether it applies could not
// be established.
func axisRecord(t *testing.T, findingID string, status domain.VulnerabilityStatus, snapshotVersion string, scannedAt time.Time) domain.VulnerabilityRecord {
	t.Helper()
	return seal(t, domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord("github.com/foo/bar", "v1.0.0"),
		WalkID:           "walk-1",
		OverallStatus:    status,
		DatabaseSnapshot: snap("govulndb", snapshotVersion),
		ScannedAt:        scannedAt,
		FirstScannedAt:   scannedAt,
		PipelineVersion:  "v1",
		Findings: []domain.VulnerabilityFinding{
			{ID: findingID, Summary: "test vuln", AffectedRange: "< v1.1.0"},
		},
	})
}

// TestRecordAxes_SplitFromCollapsedStatus pins the projection both the write
// path and the migration apply. Each of the four collapsed values answers a
// different one of the two questions, which is why reading the collapsed field
// as a findings fact was never sound.
func TestRecordAxes_SplitFromCollapsedStatus(t *testing.T) {
	for _, tc := range []struct {
		status   domain.VulnerabilityStatus
		coverage domain.RecordCoverageStatus
		findings domain.RecordFindingsStatus
	}{
		{domain.StatusClean, domain.CoverageAnalysed, domain.FindingsRecordClean},
		{domain.StatusAffected, domain.CoverageAnalysed, domain.FindingsRecordAffected},
		{domain.StatusUnscannable, domain.CoverageUnscannable, domain.FindingsRecordClean},
		{domain.StatusScanFailed, domain.CoverageFailedScan, domain.FindingsRecordClean},
	} {
		t.Run(string(tc.status), func(t *testing.T) {
			sealed := seal(t, domain.VulnerabilityRecord{
				Ecosystem:        fetchdomain.EcosystemGo,
				Coordinate:       coord("github.com/foo/bar", "v1.0.0"),
				OverallStatus:    tc.status,
				DatabaseSnapshot: snap("govulndb", "v2024-01-01"),
				ScannedAt:        time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				PipelineVersion:  "v1",
			})
			if sealed.CoverageStatus != tc.coverage || sealed.FindingsStatus != tc.findings {
				t.Fatalf("sealing %s produced coverage=%q findings=%q, want %q/%q",
					tc.status, sealed.CoverageStatus, sealed.FindingsStatus, tc.coverage, tc.findings)
			}
			// Reading a pre-split record — axes empty — recovers the same pair.
			legacy := sealed
			legacy.CoverageStatus, legacy.FindingsStatus = "", ""
			if c, f := domain.RecordAxes(legacy); c != tc.coverage || f != tc.findings {
				t.Fatalf("RecordAxes on a pre-split record = %q/%q, want %q/%q", c, f, tc.coverage, tc.findings)
			}
		})
	}
}

// TestRecordAxes_CoverageFailureCanStillCarryAFinding covers the pair the
// collapsed word cannot express: an advisory matched, but coverage failed, so
// whether it applies was never established. On a single status that became
// Clean, which reads as an all-clear. Stated on the axes it collapses to a
// coverage word while the findings axis keeps the finding.
func TestRecordAxes_CoverageFailureCanStillCarryAFinding(t *testing.T) {
	sealed := seal(t, domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord("github.com/foo/bar", "v1.0.0"),
		CoverageStatus:   domain.CoverageFailedScan,
		FindingsStatus:   domain.FindingsRecordAffected,
		ErrorDetail:      "reachability analysis did not complete",
		DatabaseSnapshot: snap("govulndb", "v2024-01-01"),
		ScannedAt:        time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion:  "v1",
		Findings: []domain.VulnerabilityFinding{
			{ID: "GO-2024-0001", Summary: "test vuln", AffectedRange: "< v1.1.0"},
		},
	})

	if sealed.OverallStatus != domain.StatusScanFailed {
		t.Fatalf("collapsed summary = %q, want %q — coverage outranks findings in the summary word",
			sealed.OverallStatus, domain.StatusScanFailed)
	}
	if _, f := domain.RecordAxes(sealed); f != domain.FindingsRecordAffected {
		t.Fatalf("findings axis = %q, want %q — the summary collapse must not retire the finding",
			f, domain.FindingsRecordAffected)
	}
}

// TestListVulnerabilityRecordsByFindingID_CoverageFailureRanksBelowRealAllClear
// is the concrete consequence of the split. Both records report no finding, so
// the findings axis cannot separate them and the old predicate — "status =
// Affected versus everything else" — put them in one bucket, where the newer
// scan won. That answered a security question with a scan that never completed.
// The coverage axis separates them: evidence of absence outranks absence of
// evidence, however recent the latter is.
func TestListVulnerabilityRecordsByFindingID_CoverageFailureRanksBelowRealAllClear(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	analysedClean := axisRecord(t, "GO-2024-0001", domain.StatusClean,
		"v2024-01-01", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	newerScanFailed := axisRecord(t, "GO-2024-0001", domain.StatusScanFailed,
		"v2024-06-01", time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC))

	for _, rec := range []domain.VulnerabilityRecord{analysedClean, newerScanFailed} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
	}

	got, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2024-0001", "")
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordsByFindingID: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1 per coordinate", len(got))
	}
	if got[0].OverallStatus != domain.StatusClean {
		t.Fatalf("ranked verdict = %s (scanned %s), want the analysed all-clear %s — "+
			"a coverage failure was ranked as though it were a clean scan",
			got[0].OverallStatus, got[0].ScannedAt, domain.StatusClean)
	}
	if c, _ := domain.RecordAxes(got[0]); c != domain.CoverageAnalysed {
		t.Fatalf("ranked record coverage = %q, want %q", c, domain.CoverageAnalysed)
	}
}

// TestListVulnerabilityRecordsByFindingID_FindingOutranksNewerCoverageFailure
// keeps the older rule intact: the findings axis is still consulted first, so a
// coverage failure does not retire an established finding either.
func TestListVulnerabilityRecordsByFindingID_FindingOutranksNewerCoverageFailure(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	affected := axisRecord(t, "GO-2024-0001", domain.StatusAffected,
		"v2024-01-01", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	newerUnscannable := axisRecord(t, "GO-2024-0001", domain.StatusUnscannable,
		"v2024-06-01", time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC))

	for _, rec := range []domain.VulnerabilityRecord{affected, newerUnscannable} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
	}

	got, err := store.ListVulnerabilityRecordsByFindingID(ctx, "GO-2024-0001", "")
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordsByFindingID: %v", err)
	}
	if len(got) != 1 || got[0].OverallStatus != domain.StatusAffected {
		t.Fatalf("ranked verdict = %v, want the finding to survive a later coverage failure", got)
	}
}

// TestMigration_BackfillsRecordStatusAxes covers the rows already in every
// store. The ranking query reads the columns, and it deliberately still reads
// older pipeline generations, so a legacy row left with an empty findings_status
// would have dropped out of the finding-bearing bucket entirely — turning a
// stored finding into a silent all-clear, the exact failure the split exists to
// prevent.
func TestMigration_BackfillsRecordStatusAxes(t *testing.T) {
	ctx := t.Context()

	// Migrate to version 10 only — before the axes columns exist.
	var pre []sqlitestore.Migration
	for _, m := range sqlite.Migrations() {
		if m.Version <= 10 {
			pre = append(pre, m)
		}
	}
	path := t.TempDir() + "/mirror.db"
	db, err := sqlitestore.Open(path, pre)
	if err != nil {
		t.Fatalf("opening db at version 10: %v", err)
	}

	if _, err := db.DB().ExecContext(ctx, `
INSERT INTO vulnerability_records (
    module_path, module_version, pipeline_version, snapshot_source,
    snapshot_version, walk_id, overall_status, finding_count,
    scanned_at, first_scanned_at, content_hash, serialised
) VALUES
 ('example.com/a', 'v1.0.0', 'v14', 'govulndb', 'v1', 'w', 'Affected',    1, '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z', 'h1', '{}'),
 ('example.com/b', 'v1.0.0', 'v14', 'govulndb', 'v1', 'w', 'Clean',       0, '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z', 'h2', '{}'),
 ('example.com/c', 'v1.0.0', 'v14', 'govulndb', 'v1', 'w', 'Unscannable', 0, '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z', 'h3', '{}'),
 ('example.com/d', 'v1.0.0', 'v14', 'govulndb', 'v1', 'w', 'ScanFailed',  0, '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z', 'h4', '{}');
`); err != nil {
		t.Fatalf("seeding pre-split records: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing db: %v", err)
	}

	migrated, err := sqlitestore.Open(path, sqlite.Migrations())
	if err != nil {
		t.Fatalf("applying migration 11: %v", err)
	}
	t.Cleanup(func() { _ = migrated.Close() })

	for _, tc := range []struct{ path, coverage, findings string }{
		{"example.com/a", "Analysed", "Affected"},
		{"example.com/b", "Analysed", "Clean"},
		{"example.com/c", "Unscannable", "Clean"},
		{"example.com/d", "Failed", "Clean"},
	} {
		var coverage, findings string
		if err := migrated.DB().QueryRowContext(ctx,
			`SELECT coverage_status, findings_status FROM vulnerability_records WHERE module_path = ?`,
			tc.path).Scan(&coverage, &findings); err != nil {
			t.Fatalf("reading back %s: %v", tc.path, err)
		}
		if coverage != tc.coverage || findings != tc.findings {
			t.Errorf("%s: coverage=%q findings=%q, want %q/%q", tc.path, coverage, findings, tc.coverage, tc.findings)
		}
	}
}

// TestMigration_LeavesPreHashSnapshotsUnsealed pins the withdrawal of the
// in-place sealing migration.
//
// A hash taken at migration time attests only that the blob was unchanged since
// the migration, yet is indistinguishable from one taken at fetch — so it
// reports an integrity guarantee that was never established. A pre-hash
// snapshot must therefore stay unverifiable, which is what it honestly is, and
// still be readable.
func TestMigration_LeavesPreHashSnapshotsUnsealed(t *testing.T) {
	ctx := t.Context()

	var pre []sqlitestore.Migration
	for _, m := range sqlite.Migrations() {
		if m.Version <= 9 {
			pre = append(pre, m)
		}
	}
	path := t.TempDir() + "/mirror.db"
	db, err := sqlitestore.Open(path, pre)
	if err != nil {
		t.Fatalf("opening db at version 9: %v", err)
	}

	const body = "advisory database bytes"
	if _, err := db.DB().ExecContext(ctx, `
INSERT INTO vulnerability_snapshots (source, version, retrieved_at, content_hash, content)
VALUES ('govulndb', 'v2024-01-01', '2024-01-01T00:00:00Z', '', ?)`, []byte(body)); err != nil {
		t.Fatalf("seeding unsealed snapshot: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing db: %v", err)
	}

	migrated, err := sqlitestore.Open(path, sqlite.Migrations())
	if err != nil {
		t.Fatalf("applying the full migration set: %v", err)
	}
	t.Cleanup(func() { _ = migrated.Close() })

	var stored string
	if err := migrated.DB().QueryRowContext(ctx,
		`SELECT content_hash FROM vulnerability_snapshots WHERE source = 'govulndb'`).Scan(&stored); err != nil {
		t.Fatalf("reading back snapshot hash: %v", err)
	}
	if stored != "" {
		t.Fatalf("pre-hash snapshot content hash = %q, want it left empty — "+
			"sealing it at migration time attests bytes nothing ever attested", stored)
	}

	// Unverifiable is not unreadable: the blob still serves a scan.
	store := sqlite.New(migrated)
	rc, err := store.GetDatabaseSnapshot(ctx, domain.DatabaseSnapshot{Source: "govulndb", Version: "v2024-01-01"})
	if err != nil {
		t.Fatalf("GetDatabaseSnapshot on an unsealed legacy snapshot: %v", err)
	}
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading snapshot body: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("closing snapshot reader: %v", err)
	}
	if string(got) != body {
		t.Fatalf("snapshot body = %q, want %q", got, body)
	}
}

// TestMigration_UnsealsSnapshotsTheWithdrawnMigrationSealed covers the store the
// withdrawn migration already ran against: its hashes are cleared, while a
// snapshot fetched afterwards — sealed honestly, against the bytes downloaded —
// keeps its hash.
func TestMigration_UnsealsSnapshotsTheWithdrawnMigrationSealed(t *testing.T) {
	ctx := t.Context()

	var pre []sqlitestore.Migration
	for _, m := range sqlite.Migrations() {
		if m.Version <= 11 {
			pre = append(pre, m)
		}
	}
	path := t.TempDir() + "/mirror.db"
	db, err := sqlitestore.Open(path, pre)
	if err != nil {
		t.Fatalf("opening db at version 11: %v", err)
	}

	// Reproduce the post-migration-10 state: a legacy snapshot retrieved before
	// the migration ran and sealed by it, plus one fetched afterwards.
	if _, err := db.DB().ExecContext(ctx, `
INSERT INTO vulnerability_snapshots (source, version, retrieved_at, content_hash, content) VALUES
 ('govulndb', 'legacy', '2024-01-01T00:00:00Z', ?, ?),
 ('govulndb', 'fresh',  ?,                      ?, ?)`,
		domain.HashSnapshotContent([]byte("legacy")), []byte("legacy"),
		"2099-01-01T00:00:00Z", domain.HashSnapshotContent([]byte("fresh")), []byte("fresh")); err != nil {
		t.Fatalf("seeding sealed snapshots: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing db: %v", err)
	}

	migrated, err := sqlitestore.Open(path, sqlite.Migrations())
	if err != nil {
		t.Fatalf("applying migration 12: %v", err)
	}
	t.Cleanup(func() { _ = migrated.Close() })

	for _, tc := range []struct{ version, want string }{
		{"legacy", ""},
		{"fresh", domain.HashSnapshotContent([]byte("fresh"))},
	} {
		var got string
		if err := migrated.DB().QueryRowContext(ctx,
			`SELECT content_hash FROM vulnerability_snapshots WHERE version = ?`, tc.version).Scan(&got); err != nil {
			t.Fatalf("reading %s: %v", tc.version, err)
		}
		if got != tc.want {
			t.Errorf("%s snapshot content_hash = %q, want %q", tc.version, got, tc.want)
		}
	}
}

// TestMigration13_CorrectsCoverageBackFilledFromTheCollapsedWord is the
// correction applied to rows already in every store.
//
// Migration 11 back-filled the coverage column by projecting the collapsed status
// word, which is not a coverage answer on a record that carries both a coverage
// gap and an advisory match: the word holds the match, so the projection wrote
// 'Analysed' for a module whose source was never read. 74 rows of the
// maintainer's store persist that claim.
//
// The rows are built here the way the old pipeline wrote them — a blob with no
// axes of its own, and columns back-filled by migration 11's own SQL — so the
// test exercises the migration against the shape it exists for rather than
// against a record today's writer would produce.
func TestMigration13_CorrectsCoverageBackFilledFromTheCollapsedWord(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "vuln.db")

	// Stop at 12: the state a store is in before this correction.
	var upTo12 []sqlitestore.Migration
	for _, m := range sqlite.Migrations() {
		if m.Module != "vuln" || m.Version <= 12 {
			upTo12 = append(upTo12, m)
		}
	}
	db, err := sqlitestore.Open(dsn, upTo12)
	if err != nil {
		t.Fatalf("opening at migration 12: %v", err)
	}

	// Four legacy rows: the two mislabelled shapes, and two that must not move.
	for _, r := range []struct {
		version           string
		overall           string
		unscanReason      string
		unscannableReason string
		errorDetail       string
	}{
		{"v1.0.0", "Affected", "version-not-in-toolchain", "metadata-only", ""},
		{"v1.1.0", "Clean", "", "metadata-only: module not fetched (shallow walk)", ""},
		{"v1.2.0", "Affected", "", "", "govulncheck exited 1"},
		{"v1.3.0", "Affected", "", "", ""},
	} {
		blob := fmt.Sprintf(
			`{"ecosystem":"go","overall_status":%q,"unscan_reason":%q,"unscannable_reason":%q,"error_detail":%q}`,
			r.overall, r.unscanReason, r.unscannableReason, r.errorDetail)
		if _, err := db.DB().Exec(`
INSERT INTO vulnerability_records
  (module_path, module_version, pipeline_version, snapshot_source, snapshot_version,
   overall_status, coverage_status, findings_status, finding_count, scanned_at, first_scanned_at, content_hash, serialised)
VALUES ('github.com/foo/bar', ?, 'v14', 'govulndb', 'v2024-01-01', ?, ?, ?, 0,
        '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z', 'hash-'||?, ?)`,
			r.version, r.overall,
			// Exactly what migration 11's CASE produced for this word.
			map[string]string{"Clean": "Analysed", "Affected": "Analysed", "Unscannable": "Unscannable"}[r.overall],
			map[string]string{"Clean": "Clean", "Affected": "Affected", "Unscannable": "Clean"}[r.overall],
			r.version, blob); err != nil {
			t.Fatalf("seeding legacy row %s: %v", r.version, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	// Re-open with the full set, which applies 13 to the rows above.
	db2, err := sqlitestore.Open(dsn, sqlite.Migrations())
	if err != nil {
		t.Fatalf("applying migration 13: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })

	for _, want := range []struct {
		version  string
		coverage string
		overall  string
		why      string
	}{
		{"v1.0.0", "Unscannable", "Affected", "an advisory matched on a module whose source was never analysed"},
		{"v1.1.0", "Unscannable", "Clean", "prose without a reason code is still a coverage gap"},
		{"v1.2.0", "Failed", "Affected", "an error detail alone is a failed look"},
		{"v1.3.0", "Analysed", "Affected", "a genuine analysis must not be touched"},
	} {
		var coverage, overall string
		if err := db2.DB().QueryRow(
			`SELECT coverage_status, overall_status FROM vulnerability_records WHERE module_version = ?`,
			want.version).Scan(&coverage, &overall); err != nil {
			t.Fatalf("reading %s back: %v", want.version, err)
		}
		if coverage != want.coverage {
			t.Errorf("%s: coverage_status = %q, want %q — %s", want.version, coverage, want.coverage, want.why)
		}
		// The summary word is never rewritten by the migration. Deriving it from the
		// corrected coverage would report Unscannable for the first row and retire a
		// finding every summary-reading consumer reports today; and it is inside the
		// blob, which the migration must not contradict.
		if overall != want.overall {
			t.Errorf("%s: overall_status = %q, want %q left as written", want.version, overall, want.overall)
		}
	}

	// The acceptance measurement, run against this store: no row may claim it was
	// analysed while carrying a diagnostic saying otherwise.
	var mislabelled int
	if err := db2.DB().QueryRow(`
SELECT COUNT(*) FROM vulnerability_records
WHERE coverage_status = 'Analysed'
  AND (COALESCE(json_extract(serialised, '$.unscan_reason'), '') != ''
    OR COALESCE(json_extract(serialised, '$.unscannable_reason'), '') != ''
    OR COALESCE(json_extract(serialised, '$.error_detail'), '') != '')`).Scan(&mislabelled); err != nil {
		t.Fatalf("counting mislabelled rows: %v", err)
	}
	if mislabelled != 0 {
		t.Errorf("%d rows still claim Analysed while carrying a coverage diagnostic, want 0", mislabelled)
	}
}
