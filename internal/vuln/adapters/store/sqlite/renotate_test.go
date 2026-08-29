package sqlite_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// notationVersion is the migration that re-notated the bare-hex seals.
const notationVersion = 15

// migrationsBeforeNotation returns the schema the store had when the bare-hex
// rows were written.
//
// It selects by version rather than by position. "Everything but the last"
// silently retargets itself at whatever migration is added next, and the
// failure it produces is a seal mismatch — which reads as a re-notation bug
// rather than as a test that is no longer pointing at the re-notation.
func migrationsBeforeNotation() []sqlitestore.Migration {
	var before []sqlitestore.Migration
	for _, m := range sqlite.Migrations() {
		if m.Version < notationVersion {
			before = append(before, m)
		}
	}
	return before
}

// preNotationStore opens a store at the schema that precedes the re-notation, so
// a test can seed the rows the migration will find.
func preNotationStore(t *testing.T) sqlitestore.DB {
	t.Helper()
	db, err := sqlitestore.Open(":memory:", migrationsBeforeNotation(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening the pre-notation store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// bareSeal is the pre-migration spelling of a seal: the same digest, unlabelled.
func bareSeal(hash string) string { return strings.TrimPrefix(hash, "sha256:") }

// legacyRecord returns a record exactly as the bare-hex build wrote it — the
// blob it stored and the seal it stored beside it — together with the record
// today's build seals, which is what the migration must arrive at.
func legacyRecord(t *testing.T, snapshot domain.DatabaseSnapshot, c coordinate.ModuleCoordinate) (blob []byte, bareHash string, want domain.VulnerabilityRecord) {
	t.Helper()

	want = seal(t, domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       c,
		WalkID:           "walk-1",
		OverallStatus:    domain.StatusClean,
		DatabaseSnapshot: snapshot,
		ScannedAt:        time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		FirstScannedAt:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion:  "v17",
	})

	legacy := want
	legacy.ContentHash = bareSeal(want.ContentHash)
	blob, err := domain.VulnerabilityRecordHasher{}.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshalling the legacy record: %v", err)
	}
	return blob, legacy.ContentHash, want
}

func insertLegacyRecord(t *testing.T, db sqlitestore.DB, rec domain.VulnerabilityRecord, bareHash string, blob []byte) {
	t.Helper()

	if _, err := db.DB().Exec(`
INSERT INTO vulnerability_records (
    module_path, module_version, pipeline_version,
    snapshot_source, snapshot_version, rooting, walk_id,
    overall_status, coverage_status, findings_status,
    finding_count, scanned_at, first_scanned_at, content_hash, serialised
) VALUES (?, ?, ?, ?, ?, '', ?, ?, ?, ?, 0, ?, ?, ?, ?)`,
		rec.Coordinate.Path(), rec.Coordinate.Version(), rec.PipelineVersion,
		rec.DatabaseSnapshot.Source(), rec.DatabaseSnapshot.Version(), rec.WalkID,
		string(rec.OverallStatus), string(rec.CoverageStatus), string(rec.FindingsStatus),
		rec.ScannedAt.UTC().Format(time.RFC3339),
		rec.FirstScannedAt.UTC().Format(time.RFC3339),
		bareHash, blob,
	); err != nil {
		t.Fatalf("seeding a legacy vulnerability record: %v", err)
	}
}

// legacyRun returns a walk scan run as the bare-hex build wrote it, alongside
// the run today's build seals over the re-notated contents. The two seals are
// genuinely different digests, because per_module_results is inside the seal.
func legacyRun(t *testing.T, snapshot domain.DatabaseSnapshot, c coordinate.ModuleCoordinate, recordHash string) (blob []byte, bareHash string, want domain.WalkScanRun) {
	t.Helper()

	base := domain.WalkScanRun{
		ID:               "run-1",
		WalkID:           "walk-1",
		Snapshot:         snapshot,
		OverallStatus:    domain.WalkStatusAllClean,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{c: recordHash},
		StartedAt:        time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		CompletedAt:      time.Date(2026, 7, 1, 0, 1, 0, 0, time.UTC),
		PipelineVersion:  "v17",
	}
	want = sealRun(t, base)

	legacy := base
	legacy.PerModuleResults = map[coordinate.ModuleCoordinate]string{c: bareSeal(recordHash)}
	legacy.ContentHash = ""
	unsealed, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshalling the legacy run for its seal: %v", err)
	}
	sum := sha256.Sum256(unsealed)
	bareHash = hex.EncodeToString(sum[:])

	legacy.ContentHash = bareHash
	blob, err = json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshalling the legacy run: %v", err)
	}
	return blob, bareHash, want
}

func insertLegacyRun(t *testing.T, db sqlitestore.DB, run domain.WalkScanRun, c coordinate.ModuleCoordinate, bareRunHash, bareRecordHash string, blob []byte) {
	t.Helper()

	if _, err := db.DB().Exec(`
INSERT INTO walk_scan_runs (
    id, walk_id, snapshot_source, snapshot_version,
    started_at, completed_at, overall_status,
    coverage_status, findings_status,
    total_modules, analysed_modules, affected_modules,
    unscannable_modules, failed_modules,
    operator, content_hash, serialised
) VALUES (?, ?, ?, ?, ?, ?, ?, '', '', 1, 1, 0, 0, 0, '', ?, ?)`,
		run.ID, run.WalkID, run.Snapshot.Source(), run.Snapshot.Version(),
		run.StartedAt.UTC().Format(time.RFC3339),
		run.CompletedAt.UTC().Format(time.RFC3339),
		string(run.OverallStatus), bareRunHash, blob,
	); err != nil {
		t.Fatalf("seeding a legacy walk scan run: %v", err)
	}

	if _, err := db.DB().Exec(`
INSERT INTO walk_scan_run_modules (
    walk_scan_run_id, module_path, module_version,
    pipeline_version, snapshot_source, snapshot_version, walk_id,
    record_content_hash
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		run.ID, c.Path(), c.Version(), run.PipelineVersion,
		run.Snapshot.Source(), run.Snapshot.Version(), run.WalkID, bareRecordHash,
	); err != nil {
		t.Fatalf("seeding a legacy walk scan run module: %v", err)
	}
}

func scanString(t *testing.T, db sqlitestore.DB, query string, args ...any) string {
	t.Helper()
	var got string
	if err := db.DB().QueryRow(query, args...).Scan(&got); err != nil {
		t.Fatalf("querying %q: %v", query, err)
	}
	return got
}

func scanBlob(t *testing.T, db sqlitestore.DB, query string, args ...any) []byte {
	t.Helper()
	var got []byte
	if err := db.DB().QueryRow(query, args...).Scan(&got); err != nil {
		t.Fatalf("querying %q: %v", query, err)
	}
	return got
}

// TestNotationMigration_ReNotatesEverySeal is the whole migration, seeded as the
// bare-hex build left it and read back the way a reader reads it.
//
// The two shapes are asserted differently on purpose, because they migrate
// differently. A record is a PURE PREFIX: its seal covers its own JSON with
// content_hash blanked, so the digest cannot depend on how that field is spelled
// and the new value must be exactly the label plus the old one. A run is a
// GENUINE RECOMPUTE: per_module_results holds the record hashes, so re-notating
// the records changes the run's sealed content, and the only right answer is the
// seal today's hasher produces over the re-notated run.
func TestNotationMigration_ReNotatesEverySeal(t *testing.T) {
	ctx := t.Context()
	db := preNotationStore(t)

	snapshot := snap("govulndb", "2026-07-01T00:00:00Z")
	c := coord("github.com/foo/bar", "v1.0.0")

	recBlob, bareRecHash, wantRec := legacyRecord(t, snapshot, c)
	insertLegacyRecord(t, db, wantRec, bareRecHash, recBlob)

	runBlob, bareRunHash, wantRun := legacyRun(t, snapshot, c, wantRec.ContentHash)
	insertLegacyRun(t, db, wantRun, c, bareRunHash, bareRecHash, runBlob)

	if err := sqlitestore.Apply(db, sqlite.Migrations()); err != nil {
		t.Fatalf("applying the notation migration: %v", err)
	}

	// The record's column and its blob both carry the label, and the digest
	// underneath is untouched.
	gotRecHash := scanString(t, db, `SELECT content_hash FROM vulnerability_records`)
	if gotRecHash != "sha256:"+bareRecHash {
		t.Errorf("record seal = %q, want %q — a record must re-notate by pure prefix", gotRecHash, "sha256:"+bareRecHash)
	}
	if gotRecHash != wantRec.ContentHash {
		t.Errorf("record seal = %q, but today's hasher seals the same record %q", gotRecHash, wantRec.ContentHash)
	}
	gotRecBlob := scanBlob(t, db, `SELECT serialised FROM vulnerability_records`)
	if _, embedded, err := recordseal.ReplaceTopLevelContentHash(gotRecBlob, ""); err != nil {
		t.Fatalf("reading the migrated record blob: %v", err)
	} else if embedded != gotRecHash {
		t.Errorf("the migrated record blob carries %q while its column carries %q", embedded, gotRecHash)
	}

	// The bytes under the seal did not move. This is the property that makes the
	// record leg a re-spelling rather than a reseal.
	blankedBefore, _, err := recordseal.ReplaceTopLevelContentHash(recBlob, "")
	if err != nil {
		t.Fatalf("blanking the seeded record blob: %v", err)
	}
	blankedAfter, _, err := recordseal.ReplaceTopLevelContentHash(gotRecBlob, "")
	if err != nil {
		t.Fatalf("blanking the migrated record blob: %v", err)
	}
	if string(blankedBefore) != string(blankedAfter) {
		t.Errorf("the migration changed the sealed bytes of the record:\nbefore %s\nafter  %s", blankedBefore, blankedAfter)
	}

	// The membership column names the generation the run scanned, so it moves
	// with the record it names or the run stops resolving to it.
	gotMember := scanString(t, db, `SELECT record_content_hash FROM walk_scan_run_modules`)
	if gotMember != gotRecHash {
		t.Errorf("membership names %q, but the record it scanned is now %q", gotMember, gotRecHash)
	}

	// The run is a recompute: its seal is not its old digest with a label, it is
	// the seal of its re-notated contents.
	gotRunHash := scanString(t, db, `SELECT content_hash FROM walk_scan_runs`)
	if gotRunHash != wantRun.ContentHash {
		t.Errorf("run seal = %q, want %q — the seal today's hasher produces over the re-notated run", gotRunHash, wantRun.ContentHash)
	}
	if gotRunHash == "sha256:"+bareRunHash {
		t.Error("run seal is the old digest with a label; per_module_results is inside the seal, so it must have changed")
	}

	// Read back the way a reader reads: both legs verify their own seal, so a
	// mis-migrated row would surface as an integrity failure rather than as a
	// column that merely looks right.
	store := sqlite.New(db)
	served, found, err := store.GetVulnerabilityRecord(ctx, c, wantRec.PipelineVersion, snapshot)
	if err != nil || !found {
		t.Fatalf("GetVulnerabilityRecord after the migration = found %v, err %v", found, err)
	}
	if served.ContentHash != wantRec.ContentHash {
		t.Errorf("served seal %q, want %q", served.ContentHash, wantRec.ContentHash)
	}
	servedRun, found, err := store.GetWalkScanRun(ctx, wantRun.ID)
	if err != nil || !found {
		t.Fatalf("GetWalkScanRun after the migration = found %v, err %v", found, err)
	}
	if servedRun.ContentHash != wantRun.ContentHash {
		t.Errorf("served run seal %q, want %q", servedRun.ContentHash, wantRun.ContentHash)
	}
	if got := servedRun.PerModuleResults[c]; got != wantRec.ContentHash {
		t.Errorf("the run names record %q, want %q", got, wantRec.ContentHash)
	}
}

// An altered record keeps saying it was altered.
//
// Re-notating cannot repair or conceal a broken row, and that is the point: the
// sealed bytes do not move, so a row that failed its check before fails it after
// with the same digest underneath. The migration re-spells it and changes
// nothing about what it reports.
func TestNotationMigration_AnAlteredRecordStillSaysSo(t *testing.T) {
	ctx := t.Context()
	db := preNotationStore(t)

	snapshot := snap("govulndb", "2026-07-01T00:00:00Z")
	c := coord("github.com/foo/bar", "v1.0.0")

	blob, bareHash, rec := legacyRecord(t, snapshot, c)

	// Alter a byte of the sealed content, leaving the seal claiming the original.
	altered := []byte(strings.Replace(string(blob), `"walk_id":"walk-1"`, `"walk_id":"walk-9"`, 1))
	if string(altered) == string(blob) {
		t.Fatal("the test did not alter the record blob")
	}
	insertLegacyRecord(t, db, rec, bareHash, altered)

	if err := sqlitestore.Apply(db, sqlite.Migrations()); err != nil {
		t.Fatalf("applying the notation migration: %v", err)
	}

	if got := scanString(t, db, `SELECT content_hash FROM vulnerability_records`); got != "sha256:"+bareHash {
		t.Errorf("altered record seal = %q, want %q", got, "sha256:"+bareHash)
	}
	// The alteration is still there and still unaccounted for.
	gotBlob := scanBlob(t, db, `SELECT serialised FROM vulnerability_records`)
	if !strings.Contains(string(gotBlob), `"walk_id":"walk-9"`) {
		t.Error("the migration rewrote an altered record's contents")
	}
	if _, _, err := sqlite.New(db).GetVulnerabilityRecord(ctx, c, rec.PipelineVersion, snapshot); err == nil {
		t.Error("the altered record now passes its integrity check; re-notating must not repair anything")
	}
}

// A row whose column and blob disagree about what the seal is has already
// contradicted itself. Prefixing one side would leave it contradicting itself in
// a new way and hide which side moved, so it is left alone.
func TestNotationMigration_LeavesASelfContradictingRowAlone(t *testing.T) {
	db := preNotationStore(t)

	snapshot := snap("govulndb", "2026-07-01T00:00:00Z")
	c := coord("github.com/foo/bar", "v1.0.0")

	blob, bareHash, rec := legacyRecord(t, snapshot, c)
	const otherHash = "0000000000000000000000000000000000000000000000000000000000000000"
	if otherHash == bareHash {
		t.Fatal("the test's stand-in seal collided with the real one")
	}
	insertLegacyRecord(t, db, rec, otherHash, blob)

	if err := sqlitestore.Apply(db, sqlite.Migrations()); err != nil {
		t.Fatalf("applying the notation migration: %v", err)
	}

	if got := scanString(t, db, `SELECT content_hash FROM vulnerability_records`); got != otherHash {
		t.Errorf("self-contradicting record seal = %q, want it left at %q", got, otherHash)
	}
	if got := scanBlob(t, db, `SELECT serialised FROM vulnerability_records`); string(got) != string(blob) {
		t.Error("the migration rewrote a self-contradicting record's bytes")
	}
}

// A row already carrying the label is left alone, so re-applying the rewrite can
// never double the prefix.
func TestNotationMigration_IsIdempotent(t *testing.T) {
	db := preNotationStore(t)

	snapshot := snap("govulndb", "2026-07-01T00:00:00Z")
	c := coord("github.com/foo/bar", "v1.0.0")

	_, _, rec := legacyRecord(t, snapshot, c)
	blob, err := domain.VulnerabilityRecordHasher{}.Marshal(rec)
	if err != nil {
		t.Fatalf("marshalling the record: %v", err)
	}
	insertLegacyRecord(t, db, rec, rec.ContentHash, blob)

	run := sealRun(t, domain.WalkScanRun{
		ID:               "run-1",
		WalkID:           "walk-1",
		Snapshot:         snapshot,
		OverallStatus:    domain.WalkStatusAllClean,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{c: rec.ContentHash},
		StartedAt:        time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		CompletedAt:      time.Date(2026, 7, 1, 0, 1, 0, 0, time.UTC),
		PipelineVersion:  "v17",
	})
	runBlob, err := domain.WalkScanRunHasher{}.Marshal(run)
	if err != nil {
		t.Fatalf("marshalling the run: %v", err)
	}
	insertLegacyRun(t, db, run, c, run.ContentHash, rec.ContentHash, runBlob)

	if err := sqlitestore.Apply(db, sqlite.Migrations()); err != nil {
		t.Fatalf("applying the notation migration: %v", err)
	}

	if got := scanString(t, db, `SELECT content_hash FROM vulnerability_records`); got != rec.ContentHash {
		t.Errorf("already-labelled record seal = %q, want %q", got, rec.ContentHash)
	}
	if got := scanString(t, db, `SELECT record_content_hash FROM walk_scan_run_modules`); got != rec.ContentHash {
		t.Errorf("already-labelled membership = %q, want %q", got, rec.ContentHash)
	}
	if got := scanString(t, db, `SELECT content_hash FROM walk_scan_runs`); got != run.ContentHash {
		t.Errorf("already-labelled run seal = %q, want %q", got, run.ContentHash)
	}
}
