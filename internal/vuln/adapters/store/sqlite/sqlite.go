package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// Store implements ports.VulnerabilityStore using SQLite.
type Store struct {
	db sqlitestore.DB
}

// querier is the read surface *sql.DB and *sql.Tx have in common, so a helper
// can be called either standalone or inside an open transaction. The pool holds
// one connection, which makes the choice mandatory rather than stylistic: a
// helper that reached for the store's own handle from inside a transaction
// would wait on the connection that transaction is holding.
type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// execQuerier is querier plus the write surface, for a helper that both reads
// the ledger and rewrites a satellite inside the caller's transaction.
type execQuerier interface {
	querier
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// New returns a new Store.
func New(db sqlitestore.DB) *Store {
	return &Store{db: db}
}

// Migrations returns the schema migrations for the vulnerability module.
func Migrations() []sqlitestore.Migration {
	return []sqlitestore.Migration{
		{
			Module:  "vuln",
			Version: 1,
			SQL: `
CREATE TABLE IF NOT EXISTS vulnerability_records (
    module_path        TEXT NOT NULL,
    module_version     TEXT NOT NULL,
    pipeline_version   TEXT NOT NULL,
    snapshot_source    TEXT NOT NULL,
    snapshot_version   TEXT NOT NULL,
    walk_id            TEXT NOT NULL,
    overall_status     TEXT NOT NULL,
    finding_count      INTEGER NOT NULL,
    scanned_at         TEXT NOT NULL,
    content_hash       TEXT NOT NULL,
    serialised         BLOB NOT NULL,
    PRIMARY KEY (module_path, module_version, pipeline_version,
                 snapshot_source, snapshot_version, walk_id)
);

CREATE INDEX IF NOT EXISTS vuln_records_finding_count_idx
  ON vulnerability_records(finding_count);

CREATE INDEX IF NOT EXISTS vuln_records_walk_idx
  ON vulnerability_records(walk_id);

CREATE TABLE IF NOT EXISTS walk_scan_runs (
    id                 TEXT PRIMARY KEY,
    walk_id            TEXT NOT NULL,
    snapshot_source    TEXT NOT NULL,
    snapshot_version   TEXT NOT NULL,
    started_at         TEXT NOT NULL,
    completed_at       TEXT NOT NULL,
    overall_status     TEXT NOT NULL,
    operator           TEXT NOT NULL,
    content_hash       TEXT NOT NULL,
    serialised         BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS walk_scan_runs_walk_idx
  ON walk_scan_runs(walk_id);

CREATE TABLE IF NOT EXISTS vulnerability_snapshots (
    source       TEXT NOT NULL,
    version      TEXT NOT NULL,
    retrieved_at TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    content      BLOB NOT NULL,
    PRIMARY KEY (source, version)
);

CREATE TABLE IF NOT EXISTS vulnerability_findings_index (
    finding_id         TEXT NOT NULL,
    module_path        TEXT NOT NULL,
    module_version     TEXT NOT NULL,
    pipeline_version   TEXT NOT NULL,
    snapshot_source    TEXT NOT NULL,
    snapshot_version   TEXT NOT NULL,
    walk_id            TEXT NOT NULL,
    is_reachable       INTEGER,
    PRIMARY KEY (finding_id, module_path, module_version,
                 pipeline_version, snapshot_source, snapshot_version,
                 walk_id)
);

CREATE INDEX IF NOT EXISTS vuln_findings_finding_idx
  ON vulnerability_findings_index(finding_id);
`,
		},
		{
			Module:  "vuln",
			Version: 2,
			SQL: `
CREATE TABLE IF NOT EXISTS walk_scan_run_modules (
    walk_scan_run_id   TEXT NOT NULL,
    module_path        TEXT NOT NULL,
    module_version     TEXT NOT NULL,
    pipeline_version   TEXT NOT NULL,
    snapshot_source    TEXT NOT NULL,
    snapshot_version   TEXT NOT NULL,
    walk_id            TEXT NOT NULL,
    PRIMARY KEY (walk_scan_run_id, module_path, module_version)
);

CREATE INDEX IF NOT EXISTS walk_scan_run_modules_run_idx
  ON walk_scan_run_modules(walk_scan_run_id);
`,
		},
		{
			Module:  "vuln",
			Version: 3,
			SQL: `
CREATE TABLE IF NOT EXISTS vulnerability_findings_index (
    finding_id         TEXT NOT NULL,
    module_path        TEXT NOT NULL,
    module_version     TEXT NOT NULL,
    pipeline_version   TEXT NOT NULL,
    snapshot_source    TEXT NOT NULL,
    snapshot_version   TEXT NOT NULL,
    walk_id            TEXT NOT NULL,
    is_reachable       INTEGER,
    PRIMARY KEY (finding_id, module_path, module_version,
                 pipeline_version, snapshot_source, snapshot_version,
                 walk_id)
);

CREATE INDEX IF NOT EXISTS vuln_findings_finding_idx
  ON vulnerability_findings_index(finding_id);
`,
		},
		{
			Module:  "vuln",
			Version: 4,
			// Backfill walk_scan_run_modules from existing scan run JSON blobs.
			// per_module_results keys are serialised as "path@version" by MarshalText.
			SQL: `
INSERT OR IGNORE INTO walk_scan_run_modules (
    walk_scan_run_id, module_path, module_version,
    pipeline_version, snapshot_source, snapshot_version, walk_id
)
SELECT
    wsr.id,
    substr(pm.key, 1, instr(pm.key, '@') - 1),
    substr(pm.key, instr(pm.key, '@') + 1),
    json_extract(wsr.serialised, '$.pipeline_version'),
    json_extract(wsr.serialised, '$.snapshot.source'),
    json_extract(wsr.serialised, '$.snapshot.version'),
    wsr.walk_id
FROM walk_scan_runs wsr,
     json_each(json_extract(wsr.serialised, '$.per_module_results')) pm;
`,
		},
		{
			Module:  "vuln",
			Version: 5,
			// Remove walk_id from the PRIMARY KEY of vulnerability_records and
			// vulnerability_findings_index so scans are reused across different walks
			// for the same (module, snapshot) pair. walk_id becomes a provenance
			// column on vulnerability_records (last walk that triggered the scan).
			SQL: `
CREATE TABLE vulnerability_records_v5 (
    module_path        TEXT NOT NULL,
    module_version     TEXT NOT NULL,
    pipeline_version   TEXT NOT NULL,
    snapshot_source    TEXT NOT NULL,
    snapshot_version   TEXT NOT NULL,
    walk_id            TEXT,
    overall_status     TEXT NOT NULL,
    finding_count      INTEGER NOT NULL,
    scanned_at         TEXT NOT NULL,
    content_hash       TEXT NOT NULL,
    serialised         BLOB NOT NULL,
    PRIMARY KEY (module_path, module_version, pipeline_version,
                 snapshot_source, snapshot_version)
);

INSERT INTO vulnerability_records_v5
SELECT r.module_path, r.module_version, r.pipeline_version,
       r.snapshot_source, r.snapshot_version, r.walk_id,
       r.overall_status, r.finding_count, r.scanned_at,
       r.content_hash, r.serialised
FROM vulnerability_records r
WHERE NOT EXISTS (
    SELECT 1 FROM vulnerability_records r2
    WHERE r2.module_path      = r.module_path
      AND r2.module_version   = r.module_version
      AND r2.pipeline_version = r.pipeline_version
      AND r2.snapshot_source  = r.snapshot_source
      AND r2.snapshot_version = r.snapshot_version
      AND r2.scanned_at > r.scanned_at
);

DROP TABLE vulnerability_records;
ALTER TABLE vulnerability_records_v5 RENAME TO vulnerability_records;

CREATE INDEX IF NOT EXISTS vuln_records_finding_count_idx
  ON vulnerability_records(finding_count);
CREATE INDEX IF NOT EXISTS vuln_records_walk_idx
  ON vulnerability_records(walk_id);

CREATE TABLE vulnerability_findings_index_v5 (
    finding_id         TEXT NOT NULL,
    module_path        TEXT NOT NULL,
    module_version     TEXT NOT NULL,
    pipeline_version   TEXT NOT NULL,
    snapshot_source    TEXT NOT NULL,
    snapshot_version   TEXT NOT NULL,
    is_reachable       INTEGER,
    PRIMARY KEY (finding_id, module_path, module_version,
                 pipeline_version, snapshot_source, snapshot_version)
);

INSERT OR IGNORE INTO vulnerability_findings_index_v5
SELECT finding_id, module_path, module_version, pipeline_version,
       snapshot_source, snapshot_version, is_reachable
FROM vulnerability_findings_index;

DROP TABLE vulnerability_findings_index;
ALTER TABLE vulnerability_findings_index_v5 RENAME TO vulnerability_findings_index;

CREATE INDEX IF NOT EXISTS vuln_findings_finding_idx
  ON vulnerability_findings_index(finding_id);
`,
		},
		{
			Module:  "vuln",
			Version: 6,
			// The ecosystem field joined the canonical hash, so every pre-existing
			// vulnerability record carries a stale hash and a blob with no
			// ecosystem field — unreadable under the new schema. Purge the legacy
			// records and the walk scan runs that index them; both are
			// regenerable by re-scanning.
			SQL: `
DELETE FROM vulnerability_records;
DELETE FROM vulnerability_findings_index;
DELETE FROM walk_scan_runs;
DELETE FROM walk_scan_run_modules;
`,
		},
		{
			Module:  "vuln",
			Version: 7,
			// first_scanned_at is an immutable first-seen anchor: set on the first
			// insert for a (module, version, pipeline, snapshot) and never moved
			// forward on reuse/re-attribution, in contrast to scanned_at which
			// follows the run that last validated the verdict. Backfill existing
			// rows from scanned_at — the best available anchor for a record whose
			// true first-seen time predates this column.
			SQL: `
ALTER TABLE vulnerability_records ADD COLUMN first_scanned_at TEXT NOT NULL DEFAULT '';
UPDATE vulnerability_records SET first_scanned_at = scanned_at WHERE first_scanned_at = '';
`,
		},
		{
			Module:  "vuln",
			Version: 8,
			// A WalkScanRun now carries two independent verdict axes — coverage and
			// findings — plus the module counts they derive from, instead of the
			// single collapsed overall_status. Persist them as columns for
			// queryability alongside the existing overall_status, and purge the
			// pre-split runs: their serialised blobs have neither axis, so a
			// consumer that reads FindingsStatus off a legacy run silently loses the
			// finding — the same absence-as-answer defect this change removes. The
			// runs are regenerable by re-scanning (the PipelineVersion bump to v14
			// re-scans every walk in any case), so purging rather than back-filling
			// keeps the store free of collapsed-shape rows a new reader could
			// misread. walk_scan_run_modules indexes those runs and is purged with
			// them.
			SQL: `
ALTER TABLE walk_scan_runs ADD COLUMN coverage_status TEXT NOT NULL DEFAULT '';
ALTER TABLE walk_scan_runs ADD COLUMN findings_status TEXT NOT NULL DEFAULT '';
ALTER TABLE walk_scan_runs ADD COLUMN total_modules INTEGER NOT NULL DEFAULT 0;
ALTER TABLE walk_scan_runs ADD COLUMN analysed_modules INTEGER NOT NULL DEFAULT 0;
ALTER TABLE walk_scan_runs ADD COLUMN affected_modules INTEGER NOT NULL DEFAULT 0;
ALTER TABLE walk_scan_runs ADD COLUMN unscannable_modules INTEGER NOT NULL DEFAULT 0;
ALTER TABLE walk_scan_runs ADD COLUMN failed_modules INTEGER NOT NULL DEFAULT 0;

DELETE FROM walk_scan_runs;
DELETE FROM walk_scan_run_modules;
`,
		},
		{
			Module:  "vuln",
			Version: 9,
			// Both legs of this store now verify a record's content hash, so a row
			// carrying an empty one is a row no read can return. Such rows exist:
			// the local-replace and worker-failure paths persisted records without
			// hashing them at all, because nothing checked. They are Unscannable
			// and ScanFailed verdicts with no findings, regenerable by re-scanning,
			// so they are deleted rather than back-filled — computing a hash for
			// them here would seal bytes this migration never read as evidence.
			//
			// This must land before the read-leg check goes live, or the first read
			// of such a row starts failing. Their index entries go with them (an
			// Unscannable record indexes no finding, so this is belt and braces).
			// Their walk_scan_run_modules membership is deliberately left alone: a
			// run that named a module it can no longer produce a record for is
			// surfaced by the scan-show read as a verdict with nothing backing it,
			// which is the honest report of what the deletion did.
			SQL: `
DELETE FROM vulnerability_findings_index
WHERE EXISTS (
    SELECT 1 FROM vulnerability_records r
    WHERE r.content_hash = ''
      AND r.module_path      = vulnerability_findings_index.module_path
      AND r.module_version   = vulnerability_findings_index.module_version
      AND r.pipeline_version = vulnerability_findings_index.pipeline_version
      AND r.snapshot_source  = vulnerability_findings_index.snapshot_source
      AND r.snapshot_version = vulnerability_findings_index.snapshot_version
);

DELETE FROM vulnerability_records WHERE content_hash = '';
`,
		},
		{
			Module:  "vuln",
			Version: 10,
			// WITHDRAWN. This migration used to hash every stored snapshot blob in
			// place, to give the pre-existing rows the content hash they were
			// written without.
			//
			// That sealed the wrong claim. A snapshot's content hash answers "are
			// these the bytes we fetched"; hashing at migration time answers "are
			// these the bytes we held when the migration ran". A blob altered before
			// that moment would have been blessed by the migration and verified
			// cleanly ever after, and the resulting seal is indistinguishable from
			// an honest one — so the check would report integrity it never
			// established.
			//
			// The version number is retained and made a no-op rather than removed,
			// because schema_migrations is keyed on (module, version) and a store
			// that already applied it must not renumber. Migration 12 unseals the
			// rows this one sealed on stores where it ran.
			//
			// A pre-hash snapshot therefore stays unverifiable, which is what it
			// honestly is: the read leg tolerates an empty hash and reports such a
			// blob as unverified rather than as verified. Nothing is lost that these
			// rows ever had, and they age out as fresh snapshots are fetched.
			SQL: ``,
		},
		{
			Module:  "vuln",
			Version: 11,
			// A VulnerabilityRecord now carries the same two independent verdict
			// axes a WalkScanRun does — coverage (was this module analysed?) and
			// findings (did the analysis report anything?) — instead of only the
			// single collapsed overall_status, which mixed answers to both. Persist
			// them as columns so the ranking query can ask a findings question
			// without treating "we could not look" as "we looked and it was clean".
			//
			// The back-fill is exact, not a guess: the projection from the collapsed
			// status onto each axis is total and lossless (Clean and Affected are
			// analysed; Unscannable and ScanFailed are the two coverage failures,
			// neither of which reports a finding). It is the same mapping the write
			// path applies, expressed in SQL.
			//
			// The records themselves are kept. Unlike migration 8's walk_scan_runs
			// purge — where a legacy blob had no axis at all and a reader would
			// silently lose a finding — a pre-split record's axes are recoverable
			// from what it already stores, and RecordAxes recovers them on read. The
			// PipelineVersion bump means new scans write the new shape; deleting
			// thousands of still-readable verdicts to reach the same place would
			// destroy evidence rather than correct it.
			SQL: `
ALTER TABLE vulnerability_records ADD COLUMN coverage_status TEXT NOT NULL DEFAULT '';
ALTER TABLE vulnerability_records ADD COLUMN findings_status TEXT NOT NULL DEFAULT '';

UPDATE vulnerability_records SET
    coverage_status = CASE overall_status
        WHEN 'Clean'       THEN 'Analysed'
        WHEN 'Affected'    THEN 'Analysed'
        WHEN 'Unscannable' THEN 'Unscannable'
        ELSE 'Failed'
    END,
    findings_status = CASE overall_status
        WHEN 'Affected' THEN 'Affected'
        ELSE 'Clean'
    END;

CREATE INDEX IF NOT EXISTS vuln_records_findings_status_idx
  ON vulnerability_records(findings_status);
`,
		},
		{
			Module:  "vuln",
			Version: 12,
			// Unseal the snapshots migration 10 sealed, on stores where it ran
			// before it was withdrawn (see the note there). Such a hash attests
			// only that the blob was unchanged since the migration, while being
			// indistinguishable from one taken at fetch — so it reports an
			// integrity guarantee that was never established, which is worse than
			// reporting none.
			//
			// The rows to clear are exactly those retrieved BEFORE migration 10 ran:
			// a snapshot fetched afterwards was sealed by the fetch path against the
			// bytes it downloaded, and that hash is honest and must survive. Both
			// timestamps are RFC3339 in UTC, so the string comparison is
			// chronological.
			//
			// When migration 10 has no recorded applied_at — impossible in practice,
			// since it is applied before this one — the subquery is NULL, the
			// predicate is false and nothing is touched. Failing closed is right: the
			// alternative would clear honestly-sealed rows.
			SQL: `
UPDATE vulnerability_snapshots
SET content_hash = ''
WHERE content_hash != ''
  AND retrieved_at < (
    SELECT applied_at FROM schema_migrations
    WHERE module = 'vuln' AND version = 10
  );
`,
		},
		{
			Module:  "vuln",
			Version: 13,
			// Correct the coverage axis migration 11 back-filled from the collapsed
			// status word.
			//
			// That back-fill was exact for the projection it applied, but the word it
			// projected from is not always a coverage answer. A writer that has both a
			// coverage gap and a matching advisory can put only one of them in the
			// single word, and it puts the finding there: the metadata-only fallback
			// records Affected and leaves the gap in unscan_reason. Migration 11 read
			// Affected and wrote 'Analysed', so 74 rows persist a claim that a module
			// was analysed when only its coordinate was ever matched — the exact
			// over-claim the axis exists to prevent.
			//
			// The diagnostics on the record are the evidence the word discarded, and
			// they are read here in the same precedence the domain applies
			// (DetermineRecordCoverage): a named reason means Unscannable, an error
			// detail alone means Failed — a look that went wrong rather than a module
			// that cannot be looked at.
			//
			// Three guards keep it to rows that are genuinely wrong. Only rows whose
			// blob states no coverage_status of its own are touched, so a record that
			// asserted its axis at seal time keeps the value its content hash covers;
			// only rows currently claiming 'Analysed'; and only rows that actually
			// carry a diagnostic to re-derive from.
			//
			// No PipelineVersion bump: coverage_status is absent from the blob of every
			// row this touches (the field is omitempty and these predate the split),
			// so no stored content hash covers the value being corrected and no record
			// stops verifying.
			SQL: `
UPDATE vulnerability_records
SET coverage_status = CASE
        WHEN COALESCE(json_extract(serialised, '$.unscan_reason'), '') != ''
          OR COALESCE(json_extract(serialised, '$.unscannable_reason'), '') != ''
        THEN 'Unscannable'
        ELSE 'Failed'
    END
WHERE json_extract(serialised, '$.coverage_status') IS NULL
  AND coverage_status = 'Analysed'
  AND (COALESCE(json_extract(serialised, '$.unscan_reason'), '') != ''
    OR COALESCE(json_extract(serialised, '$.unscannable_reason'), '') != ''
    OR COALESCE(json_extract(serialised, '$.error_detail'), '') != '');
`,
		},
		{
			Module:  "vuln",
			Version: 14,
			// The ledger, plus the identity axis the old key discarded.
			//
			// The key was (module, version, pipeline, snapshot). Two things follow
			// from that, and both are defects rather than economies.
			//
			// First, every re-scan UPDATEd its predecessor, so the store could not
			// say what it previously held. A vulnerability finding legitimately
			// changes for one artefact — a new advisory lands, an advisory is
			// retracted, a reachability finding is corrected by a better call graph
			// — and the overwrite destroyed the earlier finding each time, which is
			// the one fact an audit asks about by date.
			//
			// Second, and worse, the key had no place for the ANALYSIS FRAME. A
			// target-rooted scan and an isolated scan of the same coordinate under
			// the same snapshot are two answers to two different questions, and they
			// overwrote each other: whichever ran last survived, and nothing recorded
			// which question the survivor answered. Coordinate-keyed walks scan
			// target-rooted while `kanonarion vuln <module>` scans in isolation, so
			// both kinds are written in a working store today.
			//
			// The new key adds the time of measurement and the record's own content
			// hash, so every scan that passes is its own row. rooting is a COLUMN and
			// not a key column, for the same reason the licence ledger left the
			// artefact identity out of its key: the frame is inside the hashed shape,
			// so two records stating different frames necessarily carry different
			// content hashes and the key already separates them. Putting it in the
			// key would additionally split every pre-existing row — all of which
			// state no frame — into a partition of its own, so the first re-scan of a
			// module would land in a group its own history could not be reconciled
			// with. The column exists so a reader can filter and count frames without
			// decoding 9,276 blobs.
			//
			// walk_id stays a provenance column, and this conversion is what finally
			// makes it honest. It used to be re-stamped in place on every cache
			// reuse, so it named the last walk to touch the row rather than the walk
			// the measurement was made in; a row is now immutable, so it names the
			// walk that produced it. Membership of later runs lives in
			// walk_scan_run_modules, which is where it always belonged.
			//
			// ON CONFLICT DO NOTHING on the write covers the one remaining collision:
			// the byte-identical record written twice. That is one measurement, not
			// two, so dropping it discards no evidence — and it must not be an error,
			// or a retried write would fail a run that had already succeeded.
			//
			// Existing rows carry in as the first generation with no purge. No
			// content hash is touched and no PipelineVersion is bumped: the rooting
			// field is omitempty and absent from every stored blob, so the canonical
			// shape of every existing record is unchanged.
			//
			// The satellites get the same treatment, because both reference a record
			// by the key that is changing:
			//
			//   - vulnerability_findings_index gains rooting in its key. Without it,
			//     writing an isolated record would clear the index rows a
			//     target-rooted record put there — the reconciliation added to keep a
			//     later all-clear from leaving a retracted finding behind would start
			//     retracting the OTHER frame's live findings instead.
			//   - walk_scan_run_modules gains record_content_hash, so a run names the
			//     exact generation it scanned rather than a coordinate that now
			//     resolves to several. Legacy rows carry the empty string and are
			//     resolved by composition, which is the honest reading of a run that
			//     recorded only a coordinate.
			SQL: `
CREATE TABLE vulnerability_records_ledger (
    module_path        TEXT NOT NULL,
    module_version     TEXT NOT NULL,
    pipeline_version   TEXT NOT NULL,
    snapshot_source    TEXT NOT NULL,
    snapshot_version   TEXT NOT NULL,
    rooting            TEXT NOT NULL DEFAULT '',
    walk_id            TEXT,
    overall_status     TEXT NOT NULL,
    coverage_status    TEXT NOT NULL DEFAULT '',
    findings_status    TEXT NOT NULL DEFAULT '',
    finding_count      INTEGER NOT NULL,
    scanned_at         TEXT NOT NULL,
    first_scanned_at   TEXT NOT NULL DEFAULT '',
    content_hash       TEXT NOT NULL,
    serialised         BLOB NOT NULL,
    PRIMARY KEY (module_path, module_version, pipeline_version,
                 snapshot_source, snapshot_version, scanned_at, content_hash)
);

INSERT INTO vulnerability_records_ledger (
    module_path, module_version, pipeline_version,
    snapshot_source, snapshot_version, rooting, walk_id,
    overall_status, coverage_status, findings_status,
    finding_count, scanned_at, first_scanned_at, content_hash, serialised
)
SELECT
    module_path, module_version, pipeline_version,
    snapshot_source, snapshot_version,
    COALESCE(json_extract(serialised, '$.rooting'), ''), walk_id,
    overall_status, coverage_status, findings_status,
    finding_count, scanned_at, first_scanned_at, content_hash, serialised
FROM vulnerability_records;

DROP TABLE vulnerability_records;
ALTER TABLE vulnerability_records_ledger RENAME TO vulnerability_records;

CREATE INDEX IF NOT EXISTS vuln_records_finding_count_idx
  ON vulnerability_records(finding_count);
CREATE INDEX IF NOT EXISTS vuln_records_walk_idx
  ON vulnerability_records(walk_id);
CREATE INDEX IF NOT EXISTS vuln_records_findings_status_idx
  ON vulnerability_records(findings_status);
CREATE INDEX IF NOT EXISTS vuln_records_rooting_idx
  ON vulnerability_records(rooting);
CREATE INDEX IF NOT EXISTS vuln_records_generation_idx
  ON vulnerability_records(module_path, module_version, pipeline_version,
                           snapshot_source, snapshot_version);

CREATE TABLE vulnerability_findings_index_v14 (
    finding_id         TEXT NOT NULL,
    module_path        TEXT NOT NULL,
    module_version     TEXT NOT NULL,
    pipeline_version   TEXT NOT NULL,
    snapshot_source    TEXT NOT NULL,
    snapshot_version   TEXT NOT NULL,
    rooting            TEXT NOT NULL DEFAULT '',
    is_reachable       INTEGER,
    PRIMARY KEY (finding_id, module_path, module_version,
                 pipeline_version, snapshot_source, snapshot_version, rooting)
);

INSERT OR IGNORE INTO vulnerability_findings_index_v14 (
    finding_id, module_path, module_version, pipeline_version,
    snapshot_source, snapshot_version, rooting, is_reachable
)
SELECT finding_id, module_path, module_version, pipeline_version,
       snapshot_source, snapshot_version, '', is_reachable
FROM vulnerability_findings_index;

DROP TABLE vulnerability_findings_index;
ALTER TABLE vulnerability_findings_index_v14 RENAME TO vulnerability_findings_index;

CREATE INDEX IF NOT EXISTS vuln_findings_finding_idx
  ON vulnerability_findings_index(finding_id);

ALTER TABLE walk_scan_run_modules ADD COLUMN record_content_hash TEXT NOT NULL DEFAULT '';
`,
		},
		{
			Module:  "vuln",
			Version: 15,
			// Re-notate every stored vulnerability seal from bare hex to the
			// labelled form the other seven record domains write.
			//
			// This domain sealed bare hex for one reason, stated in hasher.go and
			// in the snapshot hasher's own comment: the rows already written. It
			// was never a design position, and it cost a real answer — the shared
			// verifier compared only against the labelled form, so a vulnerability
			// record could never be classified and a drifted walk scan run was
			// reported in the wording reserved for altered bytes. A record also
			// carried both rules at once: its own seal was bare while the database
			// snapshot hash inside it is labelled, and the snapshot constructor
			// REFUSES a bare one.
			//
			// The whole rewrite lives in the Go step and not in SQL, because its
			// correctness is the ORDER and the proof, neither of which SQL can
			// express here: records re-notate by pure prefix and each rewrite is
			// checked against that property, the membership column follows the
			// records it names, and only then are the run seals recomputed over
			// contents that have genuinely changed. See renotateVulnSeals.
			//
			// No purge and no PipelineVersion bump: this is the same measurement
			// from the same pipeline, spelled the way the rest of the project
			// spells it.
			Fn: renotateVulnSeals,
		},
		{
			Module:  "vuln",
			Version: 16,
			// Drop is_reachable from the findings index.
			//
			// The column was written on every indexed finding and preserved by
			// both table rebuilds this adapter has done, and no SELECT has ever
			// projected it, filtered on it or ordered by it. The index exists so
			// vuln-by-id can name the affected modules without decoding every
			// record; reachability was never part of that question, and the
			// record remains the authority on it.
			//
			// It is dropped rather than corrected because a bool is the wrong
			// shape for what reachability now means: the domain carries three
			// states — reachable, not reachable, and not determined — and the
			// stored rows cannot express the third. Rows written by superseded
			// generations therefore assert a claim this generation would not
			// make, with nothing on the row saying so. A column no reader has
			// ever consulted has never taught a reader that it must filter on
			// pipeline_version first, so the first cross-store query to reach
			// for it would inherit that claim silently. Re-adding a
			// three-valued column when such a query actually exists costs less
			// than carrying a wrong one until then.
			//
			// No purge and no PipelineVersion bump: the index is derived from
			// the records, not a fact of its own, and every record's own
			// reachability field is untouched.
			SQL: `
ALTER TABLE vulnerability_findings_index DROP COLUMN is_reachable;
`,
		},
	}
}

// PutVulnerabilityRecord appends a scan to the ledger.
//
// It never updates a record. The key carries the time of measurement and the
// record's own content hash, so two distinct scans are always two rows, and the
// only collision left is the same record written twice — which the conflict
// clause makes a no-op, because that is one measurement rather than two.
//
// This is the property the conversion turns on. A vulnerability finding
// legitimately changes for one artefact: a new advisory lands, an advisory is
// retracted, a better call graph corrects a reachability finding. An overwriting
// store destroyed the earlier finding every time, and it also destroyed the
// other ANALYSIS FRAME's answer — an isolated scan and a target-rooted scan of
// one coordinate under one snapshot shared a row, so whichever ran last silently
// answered for both questions.
//
// first_scanned_at is an immutable first-seen anchor: the store, not the caller,
// owns its persistence so the guarantee holds across every write path. When the
// ledger already holds a generation for the (module, version, pipeline,
// snapshot) tuple, the earliest anchor it carries is preserved in both the
// column and the serialised blob, regardless of what the caller set.
//
// The record row and its findings-index rows are written in one transaction, and
// the index is reconciled rather than appended to: every index row for the
// record's coordinate, snapshot AND FRAME is deleted and re-derived from the
// composed record of that frame. All three properties are load-bearing.
//
// Appending to the index alone let a re-scan that returned *fewer* findings than
// its predecessor — the advisory stopped applying, the reachability finding
// changed, the scan came back clean — leave the earlier scan's rows behind,
// describing a record that no longer supports them. vuln-by-id resolves through
// this index, so such a row is a false positive on a security question,
// manufactured by the store rather than by the scanner, and invisible to a
// content-hash check because each record is internally valid.
//
// Scoping the reconciliation to the frame is what keeps that fix from becoming
// its own defect once records are appended: without it, writing an isolated
// all-clear would retract the live findings a target-rooted scan had indexed.
//
// The re-derivation reads the composed record rather than the record just
// written, because an append is not necessarily the newest or the best-founded
// generation — a re-scan under an older snapshot, or one backed by a weaker call
// graph, must not be able to retract the index rows of the record a read
// actually serves.
//
// Separate statements on the shared handle let a failure between the record
// write and the index write leave the two permanently disagreeing even with no
// re-scan at all. One transaction is what makes the reconciliation atomic with
// the verdict it describes.
func (s *Store) PutVulnerabilityRecord(ctx context.Context, record domain.VulnerabilityRecord) error {
	// A record whose coordinate is the zero value would key a row on the empty
	// path at the empty version, which every later read treats as a genuine
	// measurement of a module that does not exist.
	if record.Coordinate.IsZero() {
		return coordinate.ErrZeroCoordinate
	}
	// A record whose snapshot is the zero value would key a row on the empty
	// database at the empty generation. That is worse than the empty coordinate:
	// the ledger composes on (coordinate, pipeline version, snapshot), so such a
	// row joins the group holding every other record that also named no snapshot,
	// and a read composes them as one measurement against one advisory database.
	if record.DatabaseSnapshot.IsZero() {
		return fmt.Errorf("putting the vulnerability record for %s: %w", record.Coordinate, domain.ErrZeroSnapshot)
	}
	// A record whose hash does not describe its contents is refused before it
	// reaches the table: the hash is what every later read checks the record
	// against, so storing one that is already wrong stores a row that can only
	// ever be read as a tamper. It also catches the caller that forgot to seal —
	// an empty hash never describes anything.
	//
	// FirstScannedAt is outside the hash, so the anchor substitution below does
	// not disturb this verdict.
	var h domain.VulnerabilityRecordHasher
	if verr := h.VerifyContentHash(record); verr != nil {
		return fmt.Errorf("%w: verifying %s before put: %w", ports.ErrVulnIntegrity, record.Coordinate, verr)
	}
	// The pool is capped at a single connection, so every statement below —
	// including the first-seen lookup — must run on the transaction's handle. A
	// query issued against s.db.DB() while this transaction is open would wait
	// for a connection the transaction is holding, and deadlock.
	tx, err := s.db.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if existing, ok, ferr := s.firstScannedAt(ctx, tx, record); ferr != nil {
		return ferr
	} else if ok {
		record.FirstScannedAt = existing
	}

	serialised, err := h.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshalling vulnerability record: %w", err)
	}

	const q = `
INSERT INTO vulnerability_records (
    module_path, module_version, pipeline_version,
    snapshot_source, snapshot_version, rooting, walk_id,
    overall_status, coverage_status, findings_status,
    finding_count, scanned_at, first_scanned_at,
    content_hash, serialised
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (module_path, module_version, pipeline_version,
             snapshot_source, snapshot_version, scanned_at, content_hash)
DO NOTHING`

	// The columns come from RecordAxes rather than from the fields directly, so a
	// record that reached here without the seal step's derivation still indexes
	// under a real axis instead of the empty string.
	coverage, findings := domain.RecordAxes(record)
	rooting := domain.RecordRooting(record)

	if _, err = tx.ExecContext(ctx, q,
		record.Coordinate.Path(), record.Coordinate.Version(), record.PipelineVersion,
		record.DatabaseSnapshot.Source(), record.DatabaseSnapshot.Version(),
		string(rooting), record.WalkID,
		string(record.OverallStatus), string(coverage), string(findings), len(record.Findings),
		record.ScannedAt.UTC().Format(time.RFC3339),
		record.FirstScannedAt.UTC().Format(time.RFC3339),
		record.ContentHash, serialised,
	); err != nil {
		return fmt.Errorf("inserting vulnerability record: %w", err)
	}

	if err = s.reconcileFindingsIndex(ctx, tx, record, rooting); err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("committing vulnerability record: %w", err)
	}
	return nil
}

// reconcileFindingsIndex rewrites the findings index for one coordinate,
// snapshot and analysis frame so it describes the record a read of that frame
// now serves.
//
// It composes rather than indexing the record just written. An append is not
// necessarily the best-founded generation the ledger holds — a re-scan under an
// older snapshot, or one backed by a weaker call graph, is still a legitimate
// append — and indexing it would let such a scan retract the index rows of the
// record a read actually serves. Composing here keeps the index and the served
// record the same statement.
//
// Everything runs on the caller's transaction. The pool holds one connection, so
// a read issued against the store's own handle would wait on the transaction
// that has already written the row it needs to see.
func (s *Store) reconcileFindingsIndex(
	ctx context.Context,
	tx execQuerier,
	record domain.VulnerabilityRecord,
	rooting domain.Rooting,
) error {
	generations, err := s.listGenerations(ctx, tx,
		record.Coordinate.Path(), record.Coordinate.Version(), record.PipelineVersion,
		record.DatabaseSnapshot.Source(), record.DatabaseSnapshot.Version())
	if err != nil {
		return err
	}
	served, ok, cerr := domain.ComposeAt(generations, rooting)
	if cerr != nil {
		return fmt.Errorf("composing %s to reconcile its finding index: %w", record.Coordinate, cerr)
	}
	if !ok {
		// Unreachable in practice — the row just inserted is in this frame — but a
		// silent skip here would leave the index describing a superseded record,
		// so the impossible case is reported rather than assumed away.
		return fmt.Errorf("reconciling finding index for %s: no record in frame %q after appending one", record.Coordinate, rooting)
	}

	// The delete is what makes the index describe the served record rather than
	// the union of every record ever written for this frame — an all-clear must be
	// able to retract the rows an earlier affected scan added. It is scoped to the
	// frame so an isolated scan cannot retract what a target-rooted scan indexed.
	const clearIdxQ = `
DELETE FROM vulnerability_findings_index
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?
  AND snapshot_source = ? AND snapshot_version = ? AND rooting = ?`

	if _, err = tx.ExecContext(ctx, clearIdxQ,
		record.Coordinate.Path(), record.Coordinate.Version(), record.PipelineVersion,
		record.DatabaseSnapshot.Source(), record.DatabaseSnapshot.Version(), string(rooting),
	); err != nil {
		return fmt.Errorf("clearing finding index entries for %s: %w", record.Coordinate, err)
	}

	// Populate the findings index for cross-store queries.
	//
	// The row carries the key and nothing else. Reachability deliberately does
	// not travel with it: the record is the authority on that, it is
	// three-valued rather than boolean, and an index column carrying a claim no
	// reader consults is a claim that goes stale unobserved.
	const idxQ = `
INSERT INTO vulnerability_findings_index (
    finding_id, module_path, module_version, pipeline_version,
    snapshot_source, snapshot_version, rooting
) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT DO NOTHING`

	for _, f := range served.Findings {
		// Index all aliases too (CVE, GHSA, etc.) so queries by any identifier work.
		ids := append([]string{f.ID}, f.Aliases...)
		for _, id := range ids {
			if _, err = tx.ExecContext(ctx, idxQ,
				id,
				record.Coordinate.Path(), record.Coordinate.Version(), record.PipelineVersion,
				record.DatabaseSnapshot.Source(), record.DatabaseSnapshot.Version(),
				string(rooting),
			); err != nil {
				return fmt.Errorf("inserting finding index entry %s: %w", id, err)
			}
		}
	}
	return nil
}

// listGenerations returns every verified record the ledger holds for one
// coordinate, pipeline version and snapshot, oldest append first.
//
// It takes the querier so it can run either standalone or inside a transaction;
// see reconcileFindingsIndex for why that is mandatory rather than stylistic.
func (s *Store) listGenerations(
	ctx context.Context,
	q querier,
	path, version, pipelineVersion, snapshotSource, snapshotVersion string,
) ([]domain.VulnerabilityRecord, error) {
	// rowid, not content_hash, is the secondary sort: scanned_at persists at
	// second precision — the precision the canonical hash covers, so widening the
	// column would put the stored hashes and the stored time out of step — and two
	// scans within one second carry the same timestamp. The ledger is append-only,
	// so insertion order is the sequence it actually has.
	const stmt = `
SELECT serialised FROM vulnerability_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?
  AND snapshot_source = ? AND snapshot_version = ?
ORDER BY scanned_at ASC, rowid ASC`

	rows, err := q.QueryContext(ctx, stmt, path, version, pipelineVersion, snapshotSource, snapshotVersion)
	if err != nil {
		return nil, fmt.Errorf("querying vulnerability record generations: %w", err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck // rows.Err() checked below
	}()

	var out []domain.VulnerabilityRecord
	for rows.Next() {
		var serialised []byte
		if serr := rows.Scan(&serialised); serr != nil {
			return nil, fmt.Errorf("scanning vulnerability record: %w", serr)
		}
		rec, derr := decodeRecord(serialised)
		if derr != nil {
			return nil, derr
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating vulnerability record generations: %w", err)
	}
	return out, nil
}

// firstScannedAt returns the immutable first-seen timestamp the ledger already
// holds for record's (module, version, pipeline, snapshot) tuple, if any. ok is
// false when no generation exists yet or none carries an anchor (pre-anchor
// legacy rows), in which case the caller's own FirstScannedAt stands as the
// first insert.
//
// The earliest anchor across the tuple's generations wins, not the anchor of any
// particular row. The question the field answers — when did we first find this
// out — is about the module under that snapshot, not about one measurement of
// it, so an append must not be able to move it forward.
//
// It takes the querier rather than reaching for s.db so it can run inside
// PutVulnerabilityRecord's transaction: the connection pool holds a single
// connection, so a query on the store's own handle would block on the
// transaction that is about to write the row it is reading.
func (s *Store) firstScannedAt(ctx context.Context, q querier, record domain.VulnerabilityRecord) (time.Time, bool, error) {
	const stmt = `
SELECT MIN(first_scanned_at) FROM vulnerability_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?
  AND snapshot_source = ? AND snapshot_version = ?
  AND first_scanned_at != ''`

	// An aggregate over no rows is one NULL row rather than no rows, so the
	// "nothing stored yet" case arrives as an invalid NullString and not as
	// ErrNoRows. Both are handled: the sentinel stays checked so the reading does
	// not depend on which of the two SQLite chooses to report.
	var raw sql.NullString
	err := q.QueryRowContext(ctx, stmt,
		record.Coordinate.Path(), record.Coordinate.Version(), record.PipelineVersion,
		record.DatabaseSnapshot.Source(), record.DatabaseSnapshot.Version(),
	).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("querying first_scanned_at: %w", err)
	}
	if !raw.Valid || raw.String == "" {
		return time.Time{}, false, nil
	}
	t, perr := time.Parse(time.RFC3339, raw.String)
	if perr != nil {
		return time.Time{}, false, fmt.Errorf("parsing first_scanned_at: %w", perr)
	}
	return t, true, nil
}

// GetVulnerabilityRecord returns the composed record for a coordinate,
// pipeline version and snapshot, across every analysis frame the ledger holds.
//
// It is the read for a caller that has explicitly declined to name a frame and
// is asking what the store's best-founded answer about this module is. A caller
// that HAS a frame in mind — a scan deciding whether it may reuse an earlier
// record, a run reading back what it wrote — must use
// GetVulnerabilityRecordAt, or it will be handed an answer to the other
// question.
//
// See domain.Compose for the ladder: a finding outranks an all-clear, an
// analysed record outranks a coverage gap, a better call graph outranks a
// weaker one, and only then does recency decide. The served record states its
// own frame, snapshot and completeness, so a composed answer always names the
// evidence it rests on.
func (s *Store) GetVulnerabilityRecord(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	pipelineVersion string,
	snapshot domain.DatabaseSnapshot,
) (domain.VulnerabilityRecord, bool, error) {
	// The zero coordinate names no module, so this is a question about nothing.
	// Answering it with absence would report "no record here" for a module that
	// was never asked about — see coordinate.ErrZeroCoordinate.
	if coord.IsZero() {
		return domain.VulnerabilityRecord{}, false, coordinate.ErrZeroCoordinate
	}
	// The zero snapshot names no advisory database at no generation, so this is a
	// question about nothing. Answering it with absence would report "no record
	// here" against a database that was never named — and, worse, would read the
	// composition group every record that recorded no snapshot fell into.
	if snapshot.IsZero() {
		return domain.VulnerabilityRecord{}, false, domain.ErrZeroSnapshot
	}
	records, err := s.listGenerations(ctx, s.db.DB(),
		coord.Path(), coord.Version(), pipelineVersion, snapshot.Source(), snapshot.Version())
	if err != nil {
		return domain.VulnerabilityRecord{}, false, err
	}
	if len(records) == 0 {
		return domain.VulnerabilityRecord{}, false, nil
	}
	composed, cerr := domain.Compose(records)
	if cerr != nil {
		return domain.VulnerabilityRecord{}, false, fmt.Errorf("composing vulnerability record for %s: %w", coord, cerr)
	}
	return composed, true, nil
}

// GetVulnerabilityRecordAt returns the composed record for a coordinate,
// pipeline version and snapshot WITHIN one analysis frame. found is false when
// the ledger holds no record produced in that frame.
//
// This is what stops a frame boundary from being crossed silently. An isolated
// scan asking whether it may reuse a stored record must not be handed a
// target-rooted one: the two were computed from different builds, so reusing
// across the boundary attributes a reachability answer to a build it was never
// computed against — and before the frame was recorded, that is exactly what
// happened, because both frames shared a row.
//
// Records that state no frame are considered only when nothing in the group
// states one; see domain.ComposeAt.
func (s *Store) GetVulnerabilityRecordAt(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	pipelineVersion string,
	snapshot domain.DatabaseSnapshot,
	rooting domain.Rooting,
) (domain.VulnerabilityRecord, bool, error) {
	// The zero coordinate names no module, so this is a question about nothing.
	// Answering it with absence would report "no record here" for a module that
	// was never asked about — see coordinate.ErrZeroCoordinate.
	if coord.IsZero() {
		return domain.VulnerabilityRecord{}, false, coordinate.ErrZeroCoordinate
	}
	// The zero snapshot names no advisory database at no generation, so this is a
	// question about nothing. Answering it with absence would report "no record
	// here" against a database that was never named — and, worse, would read the
	// composition group every record that recorded no snapshot fell into.
	if snapshot.IsZero() {
		return domain.VulnerabilityRecord{}, false, domain.ErrZeroSnapshot
	}
	records, err := s.listGenerations(ctx, s.db.DB(),
		coord.Path(), coord.Version(), pipelineVersion, snapshot.Source(), snapshot.Version())
	if err != nil {
		return domain.VulnerabilityRecord{}, false, err
	}
	if len(records) == 0 {
		return domain.VulnerabilityRecord{}, false, nil
	}
	composed, ok, cerr := domain.ComposeAt(records, rooting)
	if cerr != nil {
		return domain.VulnerabilityRecord{}, false, fmt.Errorf("composing vulnerability record for %s: %w", coord, cerr)
	}
	return composed, ok, nil
}

// HasVulnerabilityRecord reports whether the ledger holds the exact generation
// named by contentHash for this coordinate, pipeline version and snapshot.
//
// It is an existence check on one measurement rather than on a coordinate,
// which is what a run needs to verify that the records it reported were
// actually kept. Composing and comparing would answer a different question: the
// record a read serves is not necessarily the one this run wrote, because an
// earlier generation may legitimately outrank it.
func (s *Store) HasVulnerabilityRecord(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	pipelineVersion string,
	snapshot domain.DatabaseSnapshot,
	contentHash string,
) (bool, error) {
	// The zero coordinate names no module, so this is a question about nothing.
	if coord.IsZero() {
		return false, coordinate.ErrZeroCoordinate
	}
	// The zero snapshot names no advisory database at no generation, so this is a
	// question about nothing. Answering it with absence would report "no record
	// here" against a database that was never named — and, worse, would read the
	// composition group every record that recorded no snapshot fell into.
	if snapshot.IsZero() {
		return false, domain.ErrZeroSnapshot
	}
	const q = `
SELECT 1 FROM vulnerability_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?
  AND snapshot_source = ? AND snapshot_version = ? AND content_hash = ?
LIMIT 1`

	var one int
	err := s.db.DB().QueryRowContext(ctx, q,
		coord.Path(), coord.Version(), pipelineVersion,
		snapshot.Source(), snapshot.Version(), contentHash,
	).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checking stored vulnerability record for %s: %w", coord, err)
	}
	return true, nil
}

// GetLatestVulnerabilityRecord returns the composed record for a coordinate and
// pipeline version across every snapshot and every frame the ledger holds.
//
// "Latest" is the name it has always had; what it serves is the best-founded
// answer, not the newest row. The distinction is the point of the ladder: a
// re-scan under a newer advisory database backed by a weaker call graph is a
// legitimate append and a worse basis for a reachability finding, so ordering by
// scanned_at alone would let it retract an established finding merely by running
// later.
func (s *Store) GetLatestVulnerabilityRecord(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	pipelineVersion string,
) (domain.VulnerabilityRecord, bool, error) {
	// The zero coordinate names no module, so this is a question about nothing.
	// Answering it with absence would report "no record here" for a module that
	// was never asked about — see coordinate.ErrZeroCoordinate.
	if coord.IsZero() {
		return domain.VulnerabilityRecord{}, false, coordinate.ErrZeroCoordinate
	}
	const q = `
SELECT serialised FROM vulnerability_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?
ORDER BY scanned_at ASC, rowid ASC`

	records, err := s.queryRecords(ctx, "latest vulnerability record", q,
		coord.Path(), coord.Version(), pipelineVersion)
	if err != nil {
		return domain.VulnerabilityRecord{}, false, err
	}
	if len(records) == 0 {
		return domain.VulnerabilityRecord{}, false, nil
	}
	composed, cerr := domain.Compose(records)
	if cerr != nil {
		return domain.VulnerabilityRecord{}, false, fmt.Errorf("composing vulnerability record for %s: %w", coord, cerr)
	}
	return composed, true, nil
}

// ListVulnerabilityRecordsForModuleInWalk returns every generation of a
// coordinate the given walk's scan runs covered, regardless of snapshot, oldest
// first.
//
// The membership index answers which MODULES a walk's runs covered, not which
// generation each run reported — that is the run's own PerModuleResults, and
// ListVulnerabilityRecords is the read that uses it. So the join is by
// coordinate and every generation of a covered module is a candidate. Narrowing
// it by the recorded content hash would make a run that named a record the store
// no longer holds answer "this walk never covered the module", which is a false
// absence rather than a narrower truth.
//
// The walk constraint goes through walk_scan_run_modules rather than the
// walk_id column on vulnerability_records: since schema v5 that column is
// provenance for the last walk that triggered the scan, so a record shared by
// two walks names only one of them and filtering on it would drop the other
// walk's module. ListVulnerabilityRecordsByFindingID takes the same route.
//
// Candidates are returned unranked. The membership key carries no analysis
// frame, so this join admits every frame the coordinate was measured in at that
// generation — the walk's own target-rooted record, an isolated scan of the
// module, and another project's target-rooted record alike. Choosing between
// them is a question about frames, which is the caller's to answer; this read
// composed them until it was measured serving a corteza-pinned question from an
// isolated record written under a different walk.
func (s *Store) ListVulnerabilityRecordsForModuleInWalk(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	pipelineVersion string,
	walkID string,
) ([]domain.VulnerabilityRecord, error) {
	// The zero coordinate names no module, so this is a question about nothing.
	// Answering it with absence would report "no record here" for a module that
	// was never asked about — see coordinate.ErrZeroCoordinate.
	if coord.IsZero() {
		return nil, coordinate.ErrZeroCoordinate
	}
	const q = `
SELECT DISTINCT vr.serialised, vr.scanned_at, vr.rowid
FROM vulnerability_records vr
JOIN walk_scan_run_modules m
  ON m.module_path      = vr.module_path
 AND m.module_version   = vr.module_version
 AND m.pipeline_version = vr.pipeline_version
 AND m.snapshot_source  = vr.snapshot_source
 AND m.snapshot_version = vr.snapshot_version
JOIN walk_scan_runs wsr ON wsr.id = m.walk_scan_run_id
WHERE vr.module_path      = ?
  AND vr.module_version   = ?
  AND vr.pipeline_version = ?
  AND wsr.walk_id = ?
ORDER BY vr.scanned_at ASC, vr.rowid ASC`

	rows, err := s.db.DB().QueryContext(ctx, q, coord.Path(), coord.Version(), pipelineVersion, walkID)
	if err != nil {
		return nil, fmt.Errorf("querying vulnerability records for walk: %w", err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck // rows.Err() checked below
	}()

	var records []domain.VulnerabilityRecord
	for rows.Next() {
		var serialised []byte
		var scannedAt string // ordering keys only; the record carries its own timestamp.
		var rowID int64
		if serr := rows.Scan(&serialised, &scannedAt, &rowID); serr != nil {
			return nil, fmt.Errorf("scanning vulnerability record: %w", serr)
		}
		rec, derr := decodeRecord(serialised)
		if derr != nil {
			return nil, derr
		}
		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating vulnerability records for walk: %w", err)
	}
	return records, nil
}

// queryRecords runs a query selecting only the serialised column and decodes
// every row, verifying each record's seal. what names the read in error
// messages.
func (s *Store) queryRecords(ctx context.Context, what, query string, args ...any) ([]domain.VulnerabilityRecord, error) {
	rows, err := s.db.DB().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying %s: %w", what, err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck // rows.Err() checked below
	}()

	var out []domain.VulnerabilityRecord
	for rows.Next() {
		var serialised []byte
		if serr := rows.Scan(&serialised); serr != nil {
			return nil, fmt.Errorf("scanning %s: %w", what, serr)
		}
		rec, derr := decodeRecord(serialised)
		if derr != nil {
			return nil, derr
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating %s: %w", what, err)
	}
	return out, nil
}

// PutWalkScanRun persists a walk scan run and its per-module membership index.
func (s *Store) PutWalkScanRun(ctx context.Context, run domain.WalkScanRun) error {
	// Same rule as PutVulnerabilityRecord: a run whose hash does not describe it
	// is refused rather than stored as a row only a tamper report can read back.
	var h domain.WalkScanRunHasher
	if verr := h.VerifyContentHash(run); verr != nil {
		return fmt.Errorf("%w: verifying run %s before put: %w", ports.ErrVulnIntegrity, run.ID, verr)
	}
	serialised, err := h.Marshal(run)
	if err != nil {
		return fmt.Errorf("marshalling walk scan run: %w", err)
	}

	tx, err := s.db.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	const q = `
INSERT INTO walk_scan_runs (
    id, walk_id, snapshot_source, snapshot_version,
    started_at, completed_at, overall_status,
    coverage_status, findings_status,
    total_modules, analysed_modules, affected_modules,
    unscannable_modules, failed_modules,
    operator, content_hash, serialised
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
    walk_id             = excluded.walk_id,
    snapshot_source     = excluded.snapshot_source,
    snapshot_version    = excluded.snapshot_version,
    started_at          = excluded.started_at,
    completed_at        = excluded.completed_at,
    overall_status      = excluded.overall_status,
    coverage_status     = excluded.coverage_status,
    findings_status     = excluded.findings_status,
    total_modules       = excluded.total_modules,
    analysed_modules    = excluded.analysed_modules,
    affected_modules    = excluded.affected_modules,
    unscannable_modules = excluded.unscannable_modules,
    failed_modules      = excluded.failed_modules,
    operator            = excluded.operator,
    content_hash        = excluded.content_hash,
    serialised          = excluded.serialised`

	if _, err = tx.ExecContext(ctx, q,
		run.ID, run.WalkID, run.Snapshot.Source(), run.Snapshot.Version(),
		run.StartedAt.UTC().Format(time.RFC3339),
		run.CompletedAt.UTC().Format(time.RFC3339),
		string(run.OverallStatus),
		string(run.CoverageStatus), string(run.FindingsStatus),
		run.Counts.Total, run.Counts.Analysed, run.Counts.Affected,
		run.Counts.Unscannable, run.Counts.Failed,
		run.Operator, run.ContentHash, serialised,
	); err != nil {
		return fmt.Errorf("inserting walk scan run: %w", err)
	}

	// record_content_hash names the exact generation this run scanned. Since the
	// record table became a ledger a coordinate resolves to several, so a
	// membership row that named only the coordinate would let a run be read back
	// against a record written after it finished. PerModuleResults already holds
	// the hash; this carries it into the index the joins actually use.
	const modQ = `
INSERT INTO walk_scan_run_modules (
    walk_scan_run_id, module_path, module_version,
    pipeline_version, snapshot_source, snapshot_version, walk_id,
    record_content_hash
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (walk_scan_run_id, module_path, module_version) DO NOTHING`

	// The row set, not a winner: each coordinate is a distinct key and the
	// conflict clause makes a repeat a no-op, and every read of this table
	// orders on the record columns rather than on insertion.
	for coord, contentHash := range run.PerModuleResults {
		if _, err = tx.ExecContext(ctx, modQ,
			run.ID, coord.Path(), coord.Version(),
			run.PipelineVersion, run.Snapshot.Source(), run.Snapshot.Version(), run.WalkID,
			contentHash,
		); err != nil {
			return fmt.Errorf("inserting walk scan run module %s: %w", coord, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing walk scan run: %w", err)
	}
	return nil
}

// GetWalkScanRun retrieves a walk scan run.
func (s *Store) GetWalkScanRun(ctx context.Context, id string) (domain.WalkScanRun, bool, error) {
	const q = `SELECT serialised FROM walk_scan_runs WHERE id = ?`

	var serialised []byte
	err := s.db.DB().QueryRowContext(ctx, q, id).Scan(&serialised)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.WalkScanRun{}, false, nil
	}
	if err != nil {
		return domain.WalkScanRun{}, false, fmt.Errorf("querying walk scan run: %w", err)
	}

	run, derr := decodeRun(serialised)
	if derr != nil {
		// Reported as the same unreadable-row failure the listings raise, for one
		// row. The listing is how an operator finds a bad run, and looking at it
		// is the next thing they do, so the two must speak the same language:
		// an inspection command can name the row and carry on, and a consuming
		// caller still matches the integrity sentinel and still fails closed.
		return domain.WalkScanRun{}, false, unreadableRunsErr([]ports.UnreadableRun{
			{ID: runIDFrom(serialised), Reason: derr},
		})
	}
	return run, true, nil
}

// ListWalkScanRuns lists scan runs for a walk.
func (s *Store) ListWalkScanRuns(ctx context.Context, walkID string) ([]domain.WalkScanRun, error) {
	const q = `SELECT serialised FROM walk_scan_runs WHERE walk_id = ? ORDER BY started_at DESC, id DESC`

	rows, err := s.db.DB().QueryContext(ctx, q, walkID)
	if err != nil {
		return nil, fmt.Errorf("listing walk scan runs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	runs, unreadable, err := collectRuns(rows)
	if err != nil {
		return nil, err
	}
	return runs, unreadableRunsErr(unreadable)
}

// ListAllWalkScanRuns lists all scan runs across all walks, most recent first.
//
// id breaks the started_at tie, so the order is total. vuln-scan-list pages this
// listing in memory, and a page is only the rows the previous page did not show
// if two calls order the population identically.
func (s *Store) ListAllWalkScanRuns(ctx context.Context) ([]domain.WalkScanRun, error) {
	const q = `SELECT serialised FROM walk_scan_runs ORDER BY started_at DESC, id DESC`

	rows, err := s.db.DB().QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("listing all walk scan runs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	runs, unreadable, err := collectRuns(rows)
	if err != nil {
		return nil, err
	}
	return runs, unreadableRunsErr(unreadable)
}

// collectRuns reads every scan run in rows, keeping the ones that verify and
// naming the ones that do not. It is the single seam both listings go through,
// so a fix to how an unreadable row is handled cannot apply to one listing and
// miss the other — vuln-scan-list reaches this store by both routes depending
// on whether it was given a walk id.
//
// Only a seal failure is survivable here. A database that cannot hand over the
// row at all is a different fault: nothing is known about what was skipped, not
// even that it exists, so there is no honest partial answer to give.
func collectRuns(rows *sql.Rows) ([]domain.WalkScanRun, []ports.UnreadableRun, error) {
	var (
		runs       []domain.WalkScanRun
		unreadable []ports.UnreadableRun
	)
	for rows.Next() {
		var serialised []byte
		if err := rows.Scan(&serialised); err != nil {
			return nil, nil, fmt.Errorf("scanning walk scan run: %w", err)
		}
		run, derr := decodeRun(serialised)
		if derr != nil {
			unreadable = append(unreadable, ports.UnreadableRun{ID: runIDFrom(serialised), Reason: derr})
			continue
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterating walk scan runs: %w", err)
	}
	return runs, unreadable, nil
}

// unreadableRunsErr wraps the unreadable rows for the caller, or returns nil
// when there were none.
func unreadableRunsErr(unreadable []ports.UnreadableRun) error {
	if len(unreadable) == 0 {
		return nil
	}
	return &ports.UnreadableRuns{Runs: unreadable}
}

// runIDFrom recovers a run's identifier from stored bytes the seal check
// rejected, so the row can be named in a report.
//
// It reads only the id field and asserts nothing else about the bytes: they are
// under suspicion, which is precisely why they must not be interpreted as a
// record. An id that cannot be read comes back empty and the row is reported
// without one.
func runIDFrom(serialised []byte) string {
	var head struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(serialised, &head); err != nil {
		return ""
	}
	return head.ID
}

// PutDatabaseSnapshot persists a snapshot blob.
func (s *Store) PutDatabaseSnapshot(ctx context.Context, snapshot domain.DatabaseSnapshot, content io.Reader) error {
	if snapshot.IsZero() {
		return fmt.Errorf("putting database snapshot: %w", domain.ErrZeroSnapshot)
	}

	data, err := io.ReadAll(content)
	if err != nil {
		return fmt.Errorf("reading snapshot content: %w", err)
	}

	// The stored hash is always computed from the bytes being stored: the store
	// is the authority on what it holds, and a hash taken from the caller's word
	// would verify nothing on the way back out.
	//
	// A caller that supplies one is asserting which bytes it fetched, so a
	// disagreement is a real finding — the blob changed between the fetch that
	// sealed it and this write — and is refused rather than papered over by
	// storing the hash of whatever arrived. A caller that supplies none has
	// simply not sealed; the store seals it, and the snapshot becomes verifiable
	// from here on.
	computed := domain.HashSnapshotContent(data)
	if snapshot.ContentHash() != "" && snapshot.ContentHash() != computed {
		return fmt.Errorf("%w: snapshot %s@%s content hash mismatch: caller declared %q, content is %q",
			ports.ErrSnapshotIntegrity, snapshot.Source(), snapshot.Version(), snapshot.ContentHash(), computed)
	}
	sealed, err := snapshot.WithContentHash(computed)
	if err != nil {
		return fmt.Errorf("sealing snapshot %s@%s against the bytes being stored: %w", snapshot.Source(), snapshot.Version(), err)
	}

	const q = `
INSERT INTO vulnerability_snapshots (
    source, version, retrieved_at, content_hash, content
) VALUES (?, ?, ?, ?, ?)
ON CONFLICT (source, version) DO UPDATE SET
    retrieved_at = excluded.retrieved_at,
    content_hash = excluded.content_hash,
    content      = excluded.content`

	_, err = s.db.DB().ExecContext(ctx, q,
		sealed.Source(), sealed.Version(),
		sealed.RetrievedAt().UTC().Format(time.RFC3339),
		sealed.ContentHash(), data,
	)
	if err != nil {
		return fmt.Errorf("inserting database snapshot: %w", err)
	}
	return nil
}

// GetDatabaseSnapshot retrieves a snapshot blob, verified against its stored
// content hash before it is handed to a scan.
//
// This is the read leg of the same rule record content already gets: the
// advisory database is the evidence every finding is derived from, so a scan
// must not consume a blob that is not the one that was fetched. A mismatch is
// reported as ErrSnapshotIntegrity rather than as absence, for the same reason a
// tampered record is — absence would trigger a silent re-fetch that overwrites
// the evidence.
//
// The sentinel is the snapshot's own, not the record's: a corrupt snapshot
// invalidates every verdict derived from it, while a corrupt record invalidates
// one module's, and a caller that would abort the run on the first and fail the
// module on the second must be able to tell them apart.
//
// A snapshot stored before the hash existed carries an empty one. Such a blob
// is returned with no check, because there is nothing to check it against;
// unverifiable is not the same claim as verified, and refusing it would make
// every pre-existing store unreadable rather than merely unproven. The
// migration that hashes those blobs in place closes the gap for stores it runs
// against.
//
// When the caller's own snapshot value carries a hash, it is checked too: it is
// the caller's assertion about which snapshot it asked for, and answering a
// question about one snapshot with the bytes of another is the failure this
// whole field exists to prevent.
func (s *Store) GetDatabaseSnapshot(ctx context.Context, snapshot domain.DatabaseSnapshot) (io.ReadCloser, error) {
	if snapshot.IsZero() {
		return nil, fmt.Errorf("getting database snapshot: %w", domain.ErrZeroSnapshot)
	}

	const q = `SELECT content, content_hash FROM vulnerability_snapshots WHERE source = ? AND version = ?`

	var content []byte
	var storedHash string
	err := s.db.DB().QueryRowContext(ctx, q, snapshot.Source(), snapshot.Version()).Scan(&content, &storedHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("snapshot not found: %s@%s", snapshot.Source(), snapshot.Version())
	}
	if err != nil {
		return nil, fmt.Errorf("querying database snapshot: %w", err)
	}

	if storedHash != "" {
		if computed := domain.HashSnapshotContent(content); computed != storedHash {
			return nil, fmt.Errorf("%w: snapshot %s@%s content hash mismatch: stored %q, computed %q",
				ports.ErrSnapshotIntegrity, snapshot.Source(), snapshot.Version(), storedHash, computed)
		}
	}
	if snapshot.ContentHash() != "" && storedHash != "" && snapshot.ContentHash() != storedHash {
		return nil, fmt.Errorf("%w: snapshot %s@%s is not the one requested: caller expected %q, store holds %q",
			ports.ErrSnapshotIntegrity, snapshot.Source(), snapshot.Version(), snapshot.ContentHash(), storedHash)
	}

	return io.NopCloser(bytes.NewReader(content)), nil
}

// GetLatestDatabaseSnapshot returns the most recently stored snapshot metadata.
//
// content_hash is part of that metadata. Omitting it — as this query did before
// the hash was populated — silently produced an unsealed snapshot value that
// then flowed into every record built from a cached snapshot, which is most of
// them: the field being empty on the record was not only a gap in the fetch
// path but a gap here, where the stored hash was read past.
func (s *Store) GetLatestDatabaseSnapshot(ctx context.Context) (domain.DatabaseSnapshot, bool, error) {
	const q = `SELECT source, version, retrieved_at, content_hash FROM vulnerability_snapshots ORDER BY retrieved_at DESC LIMIT 1`

	var source, version, retrievedAt, contentHash string
	err := s.db.DB().QueryRowContext(ctx, q).Scan(&source, &version, &retrievedAt, &contentHash)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.DatabaseSnapshot{}, false, nil
	}
	if err != nil {
		return domain.DatabaseSnapshot{}, false, fmt.Errorf("querying latest snapshot: %w", err)
	}

	t, err := time.Parse(time.RFC3339, retrievedAt)
	if err != nil {
		return domain.DatabaseSnapshot{}, false, fmt.Errorf("parsing snapshot time: %w", err)
	}

	stored, err := domain.NewDatabaseSnapshot(source, version, t, contentHash)
	if err != nil {
		return domain.DatabaseSnapshot{}, false, fmt.Errorf("reading latest snapshot: %w", err)
	}
	return stored, true, nil
}

// ListDatabaseSnapshots returns all stored snapshot metadata, most recent first.
func (s *Store) ListDatabaseSnapshots(ctx context.Context) ([]domain.DatabaseSnapshot, error) {
	const q = `SELECT source, version, retrieved_at, content_hash FROM vulnerability_snapshots ORDER BY retrieved_at DESC`

	rows, err := s.db.DB().QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("listing database snapshots: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var snapshots []domain.DatabaseSnapshot
	for rows.Next() {
		var source, version, retrievedAt, contentHash string
		if err := rows.Scan(&source, &version, &retrievedAt, &contentHash); err != nil {
			return nil, fmt.Errorf("scanning snapshot row: %w", err)
		}
		t, err := time.Parse(time.RFC3339, retrievedAt)
		if err != nil {
			return nil, fmt.Errorf("parsing snapshot time: %w", err)
		}
		stored, err := domain.NewDatabaseSnapshot(source, version, t, contentHash)
		if err != nil {
			return nil, fmt.Errorf("reading snapshot row: %w", err)
		}
		snapshots = append(snapshots, stored)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating snapshots: %w", err)
	}
	return snapshots, nil
}

// ListVulnerabilityRecordsByFindingID returns one vulnerability record per
// module version that contains a finding with the given identifier.
//
// A coordinate accumulates a record per (pipeline version, snapshot) it was ever
// scanned under, and those generations disagree — the same module version is
// Affected under one snapshot and Clean under another. Reporting every
// generation gives the reader rows they cannot rank; reporting only the newest
// would let a later Clean quietly retire an earlier finding.
//
// The tie-break is therefore the finding, not the clock: a record that reports
// the module as Affected outranks one that does not, and only among equals does
// the newest scan win.
//
// Clean is the right label for a module where the advisory was never found. It
// is not a label a finding may quietly decay into: once a finding exists,
// turning it into anything else needs a stated reason — the advisory was
// withdrawn, the module moved out of the affected range, the reachability
// verdict was corrected. The store has no way to record such a reason yet, so
// this ranking is a guard rather than a model: it keeps an unexplained Clean
// from displacing a finding until reasoned transitions exist.
//
// The guard is not hypothetical. In a working store, seven (advisory, module,
// snapshot) triples — identical inputs, no new evidence — were reported Clean by
// exactly one pipeline generation and Affected by every other. Ranking by
// recency alone would have let that generation retract seven real findings.
//
// Superseded generations are not lost — vuln-show --history exists to show them,
// and does.
//
// An empty walkID answers across the store. When walkID is set the answer is
// restricted to the modules a scan run of that walk covered, and "most recent"
// is taken within that walk.
//
// The walk constraint goes through walk_scan_run_modules rather than the
// walk_id column on vulnerability_records: since schema v5 that column is
// provenance for the last walk that triggered the scan, so a record shared by
// two walks names only one of them and filtering on it would drop the other
// walk's module. ListVulnerabilityRecordsForModuleInWalk takes the same route.
//
// An unknown walkID is an error rather than an empty result: "no modules are
// affected by this CVE" is the wrong answer to give for a walk that was never
// scanned.
func (s *Store) ListVulnerabilityRecordsByFindingID(ctx context.Context, findingID, walkID string) ([]domain.VulnerabilityRecord, error) {
	// Ranking within a coordinate: a finding-bearing verdict first, then a
	// verdict that was actually analysed, then the newest scan, then the newest
	// pipeline generation.
	//
	// The two status terms are the two axes, and both are needed. Findings first,
	// because a later all-clear must not retire an earlier finding. Coverage
	// second, because among records that report no finding, one that was analysed
	// and found nothing is evidence of absence while one that could not be
	// analysed is merely absence of evidence — ranking them together let a
	// ScanFailed record outrank a real all-clear purely on being newer, and
	// answer a security question with a scan that never happened. That is the
	// collapse this pair of columns exists to undo; a single collapsed status
	// could not express it, because two of its four values are coverage answers
	// sitting in a findings field.
	//
	// The pipeline version is a tie-break, never a filter. Pinning the reader's
	// current version would erase every module whose newest scan predates a
	// pipeline bump — measured at 92 of 235 findings in a working store, each of
	// which would have become "no modules affected". A stale answer labelled
	// with its date is a fact; a missing answer is a false all-clear.
	//
	// substr past the leading "v" makes that compare numeric, so v9 does not
	// outrank v14 the way a text compare would. A format change degrades to 0,
	// which is arbitrary but still deterministic.
	//
	// The first tier is "this record reports a matched advisory at all", which is
	// two findings values, not one: Affected and Withdrawn. A withdrawn record bears
	// the finding and states why it no longer stands, so it belongs in the tier that
	// outranks a bare all-clear, and within that tier scanned_at decides — which is
	// what lets a newer retraction supersede an older Affected verdict. Ranking
	// Withdrawn with Clean instead would have demoted the very record that carries
	// the reason, leaving a stale Affected as the answer for a retracted advisory.
	// Ranking it above Affected would be the mirror error: one live advisory beside
	// a retracted one is an Affected record, and it must not lose to a withdrawal.
	//
	// The three status placeholders are bound first because they appear first in
	// the query text, ahead of the WHERE clause parameters.
	//
	// Records written before the axes existed carry them back-filled by migration
	// 11, so the comparison is against a real value on every row rather than
	// against the empty string on the older generations the query deliberately
	// still reads.
	const rankWithinCoordinate = `
    ROW_NUMBER() OVER (
      PARTITION BY vr.module_path, vr.module_version
      ORDER BY (vr.findings_status IN (?, ?)) DESC,
               (vr.coverage_status = ?) DESC,
               vr.scanned_at DESC,
               CAST(substr(vr.pipeline_version, 2) AS INTEGER) DESC
    ) AS rn`

	// The index carries the analysis frame, so the join carries it too. Without
	// that term an index row an isolated scan wrote would attach to the
	// target-rooted record of the same coordinate and snapshot, and the answer
	// would name a record that never reported the advisory being asked about.
	const unscoped = `
SELECT serialised, scanned_at FROM (
  SELECT vr.serialised AS serialised, vr.scanned_at AS scanned_at,` + rankWithinCoordinate + `
  FROM vulnerability_records vr
  JOIN vulnerability_findings_index fi
    ON fi.module_path      = vr.module_path
   AND fi.module_version   = vr.module_version
   AND fi.pipeline_version = vr.pipeline_version
   AND fi.snapshot_source  = vr.snapshot_source
   AND fi.snapshot_version = vr.snapshot_version
   AND fi.rooting          = vr.rooting
  WHERE fi.finding_id = ?
)
WHERE rn = 1
ORDER BY scanned_at DESC`

	// The partition also absorbs the duplicate rows a walk with several scan
	// runs over one module would otherwise produce.
	const scoped = `
SELECT serialised, scanned_at FROM (
  SELECT DISTINCT vr.serialised AS serialised, vr.scanned_at AS scanned_at,` + rankWithinCoordinate + `
  FROM vulnerability_records vr
  JOIN vulnerability_findings_index fi
    ON fi.module_path      = vr.module_path
   AND fi.module_version   = vr.module_version
   AND fi.pipeline_version = vr.pipeline_version
   AND fi.snapshot_source  = vr.snapshot_source
   AND fi.snapshot_version = vr.snapshot_version
   AND fi.rooting          = vr.rooting
  JOIN walk_scan_run_modules m
    ON m.module_path      = vr.module_path
   AND m.module_version   = vr.module_version
   AND m.pipeline_version = vr.pipeline_version
   AND m.snapshot_source  = vr.snapshot_source
   AND m.snapshot_version = vr.snapshot_version
  JOIN walk_scan_runs wsr ON wsr.id = m.walk_scan_run_id
  WHERE fi.finding_id = ? AND wsr.walk_id = ?
)
WHERE rn = 1
ORDER BY scanned_at DESC`

	rank := []any{
		string(domain.FindingsRecordAffected),
		string(domain.FindingsRecordWithdrawn),
		string(domain.CoverageAnalysed),
	}

	q, args := unscoped, append(append([]any{}, rank...), findingID)
	if walkID != "" {
		known, err := s.walkHasScanRun(ctx, walkID)
		if err != nil {
			return nil, err
		}
		if !known {
			return nil, fmt.Errorf("no vulnerability scan run for walk %s — run: kanonarion vuln-scan %s", walkID, walkID)
		}
		q, args = scoped, append(append([]any{}, rank...), findingID, walkID)
	}

	rows, err := s.db.DB().QueryContext(ctx, q, args...)
	if err != nil {
		if walkID != "" {
			return nil, fmt.Errorf("querying records by finding id in walk %s: %w", walkID, err)
		}
		return nil, fmt.Errorf("querying records by finding id: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var records []domain.VulnerabilityRecord
	for rows.Next() {
		var serialised []byte
		var scannedAt string // ordering key only; the record carries its own timestamp.
		if err := rows.Scan(&serialised, &scannedAt); err != nil {
			return nil, fmt.Errorf("scanning vulnerability record: %w", err)
		}
		rec, derr := decodeRecord(serialised)
		if derr != nil {
			return nil, derr
		}
		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating vulnerability records: %w", err)
	}
	return records, nil
}

// walkHasScanRun reports whether any vulnerability scan run was recorded for
// the given walk, so a scoped query can tell "nothing matched" apart from
// "that walk was never scanned".
func (s *Store) walkHasScanRun(ctx context.Context, walkID string) (bool, error) {
	const q = `SELECT 1 FROM walk_scan_runs WHERE walk_id = ? LIMIT 1`
	var one int
	err := s.db.DB().QueryRowContext(ctx, q, walkID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checking scan runs for walk %s: %w", walkID, err)
	}
	return true, nil
}

// ListVulnerabilityRecords returns all vulnerability records for a walk scan run.
func (s *Store) ListVulnerabilityRecords(ctx context.Context, walkScanRunID string) ([]domain.VulnerabilityRecord, error) {
	// Verify the run exists before returning an empty slice.
	_, found, err := s.GetWalkScanRun(ctx, walkScanRunID)
	if err != nil {
		return nil, fmt.Errorf("getting walk scan run: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("walk scan run not found: %s", walkScanRunID)
	}

	// One row per (coordinate, generation) the run's membership index reaches. A
	// run that recorded the record's content hash reaches exactly the generation
	// it scanned; a run written before that column existed named only the
	// coordinate, so it reaches every generation and the collapse below decides.
	const q = `
SELECT vr.module_path, vr.module_version, m.record_content_hash, vr.content_hash, vr.serialised
FROM vulnerability_records vr
JOIN walk_scan_run_modules m
  ON m.module_path      = vr.module_path
 AND m.module_version   = vr.module_version
 AND m.pipeline_version = vr.pipeline_version
 AND m.snapshot_source  = vr.snapshot_source
 AND m.snapshot_version = vr.snapshot_version
WHERE m.walk_scan_run_id = ?
ORDER BY vr.module_path, vr.module_version, vr.scanned_at ASC, vr.rowid ASC`

	rows, err := s.db.DB().QueryContext(ctx, q, walkScanRunID)
	if err != nil {
		return nil, fmt.Errorf("listing vulnerability records: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type moduleKey struct{ path, version string }
	var order []moduleKey
	pinned := map[moduleKey]domain.VulnerabilityRecord{}
	candidates := map[moduleKey][]domain.VulnerabilityRecord{}

	for rows.Next() {
		var path, version, wantHash, gotHash string
		var serialised []byte
		if err := rows.Scan(&path, &version, &wantHash, &gotHash, &serialised); err != nil {
			return nil, fmt.Errorf("scanning vulnerability record: %w", err)
		}
		rec, derr := decodeRecord(serialised)
		if derr != nil {
			return nil, derr
		}
		k := moduleKey{path, version}
		if _, seen := candidates[k]; !seen {
			order = append(order, k)
		}
		candidates[k] = append(candidates[k], rec)
		if wantHash != "" && wantHash == gotHash {
			// The run named this generation. It is the answer, not a candidate:
			// serving a later one would report a record the run never produced.
			pinned[k] = rec
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating vulnerability records: %w", err)
	}

	records := make([]domain.VulnerabilityRecord, 0, len(order))
	for _, k := range order {
		if rec, ok := pinned[k]; ok {
			records = append(records, rec)
			continue
		}
		composed, cerr := domain.Compose(candidates[k])
		if cerr != nil {
			return nil, fmt.Errorf("composing vulnerability record for %s@%s in run %s: %w", k.path, k.version, walkScanRunID, cerr)
		}
		records = append(records, composed)
	}
	return records, nil
}

// ListVulnerabilityRecordsForModule returns every generation the ledger holds
// for a coordinate and pipeline version, across all walks, snapshots and
// analysis frames, newest first.
//
// This is what makes the ledger observable: after a re-scan has changed the
// served record, the earlier one is still here, stating the snapshot, the
// call-graph completeness and the frame it was reached in.
//
// The secondary sort is the row id, not the content hash. scanned_at persists at
// second precision — the precision the canonical hash covers, so widening the
// column would put the stored hashes and the stored time out of step — and two
// scans within one second carry the same timestamp. The ledger is append-only,
// so insertion order is the sequence it actually has.
func (s *Store) ListVulnerabilityRecordsForModule(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	pipelineVersion string,
) ([]domain.VulnerabilityRecord, error) {
	// The zero coordinate names no module, so this is a question about nothing.
	// Answering it with absence would report "no record here" for a module that
	// was never asked about — see coordinate.ErrZeroCoordinate.
	if coord.IsZero() {
		return nil, coordinate.ErrZeroCoordinate
	}
	const q = `
SELECT serialised FROM vulnerability_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?
ORDER BY scanned_at DESC, rowid DESC`

	return s.queryRecords(ctx, "vulnerability records for module", q,
		coord.Path(), coord.Version(), pipelineVersion)
}

// ListVulnerabilityRecordsForModuleAllGenerations returns every record the
// ledger holds for a coordinate, at every pipeline version, newest first.
//
// It is ListVulnerabilityRecordsForModule with the generation lifted out of the
// key. The keyed read answers "what does this build serve for this module"; this
// one answers "what has ever been recorded about this module", and after a
// pipeline bump those are different questions with different answers — the
// second is the one a history listing asks.
//
// Ordering and its tie-break are the keyed read's, for its reasons: scanned_at
// persists at second precision, so the row id carries the sequence the
// append-only ledger actually has. Across generations that matters more, not
// less: a re-scan under new logic lands after the record it supersedes.
func (s *Store) ListVulnerabilityRecordsForModuleAllGenerations(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
) ([]domain.VulnerabilityRecord, error) {
	// The zero coordinate names no module — the same refusal the keyed reads
	// make, for the same reason.
	if coord.IsZero() {
		return nil, coordinate.ErrZeroCoordinate
	}
	const q = `
SELECT serialised FROM vulnerability_records
WHERE module_path = ? AND module_version = ?
ORDER BY scanned_at DESC, rowid DESC`

	return s.queryRecords(ctx, "vulnerability records for module across generations", q,
		coord.Path(), coord.Version())
}

// ListVulnerabilityRecordGenerationsForModule counts what the ledger holds for
// a coordinate at each pipeline version it holds anything at.
//
// It is the read that makes "superseded" askable. Every other per-coordinate
// read takes the pipeline version as part of its key, so after a bump they all
// answer empty for a coordinate whose whole history is sitting in the table,
// and none of them can tell that from a coordinate nobody has ever scanned.
//
// The counts come from the index columns and the blobs are never decoded, so no
// seal is verified here: a record this build can no longer decode is still one
// the store holds, and a census that dropped it would understate exactly the
// generation it exists to report. Nothing may be served from these counts —
// they say how much is there, not what it says.
func (s *Store) ListVulnerabilityRecordGenerationsForModule(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
) ([]ports.VulnerabilityRecordGeneration, error) {
	// The zero coordinate names no module, so this is a question about nothing —
	// the same refusal the keyed reads make, for the same reason.
	if coord.IsZero() {
		return nil, coordinate.ErrZeroCoordinate
	}
	const q = `
SELECT pipeline_version, COUNT(*), COALESCE(SUM(finding_count), 0)
FROM vulnerability_records
WHERE module_path = ? AND module_version = ?
GROUP BY pipeline_version
ORDER BY pipeline_version`

	rows, err := s.db.DB().QueryContext(ctx, q, coord.Path(), coord.Version())
	if err != nil {
		return nil, fmt.Errorf("querying vulnerability record generations: %w", err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck // rows.Err() checked below
	}()

	var out []ports.VulnerabilityRecordGeneration
	for rows.Next() {
		var g ports.VulnerabilityRecordGeneration
		if serr := rows.Scan(&g.PipelineVersion, &g.Records, &g.Findings); serr != nil {
			return nil, fmt.Errorf("scanning vulnerability record generations: %w", serr)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating vulnerability record generations: %w", err)
	}
	return out, nil
}

// decodeRecord parses a stored record and checks the seal it carries. Every
// read path goes through it, not only the snapshot-keyed one: a guarantee that
// holds on one query and not the next has a hole the size of the rest of the
// query surface, and a caller reaching a record by any route is entitled to the
// same answer about whether it still describes what was scanned.
//
// An integrity failure is reported as ErrVulnIntegrity, never as absence. A
// detected tamper reported as "nothing here" becomes a silent re-scan that
// overwrites the evidence of the tamper.
func decodeRecord(serialised []byte) (domain.VulnerabilityRecord, error) {
	var h domain.VulnerabilityRecordHasher
	rec, err := h.Unmarshal(serialised)
	if err != nil {
		return domain.VulnerabilityRecord{}, fmt.Errorf("unmarshalling vulnerability record: %w", err)
	}
	if verr := h.VerifyContentHash(rec); verr != nil {
		// A record this build cannot reproduce is not necessarily one that has
		// been altered. recordseal decides which, on the stored bytes alone —
		// and it is JSON-aware, so the snapshot's embedded content_hash is
		// treated as the sealed content it is rather than as the seal.
		//
		// It is told what the recipe leaves out, because the stored blob and the
		// sealed bytes are not the same set of fields: a record that has been
		// re-scanned carries a first-seen anchor the seal never covered, and a
		// verifier that did not know would report every one of them as altered.
		return domain.VulnerabilityRecord{}, fmt.Errorf("%w: %s: %w",
			ports.ErrVulnIntegrity, rec.Coordinate,
			recordseal.Excluding(h.SealExcludes()...).Classify(serialised, rec.ContentHash, verr))
	}
	return rec, nil
}

// decodeRun parses a stored walk scan run and checks its seal, on the same
// terms as decodeRecord.
func decodeRun(serialised []byte) (domain.WalkScanRun, error) {
	var h domain.WalkScanRunHasher
	run, err := h.Unmarshal(serialised)
	if err != nil {
		return domain.WalkScanRun{}, fmt.Errorf("unmarshalling walk scan run: %w", err)
	}
	if verr := h.VerifyContentHash(run); verr != nil {
		return domain.WalkScanRun{}, fmt.Errorf("%w: run %s: %w",
			ports.ErrVulnIntegrity, run.ID,
			recordseal.Excluding(h.SealExcludes()...).Classify(serialised, run.ContentHash, verr))
	}
	return run, nil
}

// InternalDB returns the underlying sqlitestore.DB for testing/wiring.
func (s *Store) InternalDB() sqlitestore.DB {
	return s.db
}

// Ensure Store implements ports.VulnerabilityStore.
var _ ports.VulnerabilityStore = (*Store)(nil)
