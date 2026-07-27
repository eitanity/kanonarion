package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/sqlitestore"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// Store implements ports.VulnerabilityStore using SQLite.
type Store struct {
	db sqlitestore.DB
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
	}
}

// PutVulnerabilityRecord persists a vulnerability record.
//
// first_scanned_at is an immutable first-seen anchor: the store, not the
// caller, owns its persistence so the guarantee holds across every write path
// (fresh scan, force re-scan, metadata fallback, reuse re-attribution). When a
// row already exists for the (module, version, pipeline, snapshot) tuple, the
// existing anchor is preserved in both the column (left out of the UPDATE) and
// the serialised blob (which reads return), regardless of what the caller set.
func (s *Store) PutVulnerabilityRecord(ctx context.Context, record domain.VulnerabilityRecord) error {
	// A record whose coordinate is the zero value would key a row on the empty
	// path at the empty version, which every later read treats as a genuine
	// measurement of a module that does not exist.
	if record.Coordinate.IsZero() {
		return coordinate.ErrZeroCoordinate
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
	if existing, ok, err := s.firstScannedAt(ctx, record); err != nil {
		return err
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
    snapshot_source, snapshot_version, walk_id,
    overall_status, finding_count, scanned_at, first_scanned_at,
    content_hash, serialised
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (module_path, module_version, pipeline_version, snapshot_source, snapshot_version)
DO UPDATE SET
    walk_id        = excluded.walk_id,
    overall_status = excluded.overall_status,
    finding_count  = excluded.finding_count,
    scanned_at     = excluded.scanned_at,
    content_hash   = excluded.content_hash,
    serialised     = excluded.serialised`

	_, err = s.db.DB().ExecContext(ctx, q,
		record.Coordinate.Path(), record.Coordinate.Version(), record.PipelineVersion,
		record.DatabaseSnapshot.Source, record.DatabaseSnapshot.Version, record.WalkID,
		string(record.OverallStatus), len(record.Findings),
		record.ScannedAt.UTC().Format(time.RFC3339),
		record.FirstScannedAt.UTC().Format(time.RFC3339),
		record.ContentHash, serialised,
	)
	if err != nil {
		return fmt.Errorf("inserting vulnerability record: %w", err)
	}

	// Populate the findings index for cross-store queries.
	const idxQ = `
INSERT INTO vulnerability_findings_index (
    finding_id, module_path, module_version, pipeline_version,
    snapshot_source, snapshot_version, is_reachable
) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT DO NOTHING`

	for _, f := range record.Findings {
		var isReachable *int
		if f.Reachable != nil {
			v := 0
			if f.Reachable.IsReachable {
				v = 1
			}
			isReachable = &v
		}
		// Index all aliases too (CVE, GHSA, etc.) so queries by any identifier work.
		ids := append([]string{f.ID}, f.Aliases...)
		for _, id := range ids {
			if _, err := s.db.DB().ExecContext(ctx, idxQ,
				id,
				record.Coordinate.Path(), record.Coordinate.Version(), record.PipelineVersion,
				record.DatabaseSnapshot.Source, record.DatabaseSnapshot.Version,
				isReachable,
			); err != nil {
				return fmt.Errorf("inserting finding index entry %s: %w", id, err)
			}
		}
	}
	return nil
}

// firstScannedAt returns the immutable first-seen timestamp already stored for
// record's (module, version, pipeline, snapshot) tuple, if any. ok is false
// when no row exists yet or the stored anchor is empty (a pre-anchor legacy
// row), in which case the caller's own FirstScannedAt stands as the first
// insert.
func (s *Store) firstScannedAt(ctx context.Context, record domain.VulnerabilityRecord) (time.Time, bool, error) {
	const q = `
SELECT first_scanned_at FROM vulnerability_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?
  AND snapshot_source = ? AND snapshot_version = ?`

	var raw string
	err := s.db.DB().QueryRowContext(ctx, q,
		record.Coordinate.Path(), record.Coordinate.Version(), record.PipelineVersion,
		record.DatabaseSnapshot.Source, record.DatabaseSnapshot.Version,
	).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("querying first_scanned_at: %w", err)
	}
	if raw == "" {
		return time.Time{}, false, nil
	}
	t, perr := time.Parse(time.RFC3339, raw)
	if perr != nil {
		return time.Time{}, false, fmt.Errorf("parsing first_scanned_at: %w", perr)
	}
	return t, true, nil
}

// GetVulnerabilityRecord retrieves a vulnerability record.
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
	const q = `
SELECT serialised FROM vulnerability_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?
  AND snapshot_source = ? AND snapshot_version = ?`

	var serialised []byte
	err := s.db.DB().QueryRowContext(ctx, q,
		coord.Path(), coord.Version(), pipelineVersion,
		snapshot.Source, snapshot.Version,
	).Scan(&serialised)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.VulnerabilityRecord{}, false, nil
	}
	if err != nil {
		return domain.VulnerabilityRecord{}, false, fmt.Errorf("querying vulnerability record: %w", err)
	}

	record, derr := decodeRecord(serialised)
	if derr != nil {
		return domain.VulnerabilityRecord{}, false, derr
	}
	return record, true, nil
}

// GetLatestVulnerabilityRecord returns the most recently scanned record for a
// coordinate and pipeline version, regardless of snapshot or walk ID.
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
ORDER BY scanned_at DESC LIMIT 1`

	var serialised []byte
	err := s.db.DB().QueryRowContext(ctx, q,
		coord.Path(), coord.Version(), pipelineVersion,
	).Scan(&serialised)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.VulnerabilityRecord{}, false, nil
	}
	if err != nil {
		return domain.VulnerabilityRecord{}, false, fmt.Errorf("querying latest vulnerability record: %w", err)
	}

	record, derr := decodeRecord(serialised)
	if derr != nil {
		return domain.VulnerabilityRecord{}, false, derr
	}
	return record, true, nil
}

// GetLatestVulnerabilityRecordForWalk returns the most recently scanned record
// for a coordinate and pipeline version that is associated with any scan run
// of the given walk, regardless of snapshot.
func (s *Store) GetLatestVulnerabilityRecordForWalk(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	pipelineVersion string,
	walkID string,
) (domain.VulnerabilityRecord, bool, error) {
	// The zero coordinate names no module, so this is a question about nothing.
	// Answering it with absence would report "no record here" for a module that
	// was never asked about — see coordinate.ErrZeroCoordinate.
	if coord.IsZero() {
		return domain.VulnerabilityRecord{}, false, coordinate.ErrZeroCoordinate
	}
	const q = `
SELECT vr.serialised
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
ORDER BY vr.scanned_at DESC
LIMIT 1`

	var serialised []byte
	err := s.db.DB().QueryRowContext(ctx, q,
		coord.Path(), coord.Version(), pipelineVersion, walkID,
	).Scan(&serialised)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.VulnerabilityRecord{}, false, nil
	}
	if err != nil {
		return domain.VulnerabilityRecord{}, false, fmt.Errorf("querying vulnerability record for walk: %w", err)
	}

	record, derr := decodeRecord(serialised)
	if derr != nil {
		return domain.VulnerabilityRecord{}, false, derr
	}
	return record, true, nil
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
		run.ID, run.WalkID, run.Snapshot.Source, run.Snapshot.Version,
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

	const modQ = `
INSERT INTO walk_scan_run_modules (
    walk_scan_run_id, module_path, module_version,
    pipeline_version, snapshot_source, snapshot_version, walk_id
) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (walk_scan_run_id, module_path, module_version) DO NOTHING`

	for coord := range run.PerModuleResults {
		if _, err = tx.ExecContext(ctx, modQ,
			run.ID, coord.Path(), coord.Version(),
			run.PipelineVersion, run.Snapshot.Source, run.Snapshot.Version, run.WalkID,
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
		return domain.WalkScanRun{}, false, derr
	}
	return run, true, nil
}

// ListWalkScanRuns lists scan runs for a walk.
func (s *Store) ListWalkScanRuns(ctx context.Context, walkID string) ([]domain.WalkScanRun, error) {
	const q = `SELECT serialised FROM walk_scan_runs WHERE walk_id = ? ORDER BY started_at DESC`

	rows, err := s.db.DB().QueryContext(ctx, q, walkID)
	if err != nil {
		return nil, fmt.Errorf("listing walk scan runs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var runs []domain.WalkScanRun
	for rows.Next() {
		var serialised []byte
		if err := rows.Scan(&serialised); err != nil {
			return nil, fmt.Errorf("scanning walk scan run: %w", err)
		}
		run, derr := decodeRun(serialised)
		if derr != nil {
			return nil, derr
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating walk scan runs: %w", err)
	}
	return runs, nil
}

// ListAllWalkScanRuns lists all scan runs across all walks, most recent first.
func (s *Store) ListAllWalkScanRuns(ctx context.Context) ([]domain.WalkScanRun, error) {
	const q = `SELECT serialised FROM walk_scan_runs ORDER BY started_at DESC`

	rows, err := s.db.DB().QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("listing all walk scan runs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var runs []domain.WalkScanRun
	for rows.Next() {
		var serialised []byte
		if err := rows.Scan(&serialised); err != nil {
			return nil, fmt.Errorf("scanning walk scan run: %w", err)
		}
		run, derr := decodeRun(serialised)
		if derr != nil {
			return nil, derr
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating walk scan runs: %w", err)
	}
	return runs, nil
}

// PutDatabaseSnapshot persists a snapshot blob.
func (s *Store) PutDatabaseSnapshot(ctx context.Context, snapshot domain.DatabaseSnapshot, content io.Reader) error {
	data, err := io.ReadAll(content)
	if err != nil {
		return fmt.Errorf("reading snapshot content: %w", err)
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
		snapshot.Source, snapshot.Version,
		snapshot.RetrievedAt.UTC().Format(time.RFC3339),
		snapshot.ContentHash, data,
	)
	if err != nil {
		return fmt.Errorf("inserting database snapshot: %w", err)
	}
	return nil
}

// GetDatabaseSnapshot retrieves a snapshot blob.
func (s *Store) GetDatabaseSnapshot(ctx context.Context, snapshot domain.DatabaseSnapshot) (io.ReadCloser, error) {
	const q = `SELECT content FROM vulnerability_snapshots WHERE source = ? AND version = ?`

	var content []byte
	err := s.db.DB().QueryRowContext(ctx, q, snapshot.Source, snapshot.Version).Scan(&content)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("snapshot not found: %s@%s", snapshot.Source, snapshot.Version)
	}
	if err != nil {
		return nil, fmt.Errorf("querying database snapshot: %w", err)
	}

	return io.NopCloser(bytes.NewReader(content)), nil
}

// GetLatestDatabaseSnapshot returns the most recently stored snapshot metadata.
func (s *Store) GetLatestDatabaseSnapshot(ctx context.Context) (domain.DatabaseSnapshot, bool, error) {
	const q = `SELECT source, version, retrieved_at FROM vulnerability_snapshots ORDER BY retrieved_at DESC LIMIT 1`

	var source, version, retrievedAt string
	err := s.db.DB().QueryRowContext(ctx, q).Scan(&source, &version, &retrievedAt)
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

	return domain.DatabaseSnapshot{
		Source:      source,
		Version:     version,
		RetrievedAt: t,
	}, true, nil
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
		snapshots = append(snapshots, domain.DatabaseSnapshot{
			Source:      source,
			Version:     version,
			RetrievedAt: t,
			ContentHash: contentHash,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating snapshots: %w", err)
	}
	return snapshots, nil
}

// ListVulnerabilityRecordsByFindingID returns the vulnerability records that
// contain a finding with the given identifier.
//
// An empty walkID answers across the whole store: every module version, every
// pipeline version and every snapshot generation ever scanned. When walkID is
// set the answer is restricted to the modules a scan run of that walk covered.
//
// The walk constraint goes through walk_scan_run_modules rather than the
// walk_id column on vulnerability_records: since schema v5 that column is
// provenance for the last walk that triggered the scan, so a record shared by
// two walks names only one of them and filtering on it would drop the other
// walk's module. GetLatestVulnerabilityRecordForWalk takes the same route.
//
// An unknown walkID is an error rather than an empty result: "no modules are
// affected by this CVE" is the wrong answer to give for a walk that was never
// scanned.
func (s *Store) ListVulnerabilityRecordsByFindingID(ctx context.Context, findingID, walkID string) ([]domain.VulnerabilityRecord, error) {
	const unscoped = `
SELECT vr.serialised, vr.scanned_at
FROM vulnerability_records vr
JOIN vulnerability_findings_index fi
  ON fi.module_path      = vr.module_path
 AND fi.module_version   = vr.module_version
 AND fi.pipeline_version = vr.pipeline_version
 AND fi.snapshot_source  = vr.snapshot_source
 AND fi.snapshot_version = vr.snapshot_version
WHERE fi.finding_id = ?
ORDER BY vr.scanned_at DESC`

	// DISTINCT because a walk may hold several scan runs covering the same
	// module; without it one record is reported once per run that touched it.
	const scoped = `
SELECT DISTINCT vr.serialised, vr.scanned_at
FROM vulnerability_records vr
JOIN vulnerability_findings_index fi
  ON fi.module_path      = vr.module_path
 AND fi.module_version   = vr.module_version
 AND fi.pipeline_version = vr.pipeline_version
 AND fi.snapshot_source  = vr.snapshot_source
 AND fi.snapshot_version = vr.snapshot_version
JOIN walk_scan_run_modules m
  ON m.module_path      = vr.module_path
 AND m.module_version   = vr.module_version
 AND m.pipeline_version = vr.pipeline_version
 AND m.snapshot_source  = vr.snapshot_source
 AND m.snapshot_version = vr.snapshot_version
JOIN walk_scan_runs wsr ON wsr.id = m.walk_scan_run_id
WHERE fi.finding_id = ? AND wsr.walk_id = ?
ORDER BY vr.scanned_at DESC`

	q, args := unscoped, []any{findingID}
	if walkID != "" {
		known, err := s.walkHasScanRun(ctx, walkID)
		if err != nil {
			return nil, err
		}
		if !known {
			return nil, fmt.Errorf("no vulnerability scan run for walk %s — run: kanonarion vuln-scan %s", walkID, walkID)
		}
		q, args = scoped, []any{findingID, walkID}
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

	const q = `
SELECT vr.serialised
FROM vulnerability_records vr
JOIN walk_scan_run_modules m
  ON m.module_path      = vr.module_path
 AND m.module_version   = vr.module_version
 AND m.pipeline_version = vr.pipeline_version
 AND m.snapshot_source  = vr.snapshot_source
 AND m.snapshot_version = vr.snapshot_version
WHERE m.walk_scan_run_id = ?
ORDER BY vr.module_path, vr.module_version`

	rows, err := s.db.DB().QueryContext(ctx, q, walkScanRunID)
	if err != nil {
		return nil, fmt.Errorf("listing vulnerability records: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var records []domain.VulnerabilityRecord
	for rows.Next() {
		var serialised []byte
		if err := rows.Scan(&serialised); err != nil {
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

// ListVulnerabilityRecordsForModule returns all stored scan records for a
// coordinate and pipeline version across all walks and snapshots, newest first.
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
ORDER BY scanned_at DESC`

	rows, err := s.db.DB().QueryContext(ctx, q, coord.Path(), coord.Version(), pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("listing vulnerability records for module: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var records []domain.VulnerabilityRecord
	for rows.Next() {
		var serialised []byte
		if err := rows.Scan(&serialised); err != nil {
			return nil, fmt.Errorf("scanning vulnerability record: %w", err)
		}
		rec, derr := decodeRecord(serialised)
		if derr != nil {
			return nil, derr
		}
		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating vulnerability records for module: %w", err)
	}
	return records, nil
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
		return domain.VulnerabilityRecord{}, fmt.Errorf("%w: %s: %w", ports.ErrVulnIntegrity, rec.Coordinate, verr)
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
		return domain.WalkScanRun{}, fmt.Errorf("%w: run %s: %w", ports.ErrVulnIntegrity, run.ID, verr)
	}
	return run, nil
}

// InternalDB returns the underlying sqlitestore.DB for testing/wiring.
func (s *Store) InternalDB() sqlitestore.DB {
	return s.db
}

// Ensure Store implements ports.VulnerabilityStore.
var _ ports.VulnerabilityStore = (*Store)(nil)
