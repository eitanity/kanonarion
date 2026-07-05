// Package sqlite implements ports.DirectiveStore using the shared SQLite
// database. The directive module owns its own migration series ("directive",
// versions 1 and 2). v2 makes scan_id the primary key so every scan
// is persisted as its own row (scan history), powering directives-diff.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/directive/domain"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

// Store is the SQLite-backed directive store.
type Store struct {
	db sqlitestore.DB
}

// New returns a Store using the provided shared database handle.
func New(db sqlitestore.DB) *Store { return &Store{db: db} }

// Migrations returns the schema migrations for the directive module.
//
// v1: original "latest record per (project, pipeline)" shape.
// v2: scan history — rebuild as (scan_id PK), keep project+pipeline
// secondary for `directives-list`. Pre-existing rows are migrated by
// synthesising a scan_id derived from content_hash so existing data is not
// dropped.
func Migrations() []sqlitestore.Migration {
	return []sqlitestore.Migration{
		{Module: "directive", Version: 1, SQL: `CREATE TABLE IF NOT EXISTS directive_records (
            project_module_path TEXT NOT NULL,
            pipeline_version    TEXT NOT NULL,
            extracted_at        TEXT NOT NULL,
            content_hash        TEXT NOT NULL,
            serialised          BLOB NOT NULL,
            PRIMARY KEY (project_module_path, pipeline_version)
        )`},
		{Module: "directive", Version: 2, SQL: `
            CREATE TABLE IF NOT EXISTS directive_scans (
                scan_id             TEXT PRIMARY KEY,
                project_module_path TEXT NOT NULL,
                pipeline_version    TEXT NOT NULL,
                started_at          TEXT NOT NULL,
                completed_at        TEXT NOT NULL,
                content_hash        TEXT NOT NULL,
                serialised          BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_directive_scans_project
                ON directive_scans(project_module_path, completed_at DESC);

            -- Synthesise 'legacy-<8 hex>' (skip the 'sha256:'
            -- prefix). v3 retroactively cleans up any installs that ran the
            -- earlier (uglier) form of this migration.
            INSERT OR IGNORE INTO directive_scans (
                scan_id, project_module_path, pipeline_version,
                started_at, completed_at, content_hash, serialised
            )
            SELECT
                'legacy-' || substr(content_hash, 8, 8),
                project_module_path, pipeline_version,
                extracted_at, extracted_at, content_hash, serialised
            FROM directive_records;

            DROP TABLE directive_records;
        `},
		{Module: "directive", Version: 3, SQL: `
            -- Rename the ugly synthetic IDs produced by v2 (which
            -- embedded the redundant 'sha256:' prefix) to a clean
            -- 'legacy-<8 hex>' form. Idempotent: no-op on installs that
            -- never carried the v2 form.
            UPDATE directive_scans
            SET scan_id = 'legacy-' || substr(content_hash, 8, 8)
            WHERE scan_id LIKE 'legacy-sha256:%';
        `},
		// Migration v4: the ecosystem field is now required on read, so every
		// pre-existing blob (which has no ecosystem field) is unreadable under the
		// new schema. Purge the legacy rows; they are regenerable by re-scanning.
		{Module: "directive", Version: 4, SQL: `DELETE FROM directive_scans`},
	}
}

// PutDirectiveRecord inserts (or replaces, when the same scan_id is reused)
// a directive scan record. every invocation produces a new row.
func (s *Store) PutDirectiveRecord(ctx context.Context, r domain.Record) error {
	if r.ID == "" {
		return errors.New("directive record: missing scan ID")
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshalling directive record: %w", err)
	}
	blob := blobcodec.Encode(raw)

	started := r.StartedAt
	if started.IsZero() {
		started = r.ExtractedAt
	}
	completed := r.CompletedAt
	if completed.IsZero() {
		completed = r.ExtractedAt
	}

	const q = `
INSERT INTO directive_scans (
    scan_id, project_module_path, pipeline_version,
    started_at, completed_at, content_hash, serialised
) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (scan_id) DO UPDATE SET
    project_module_path = excluded.project_module_path,
    pipeline_version    = excluded.pipeline_version,
    started_at          = excluded.started_at,
    completed_at        = excluded.completed_at,
    content_hash        = excluded.content_hash,
    serialised          = excluded.serialised`

	if _, err := s.db.DB().ExecContext(ctx, q,
		r.ID, r.ProjectModulePath, r.PipelineVersion,
		started.UTC().Format(time.RFC3339),
		completed.UTC().Format(time.RFC3339),
		r.ContentHash, blob,
	); err != nil {
		return fmt.Errorf("inserting directive scan: %w", err)
	}
	return nil
}

// GetDirectiveRecord returns the most recent scan for a project. found is
// false (no error) when none is stored.
func (s *Store) GetDirectiveRecord(ctx context.Context, projectModulePath string) (domain.Record, bool, error) {
	const q = `SELECT scan_id, completed_at, serialised FROM directive_scans
WHERE project_module_path = ? AND pipeline_version = ?
ORDER BY completed_at DESC, scan_id DESC LIMIT 1`

	row := s.db.DB().QueryRowContext(ctx, q, projectModulePath, domain.PipelineVersion)
	return scanOneRecord(row)
}

// GetScanByID returns the scan record with the given ID.
func (s *Store) GetScanByID(ctx context.Context, scanID string) (domain.Record, bool, error) {
	const q = `SELECT scan_id, completed_at, serialised FROM directive_scans WHERE scan_id = ?`
	row := s.db.DB().QueryRowContext(ctx, q, scanID)
	return scanOneRecord(row)
}

// ListScans returns the most recent scans for a project, newest first.
// limit 0 means unlimited.
func (s *Store) ListScans(ctx context.Context, projectModulePath string, limit int) ([]domain.Record, error) {
	q := `SELECT scan_id, completed_at, serialised FROM directive_scans
WHERE project_module_path = ? AND pipeline_version = ?
ORDER BY completed_at DESC, scan_id DESC`
	args := []any{projectModulePath, domain.PipelineVersion}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := s.db.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("querying directive scans: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []domain.Record
	for rows.Next() {
		var scanID, completedAt string
		var blob []byte
		if err := rows.Scan(&scanID, &completedAt, &blob); err != nil {
			return nil, fmt.Errorf("scanning directive scan row: %w", err)
		}
		rec, err := decodeRecord(scanID, completedAt, blob)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating directive scans: %w", err)
	}
	return out, nil
}

func scanOneRecord(row *sql.Row) (domain.Record, bool, error) {
	var scanID, completedAt string
	var blob []byte
	if err := row.Scan(&scanID, &completedAt, &blob); errors.Is(err, sql.ErrNoRows) {
		return domain.Record{}, false, nil
	} else if err != nil {
		return domain.Record{}, false, fmt.Errorf("querying directive scan: %w", err)
	}
	rec, err := decodeRecord(scanID, completedAt, blob)
	if err != nil {
		return domain.Record{}, false, err
	}
	return rec, true, nil
}

// decodeRecord parses the serialised blob and backfills row-derived metadata
// (scan_id, completed_at) so pre- records — whose JSON predates the
// Record.ID and Record.CompletedAt fields — still report a usable identity
// and timestamp to the application layer.
func decodeRecord(scanID, completedAt string, blob []byte) (domain.Record, error) {
	decoded, decErr := blobcodec.Decode(blob)
	if decErr != nil {
		return domain.Record{}, fmt.Errorf("decompressing directive scan: %w", decErr)
	}
	var rec domain.Record
	if err := json.Unmarshal(decoded, &rec); err != nil {
		return domain.Record{}, fmt.Errorf("unmarshalling directive scan: %w", err)
	}
	if rec.Ecosystem != domain.EcosystemGo {
		return domain.Record{}, fmt.Errorf("%w: got %q, want %q", domain.ErrUnsupportedEcosystem, rec.Ecosystem, domain.EcosystemGo)
	}
	if rec.ID == "" {
		rec.ID = scanID
	}
	if rec.CompletedAt.IsZero() {
		if t, err := time.Parse(time.RFC3339, completedAt); err == nil {
			rec.CompletedAt = t
			if rec.ExtractedAt.IsZero() {
				rec.ExtractedAt = t
			}
		}
	}
	return rec, nil
}
