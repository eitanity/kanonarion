// Package sqlite implements ports.SBOMStore using a SQLite database.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/eitanity/kanonarion/internal/sbom/domain"
	"github.com/eitanity/kanonarion/internal/sbom/ports"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

// Store is the SQLite-backed SBOM store.
type Store struct {
	db sqlitestore.DB
}

// New returns a new Store using the provided database handle.
func New(db sqlitestore.DB) *Store {
	return &Store{db: db}
}

// Migrations returns the schema migrations for the SBOM module.
func Migrations() []sqlitestore.Migration {
	return []sqlitestore.Migration{
		{Module: "sbom", Version: 1, SQL: `
CREATE TABLE IF NOT EXISTS sbom_records (
    id                  TEXT PRIMARY KEY,
    walk_id             TEXT NOT NULL,
    walk_scan_run_id    TEXT,
    format              TEXT NOT NULL,
    pipeline_version    TEXT NOT NULL,
    generated_at        TEXT NOT NULL,
    content_hash        TEXT NOT NULL,
    content             BLOB NOT NULL,
    operator            TEXT NOT NULL,
    licenses_incomplete INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS sbom_records_walk_idx ON sbom_records(walk_id);
CREATE INDEX IF NOT EXISTS sbom_records_cache_idx
    ON sbom_records(walk_id, walk_scan_run_id, format, pipeline_version);
`},
		// Migration v2: declare the record's ecosystem scope. ContentHash digests
		// the CycloneDX content (not record metadata), so existing rows stay valid
		// and simply backfill to the Go default rather than being purged.
		{Module: "sbom", Version: 2, SQL: `ALTER TABLE sbom_records ADD COLUMN ecosystem TEXT NOT NULL DEFAULT 'go'`},
	}
}

// Open opens (or creates) the SQLite database at dsn and runs migrations.
func Open(dsn string) (*Store, error) {
	db, err := sqlitestore.Open(dsn, Migrations())
	if err != nil {
		return nil, fmt.Errorf("opening sbom store: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("closing sbom store: %w", err)
	}
	return nil
}

// PutSBOMRecord inserts or replaces an SBOM record. Idempotent on ID.
func (s *Store) PutSBOMRecord(ctx context.Context, r domain.SBOMRecord) error {
	scanRunID := sql.NullString{}
	if r.WalkScanRunID != nil {
		scanRunID = sql.NullString{String: *r.WalkScanRunID, Valid: true}
	}
	licensesIncomplete := 0
	if r.LicensesIncomplete {
		licensesIncomplete = 1
	}
	_, err := s.db.DB().ExecContext(ctx, `
INSERT INTO sbom_records
    (id, ecosystem, walk_id, walk_scan_run_id, format, pipeline_version, generated_at,
     content_hash, content, operator, licenses_incomplete)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    ecosystem           = excluded.ecosystem,
    content_hash        = excluded.content_hash,
    content             = excluded.content,
    generated_at        = excluded.generated_at,
    licenses_incomplete = excluded.licenses_incomplete`,
		r.ID, ecosystemOrDefault(r.Ecosystem), r.WalkID, scanRunID, string(r.Format), r.PipelineVersion,
		r.GeneratedAt.UTC().Format(time.RFC3339),
		r.ContentHash, r.Content, r.Operator, licensesIncomplete,
	)
	if err != nil {
		return fmt.Errorf("inserting sbom record %q: %w", r.ID, err)
	}
	return nil
}

// GetSBOMRecord retrieves an SBOM record by ID.
func (s *Store) GetSBOMRecord(ctx context.Context, id string) (domain.SBOMRecord, error) {
	row := s.db.DB().QueryRowContext(ctx, `
SELECT id, ecosystem, walk_id, walk_scan_run_id, format, pipeline_version, generated_at,
       content_hash, content, operator, licenses_incomplete
FROM sbom_records WHERE id = ?`, id)
	r, err := scanRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.SBOMRecord{}, ports.ErrSBOMNotFound
	}
	if err != nil {
		return domain.SBOMRecord{}, fmt.Errorf("querying sbom record %q: %w", id, err)
	}
	return r, nil
}

// ListSBOMRecords returns all SBOM records for a walk, most recent first.
func (s *Store) ListSBOMRecords(ctx context.Context, walkID string) ([]domain.SBOMRecord, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if walkID == "" {
		rows, err = s.db.DB().QueryContext(ctx, `
SELECT id, ecosystem, walk_id, walk_scan_run_id, format, pipeline_version, generated_at,
       content_hash, content, operator, licenses_incomplete
FROM sbom_records
ORDER BY generated_at DESC`)
	} else {
		rows, err = s.db.DB().QueryContext(ctx, `
SELECT id, ecosystem, walk_id, walk_scan_run_id, format, pipeline_version, generated_at,
       content_hash, content, operator, licenses_incomplete
FROM sbom_records WHERE walk_id = ?
ORDER BY generated_at DESC`, walkID)
	}
	if err != nil {
		return nil, fmt.Errorf("listing sbom records: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			err = fmt.Errorf("closing sbom rows: %w", cerr)
		}
	}()
	return scanRecords(rows)
}

// FindSBOMRecord looks up a cached record by (walkID, walkScanRunID, format, pipelineVersion).
func (s *Store) FindSBOMRecord(
	ctx context.Context,
	walkID string,
	walkScanRunID *string,
	format domain.SBOMFormat,
	pipelineVersion string,
) (domain.SBOMRecord, bool, error) {
	var row *sql.Row
	if walkScanRunID == nil {
		row = s.db.DB().QueryRowContext(ctx, `
SELECT id, ecosystem, walk_id, walk_scan_run_id, format, pipeline_version, generated_at,
       content_hash, content, operator, licenses_incomplete
FROM sbom_records
WHERE walk_id = ? AND walk_scan_run_id IS NULL AND format = ? AND pipeline_version = ?
ORDER BY generated_at DESC LIMIT 1`, walkID, string(format), pipelineVersion)
	} else {
		row = s.db.DB().QueryRowContext(ctx, `
SELECT id, ecosystem, walk_id, walk_scan_run_id, format, pipeline_version, generated_at,
       content_hash, content, operator, licenses_incomplete
FROM sbom_records
WHERE walk_id = ? AND walk_scan_run_id = ? AND format = ? AND pipeline_version = ?
ORDER BY generated_at DESC LIMIT 1`, walkID, *walkScanRunID, string(format), pipelineVersion)
	}
	r, err := scanRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.SBOMRecord{}, false, nil
	}
	if err != nil {
		return domain.SBOMRecord{}, false, fmt.Errorf("finding sbom record: %w", err)
	}
	return r, true, nil
}

// ecosystemOrDefault returns the record's ecosystem, defaulting an empty value
// to EcosystemGo so records constructed without it persist with the Go scope.
func ecosystemOrDefault(e string) string {
	if e == "" {
		return domain.EcosystemGo
	}
	return e
}

type scanner interface {
	Scan(dest ...any) error
}

func scanRecord(row scanner) (domain.SBOMRecord, error) {
	var r domain.SBOMRecord
	var scanRunID sql.NullString
	var generatedAtStr string
	var licensesIncomplete int
	if err := row.Scan(
		&r.ID, &r.Ecosystem, &r.WalkID, &scanRunID, &r.Format,
		&r.PipelineVersion, &generatedAtStr,
		&r.ContentHash, &r.Content, &r.Operator, &licensesIncomplete,
	); err != nil {
		return domain.SBOMRecord{}, fmt.Errorf("scanning sbom record: %w", err)
	}
	if r.Ecosystem != domain.EcosystemGo {
		return domain.SBOMRecord{}, fmt.Errorf("%w: got %q, want %q", domain.ErrUnsupportedEcosystem, r.Ecosystem, domain.EcosystemGo)
	}
	if scanRunID.Valid {
		r.WalkScanRunID = &scanRunID.String
	}
	t, err := time.Parse(time.RFC3339, generatedAtStr)
	if err != nil {
		return domain.SBOMRecord{}, fmt.Errorf("parsing generated_at %q: %w", generatedAtStr, err)
	}
	r.GeneratedAt = t.UTC()
	r.LicensesIncomplete = licensesIncomplete != 0
	return r, nil
}

func scanRecords(rows *sql.Rows) ([]domain.SBOMRecord, error) {
	var result []domain.SBOMRecord
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning sbom record row: %w", err)
		}
		result = append(result, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating sbom record rows: %w", err)
	}
	return result, nil
}
