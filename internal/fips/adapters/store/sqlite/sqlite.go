// Package sqlite implements ports.FIPSStore using the shared SQLite
// database. The fips module owns its own migration series ("fips", version
// 1), keyed by the project module path: a FIPS assessment is a property of
// a project, not of a dependency coordinate.
//
// The record is keyed on the *pipeline fingerprint* (pipeline version
// folded with the catalogue version), not the bare pipeline version: a
// catalogue revision must transparently re-classify an unchanged project
// rather than return a stale cached verdict ( mirroring).
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/fips/domain"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

// Store is the SQLite-backed FIPS store.
type Store struct {
	db sqlitestore.DB
}

// New returns a Store using the provided shared database handle.
func New(db sqlitestore.DB) *Store { return &Store{db: db} }

// Migrations returns the schema migrations for the fips module.
func Migrations() []sqlitestore.Migration {
	return []sqlitestore.Migration{
		{Module: "fips", Version: 1, SQL: `CREATE TABLE IF NOT EXISTS fips_records (
            project_module_path  TEXT NOT NULL,
            pipeline_fingerprint TEXT NOT NULL,
            extracted_at         TEXT NOT NULL,
            content_hash         TEXT NOT NULL,
            serialised           BLOB NOT NULL,
            PRIMARY KEY (project_module_path, pipeline_fingerprint)
        )`},
		// Migration v2: the ecosystem field is now required on read, so every
		// pre-existing blob (which has no ecosystem field) is unreadable under the
		// new schema. Purge the legacy rows; they are regenerable by re-scanning.
		{Module: "fips", Version: 2, SQL: `DELETE FROM fips_records`},
	}
}

// PutFIPSRecord inserts or replaces the record for a project. Idempotent
// on (project_module_path, pipeline_fingerprint).
func (s *Store) PutFIPSRecord(ctx context.Context, r domain.Record) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshalling fips record: %w", err)
	}
	blob := blobcodec.Encode(raw)

	const q = `
INSERT INTO fips_records (
    project_module_path, pipeline_fingerprint, extracted_at, content_hash, serialised
) VALUES (?, ?, ?, ?, ?)
ON CONFLICT (project_module_path, pipeline_fingerprint) DO UPDATE SET
    extracted_at = excluded.extracted_at,
    content_hash = excluded.content_hash,
    serialised   = excluded.serialised`

	if _, err := s.db.DB().ExecContext(ctx, q,
		r.ProjectModulePath, domain.PipelineFingerprint(),
		r.ExtractedAt.UTC().Format(time.RFC3339),
		r.ContentHash, blob,
	); err != nil {
		return fmt.Errorf("inserting fips record: %w", err)
	}
	return nil
}

// GetFIPSRecord returns the record for a project under the current pipeline
// fingerprint. found is false (no error) when none is stored — a project
// scanned only under an older catalogue reads as not-analysed, never as
// "no FIPS issues".
func (s *Store) GetFIPSRecord(ctx context.Context, projectModulePath string) (domain.Record, bool, error) {
	const q = `SELECT serialised FROM fips_records
WHERE project_module_path = ? AND pipeline_fingerprint = ?`

	row := s.db.DB().QueryRowContext(ctx, q, projectModulePath, domain.PipelineFingerprint())
	var blob []byte
	if err := row.Scan(&blob); errors.Is(err, sql.ErrNoRows) {
		return domain.Record{}, false, nil
	} else if err != nil {
		return domain.Record{}, false, fmt.Errorf("querying fips record: %w", err)
	}

	decoded, decErr := blobcodec.Decode(blob)
	if decErr != nil {
		return domain.Record{}, false, fmt.Errorf("decompressing fips record: %w", decErr)
	}
	var rec domain.Record
	if err := json.Unmarshal(decoded, &rec); err != nil {
		return domain.Record{}, false, fmt.Errorf("unmarshalling fips record: %w", err)
	}
	if rec.Ecosystem != domain.EcosystemGo {
		return domain.Record{}, false, fmt.Errorf("%w: got %q, want %q", domain.ErrUnsupportedEcosystem, rec.Ecosystem, domain.EcosystemGo)
	}
	return rec, true, nil
}
