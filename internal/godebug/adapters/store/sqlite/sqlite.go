// Package sqlite implements ports.GoDebugStore using the shared SQLite
// database. The godebug module owns its own migration series ("godebug",
// version 1), keyed by the project module path: a godebug scan is a property
// of a project, not of a dependency coordinate.
//
// The record is keyed on the *pipeline fingerprint* (pipeline version folded
// with the taxonomy version), not the bare pipeline version: a taxonomy
// revision must transparently re-classify an unchanged project rather than
// return a stale cached verdict.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/godebug/domain"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

// Store is the SQLite-backed godebug store.
type Store struct {
	db sqlitestore.DB
}

// New returns a Store using the provided shared database handle.
func New(db sqlitestore.DB) *Store { return &Store{db: db} }

// Migrations returns the schema migrations for the godebug module.
func Migrations() []sqlitestore.Migration {
	return []sqlitestore.Migration{
		{Module: "godebug", Version: 1, SQL: `CREATE TABLE IF NOT EXISTS godebug_records (
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
		{Module: "godebug", Version: 2, SQL: `DELETE FROM godebug_records`},
	}
}

// PutGoDebugRecord inserts or replaces the record for a project. Idempotent
// on (project_module_path, pipeline_fingerprint).
func (s *Store) PutGoDebugRecord(ctx context.Context, r domain.Record) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshalling godebug record: %w", err)
	}
	blob := blobcodec.Encode(raw)

	const q = `
INSERT INTO godebug_records (
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
		return fmt.Errorf("inserting godebug record: %w", err)
	}
	return nil
}

// GetGoDebugRecord returns the record for a project under the current
// pipeline fingerprint. found is false (no error) when none is stored — a
// project scanned only under an older taxonomy reads as not-analysed, never
// as "no settings".
func (s *Store) GetGoDebugRecord(ctx context.Context, projectModulePath string) (domain.Record, bool, error) {
	const q = `SELECT serialised FROM godebug_records
WHERE project_module_path = ? AND pipeline_fingerprint = ?`

	row := s.db.DB().QueryRowContext(ctx, q, projectModulePath, domain.PipelineFingerprint())
	var blob []byte
	if err := row.Scan(&blob); errors.Is(err, sql.ErrNoRows) {
		return domain.Record{}, false, nil
	} else if err != nil {
		return domain.Record{}, false, fmt.Errorf("querying godebug record: %w", err)
	}

	decoded, decErr := blobcodec.Decode(blob)
	if decErr != nil {
		return domain.Record{}, false, fmt.Errorf("decompressing godebug record: %w", decErr)
	}
	var rec domain.Record
	if err := json.Unmarshal(decoded, &rec); err != nil {
		return domain.Record{}, false, fmt.Errorf("unmarshalling godebug record: %w", err)
	}
	if rec.Ecosystem != domain.EcosystemGo {
		return domain.Record{}, false, fmt.Errorf("%w: got %q, want %q", domain.ErrUnsupportedEcosystem, rec.Ecosystem, domain.EcosystemGo)
	}
	return rec, true, nil
}
