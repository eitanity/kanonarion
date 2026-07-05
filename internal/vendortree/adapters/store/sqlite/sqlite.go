// Package sqlite implements ports.VendorStore using the shared SQLite
// database. The vendor module owns its own migration series ("vendor",
// version 1), keyed by the project module path: a vendored-closure scan is a
// property of a project, not of a dependency coordinate.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
	"github.com/eitanity/kanonarion/internal/vendortree/domain"
)

// Store is the SQLite-backed vendor store.
type Store struct {
	db sqlitestore.DB
}

// New returns a Store using the provided shared database handle.
func New(db sqlitestore.DB) *Store { return &Store{db: db} }

// Migrations returns the schema migrations for the vendor module.
func Migrations() []sqlitestore.Migration {
	return []sqlitestore.Migration{
		{Module: "vendor", Version: 1, SQL: `CREATE TABLE IF NOT EXISTS vendor_records (
            project_module_path TEXT NOT NULL,
            pipeline_version    TEXT NOT NULL,
            extracted_at        TEXT NOT NULL,
            content_hash        TEXT NOT NULL,
            serialised          BLOB NOT NULL,
            PRIMARY KEY (project_module_path, pipeline_version)
        )`},
		// Migration v2: the ecosystem field is now required on read, so every
		// pre-existing blob (which has no ecosystem field) is unreadable under the
		// new schema. Purge the legacy rows; they are regenerable by re-scanning.
		{Module: "vendor", Version: 2, SQL: `DELETE FROM vendor_records`},
	}
}

// PutVendorRecord inserts or replaces the record for a project. Idempotent
// on (project_module_path, pipeline_version).
func (s *Store) PutVendorRecord(ctx context.Context, r domain.Record) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshalling vendor record: %w", err)
	}
	blob := blobcodec.Encode(raw)

	const q = `
INSERT INTO vendor_records (
    project_module_path, pipeline_version, extracted_at, content_hash, serialised
) VALUES (?, ?, ?, ?, ?)
ON CONFLICT (project_module_path, pipeline_version) DO UPDATE SET
    extracted_at = excluded.extracted_at,
    content_hash = excluded.content_hash,
    serialised   = excluded.serialised`

	if _, err := s.db.DB().ExecContext(ctx, q,
		r.ProjectModulePath, r.PipelineVersion,
		r.ExtractedAt.UTC().Format(time.RFC3339),
		r.ContentHash, blob,
	); err != nil {
		return fmt.Errorf("inserting vendor record: %w", err)
	}
	return nil
}

// GetVendorRecord returns the latest-pipeline record for a project module
// path. found is false (no error) when none is stored.
func (s *Store) GetVendorRecord(ctx context.Context, projectModulePath string) (domain.Record, bool, error) {
	const q = `SELECT serialised FROM vendor_records
WHERE project_module_path = ? AND pipeline_version = ?`

	row := s.db.DB().QueryRowContext(ctx, q, projectModulePath, domain.PipelineVersion)
	var blob []byte
	if err := row.Scan(&blob); errors.Is(err, sql.ErrNoRows) {
		return domain.Record{}, false, nil
	} else if err != nil {
		return domain.Record{}, false, fmt.Errorf("querying vendor record: %w", err)
	}

	decoded, decErr := blobcodec.Decode(blob)
	if decErr != nil {
		return domain.Record{}, false, fmt.Errorf("decompressing vendor record: %w", decErr)
	}
	var rec domain.Record
	if err := json.Unmarshal(decoded, &rec); err != nil {
		return domain.Record{}, false, fmt.Errorf("unmarshalling vendor record: %w", err)
	}
	if rec.Ecosystem != domain.EcosystemGo {
		return domain.Record{}, false, fmt.Errorf("%w: got %q, want %q", domain.ErrUnsupportedEcosystem, rec.Ecosystem, domain.EcosystemGo)
	}
	return rec, true, nil
}
