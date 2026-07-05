// Package sqlite implements ports.FactStore using a SQLite database via
// modernc.org/sqlite (pure Go, no CGO). The schema is versioned through a
// schema_migrations table.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

// Store is the SQLite-backed fact store.
type Store struct {
	db sqlitestore.DB
}

// Migrations returns the schema migrations for the fetch module.
func Migrations() []sqlitestore.Migration {
	return []sqlitestore.Migration{
		{Module: "fetch", Version: 1, SQL: `CREATE TABLE IF NOT EXISTS fetch_records (
            module_path         TEXT NOT NULL,
            module_version      TEXT NOT NULL,
            pipeline_version    TEXT NOT NULL,
            schema_version      TEXT NOT NULL,
            module_hash         TEXT NOT NULL,
            go_mod_hash         TEXT NOT NULL,
            git_url             TEXT NOT NULL DEFAULT '',
            git_ref             TEXT NOT NULL DEFAULT '',
            git_commit_hash     TEXT NOT NULL DEFAULT '',
            verification_status TEXT NOT NULL,
            verification_detail TEXT NOT NULL DEFAULT '',
            fetched_at          TEXT NOT NULL,
            content_location    TEXT NOT NULL,
            content_hash        TEXT NOT NULL,
            PRIMARY KEY (module_path, module_version, pipeline_version)
        )`},
		{Module: "fetch", Version: 2, SQL: `ALTER TABLE fetch_records ADD COLUMN retracted BOOLEAN NOT NULL DEFAULT 0`},
		{Module: "fetch", Version: 3, SQL: `ALTER TABLE fetch_records ADD COLUMN go_mod_location TEXT NOT NULL DEFAULT ''`},
		{Module: "fetch", Version: 4, SQL: `ALTER TABLE fetch_records ADD COLUMN ecosystem TEXT NOT NULL DEFAULT 'go'`},
		{Module: "fetch", Version: 5, SQL: `CREATE TABLE IF NOT EXISTS fetch_attestations (
            module_path       TEXT NOT NULL,
            module_version    TEXT NOT NULL,
            pipeline_version  TEXT NOT NULL,
            subject_kind      TEXT NOT NULL,
            subject_algorithm TEXT NOT NULL,
            subject_digest    TEXT NOT NULL,
            bundle            BLOB NOT NULL,
            signed_at         TEXT NOT NULL,
            PRIMARY KEY (module_path, module_version, pipeline_version, subject_kind, subject_digest)
        )`},
	}
}

// New returns a new Store using the provided database handle.
func New(db sqlitestore.DB) *Store {
	return &Store{db: db}
}

// Open opens (or creates) the SQLite database at dsn and runs migrations.
// Use ":memory:" for tests.
func Open(dsn string) (*Store, error) {
	db, err := sqlitestore.Open(dsn, Migrations())
	if err != nil {
		return nil, fmt.Errorf("opening fact store: %w", err)
	}
	return &Store{db: db}, nil
}

// InternalDB returns the underlying sqlite.DB for testing purposes.
func (s *Store) InternalDB() sqlitestore.DB {
	return s.db
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("closing fact store: %w", err)
	}
	return nil
}

// PutFetchRecord inserts or replaces a fact record. Idempotent on
// (module_path, module_version, pipeline_version).
func (s *Store) PutFetchRecord(ctx context.Context, r domain2.FactRecord) error {
	const q = `
INSERT INTO fetch_records (
    module_path, module_version, pipeline_version,
    schema_version, ecosystem, module_hash, go_mod_hash,
    git_url, git_ref, git_commit_hash,
    verification_status, verification_detail,
    fetched_at, content_location, go_mod_location, content_hash, retracted
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (module_path, module_version, pipeline_version)
DO UPDATE SET
    schema_version      = excluded.schema_version,
    ecosystem           = excluded.ecosystem,
    module_hash         = excluded.module_hash,
    go_mod_hash         = excluded.go_mod_hash,
    git_url             = excluded.git_url,
    git_ref             = excluded.git_ref,
    git_commit_hash     = excluded.git_commit_hash,
    verification_status = excluded.verification_status,
    verification_detail = excluded.verification_detail,
    fetched_at          = excluded.fetched_at,
    content_location    = excluded.content_location,
    go_mod_location     = excluded.go_mod_location,
    content_hash        = excluded.content_hash,
    retracted           = excluded.retracted`

	_, err := s.db.DB().ExecContext(ctx, q,
		r.ModulePath, r.ModuleVersion, r.PipelineVersion,
		r.SchemaVersion, r.Ecosystem, r.ModuleHash, r.GoModHash,
		r.GitURL, r.GitRef, r.GitCommitHash,
		r.VerificationStatus, r.VerificationDetail,
		r.FetchedAt.UTC().Format(time.RFC3339),
		r.ContentLocation, r.GoModLocation, r.ContentHash, r.Retracted,
	)
	if err != nil {
		return fmt.Errorf("inserting fetch record: %w", err)
	}
	return nil
}

// GetFetchRecord retrieves and tamper-checks the fact record for the given
// coordinate and pipeline version. Returns (zero, false, nil) if not found or
// if the content hash does not match (treated as cache miss, triggering
// re-fetch). Returns (zero, false, error) on DB error.
func (s *Store) GetFetchRecord(ctx context.Context, coord domain2.ModuleCoordinate, pipelineVersion string) (domain2.FactRecord, bool, error) {
	const q = `
SELECT schema_version, ecosystem, module_path, module_version, pipeline_version,
       module_hash, go_mod_hash, git_url, git_ref, git_commit_hash,
       verification_status, verification_detail,
       fetched_at, content_location, go_mod_location, content_hash, retracted
FROM fetch_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?`

	row := s.db.DB().QueryRowContext(ctx, q, coord.Path, coord.Version, pipelineVersion)
	var r domain2.FactRecord
	var fetchedAt string
	err := row.Scan(
		&r.SchemaVersion, &r.Ecosystem, &r.ModulePath, &r.ModuleVersion, &r.PipelineVersion,
		&r.ModuleHash, &r.GoModHash, &r.GitURL, &r.GitRef, &r.GitCommitHash,
		&r.VerificationStatus, &r.VerificationDetail,
		&fetchedAt, &r.ContentLocation, &r.GoModLocation, &r.ContentHash, &r.Retracted,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return domain2.FactRecord{}, false, nil
	}
	if err != nil {
		return domain2.FactRecord{}, false, fmt.Errorf("querying fetch record: %w", err)
	}
	t, err := time.Parse(time.RFC3339, fetchedAt)
	if err != nil {
		return domain2.FactRecord{}, false, fmt.Errorf("parsing fetched_at %q: %w", fetchedAt, err)
	}
	r.FetchedAt = t.UTC()

	// Tamper-detection (T9): verify content hash before returning cached record.
	var h domain2.CanonicalHasher
	if err := h.VerifyContentHash(r); err != nil {
		// Record is corrupt or tampered; treat as absent so it is re-fetched.
		return domain2.FactRecord{}, false, nil //nolint:nilerr
	}
	return r, true, nil
}

// PutAttestation inserts or replaces a provenance attestation. Idempotent on
// (module_path, module_version, pipeline_version, subject_kind, subject_digest).
func (s *Store) PutAttestation(ctx context.Context, r domain2.AttestationRecord) error {
	const q = `
INSERT INTO fetch_attestations (
    module_path, module_version, pipeline_version,
    subject_kind, subject_algorithm, subject_digest, bundle, signed_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (module_path, module_version, pipeline_version, subject_kind, subject_digest)
DO UPDATE SET
    subject_algorithm = excluded.subject_algorithm,
    bundle            = excluded.bundle,
    signed_at         = excluded.signed_at`

	_, err := s.db.DB().ExecContext(ctx, q,
		r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion,
		string(r.SubjectKind), r.SubjectAlgorithm, r.SubjectDigest, r.Bundle,
		r.SignedAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("inserting attestation: %w", err)
	}
	return nil
}

// ListAttestations returns all attestations for a coordinate and pipeline
// version in deterministic order.
func (s *Store) ListAttestations(ctx context.Context, coord domain2.ModuleCoordinate, pipelineVersion string) ([]domain2.AttestationRecord, error) {
	const q = `
SELECT subject_kind, subject_algorithm, subject_digest, bundle, signed_at
FROM fetch_attestations
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?
ORDER BY subject_kind, subject_digest`

	rows, err := s.db.DB().QueryContext(ctx, q, coord.Path, coord.Version, pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("querying attestations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []domain2.AttestationRecord
	for rows.Next() {
		var (
			kind, algo, digest, signedAt string
			bundle                       []byte
		)
		if err := rows.Scan(&kind, &algo, &digest, &bundle, &signedAt); err != nil {
			return nil, fmt.Errorf("scanning attestation: %w", err)
		}
		t, perr := time.Parse(time.RFC3339, signedAt)
		if perr != nil {
			return nil, fmt.Errorf("parsing signed_at %q: %w", signedAt, perr)
		}
		out = append(out, domain2.AttestationRecord{
			Coordinate:       coord,
			PipelineVersion:  pipelineVersion,
			SubjectKind:      domain2.SubjectKind(kind),
			SubjectAlgorithm: algo,
			SubjectDigest:    digest,
			Bundle:           bundle,
			SignedAt:         t.UTC(),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating attestations: %w", err)
	}
	return out, nil
}

// Ensure Store implements ports.FactStore and ports.AttestationStore at compile time.
var (
	_ ports.FactStore        = (*Store)(nil)
	_ ports.AttestationStore = (*Store)(nil)
)
