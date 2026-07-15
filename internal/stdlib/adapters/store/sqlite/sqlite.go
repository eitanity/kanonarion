// Package sqlite implements ports.Store for standard-library facts using the
// shared mirror.db via modernc.org/sqlite (pure Go, no CGO). Facts are keyed by
// the canonical Go version so a tarball is acquired and verified at most once
// per version across projects.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/eitanity/kanonarion/internal/sqlitestore"
	"github.com/eitanity/kanonarion/internal/stdlib/domain"
	"github.com/eitanity/kanonarion/internal/stdlib/ports"
)

// Store is the SQLite-backed standard-library fact store.
type Store struct {
	db sqlitestore.DB
}

// Migrations returns the schema migrations for the stdlib module. Versioning is
// per-module (the schema_migrations key is (module, version)), so this is
// independent of the fetch and walk sequences.
func Migrations() []sqlitestore.Migration {
	return []sqlitestore.Migration{
		{Module: "stdlib", Version: 1, SQL: `CREATE TABLE IF NOT EXISTS stdlib_facts (
            go_version          TEXT PRIMARY KEY,
            zip_sha256          TEXT NOT NULL DEFAULT '',
            zip_sha384          TEXT NOT NULL DEFAULT '',
            zip_sha512          TEXT NOT NULL DEFAULT '',
            published_sha256    TEXT NOT NULL DEFAULT '',
            verification_status TEXT NOT NULL,
            verification_detail TEXT NOT NULL DEFAULT '',
            license_spdx        TEXT NOT NULL DEFAULT '',
            source_url          TEXT NOT NULL DEFAULT '',
            vcs_url             TEXT NOT NULL DEFAULT '',
            vcs_ref             TEXT NOT NULL DEFAULT '',
            vcs_commit          TEXT NOT NULL DEFAULT '',
            content_location    TEXT NOT NULL DEFAULT '',
            acquired_at         TEXT NOT NULL
        )`},
	}
}

// New returns a Store using the provided database handle.
func New(db sqlitestore.DB) *Store { return &Store{db: db} }

// Open opens (or creates) the SQLite database at dsn and runs migrations.
// Use ":memory:" for tests.
func Open(dsn string) (*Store, error) {
	db, err := sqlitestore.Open(dsn, Migrations())
	if err != nil {
		return nil, fmt.Errorf("opening stdlib store: %w", err)
	}
	return &Store{db: db}, nil
}

// Put inserts or replaces the facts for their Go version.
func (s *Store) Put(ctx context.Context, f domain.Facts) error {
	const q = `
INSERT INTO stdlib_facts (
    go_version, zip_sha256, zip_sha384, zip_sha512, published_sha256,
    verification_status, verification_detail, license_spdx, source_url,
    vcs_url, vcs_ref, vcs_commit, content_location, acquired_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (go_version) DO UPDATE SET
    zip_sha256          = excluded.zip_sha256,
    zip_sha384          = excluded.zip_sha384,
    zip_sha512          = excluded.zip_sha512,
    published_sha256    = excluded.published_sha256,
    verification_status = excluded.verification_status,
    verification_detail = excluded.verification_detail,
    license_spdx        = excluded.license_spdx,
    source_url          = excluded.source_url,
    vcs_url             = excluded.vcs_url,
    vcs_ref             = excluded.vcs_ref,
    vcs_commit          = excluded.vcs_commit,
    content_location    = excluded.content_location,
    acquired_at         = excluded.acquired_at`

	_, err := s.db.DB().ExecContext(ctx, q,
		f.GoVersion, f.Digests.SHA256, f.Digests.SHA384, f.Digests.SHA512, f.PublishedSHA256,
		string(f.VerificationStatus), f.VerificationDetail, f.LicenseSPDX, f.SourceURL,
		f.VCSURL, f.VCSRef, f.VCSCommit, f.ContentLocation,
		f.AcquiredAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("inserting stdlib facts: %w", err)
	}
	return nil
}

// Get returns the cached facts for goVersion. The bool is false on a cache miss.
func (s *Store) Get(ctx context.Context, goVersion string) (domain.Facts, bool, error) {
	const q = `
SELECT go_version, zip_sha256, zip_sha384, zip_sha512, published_sha256,
       verification_status, verification_detail, license_spdx, source_url,
       vcs_url, vcs_ref, vcs_commit, content_location, acquired_at
FROM stdlib_facts WHERE go_version = ?`

	row := s.db.DB().QueryRowContext(ctx, q, goVersion)
	var (
		f          domain.Facts
		status     string
		acquiredAt string
	)
	err := row.Scan(
		&f.GoVersion, &f.Digests.SHA256, &f.Digests.SHA384, &f.Digests.SHA512, &f.PublishedSHA256,
		&status, &f.VerificationDetail, &f.LicenseSPDX, &f.SourceURL,
		&f.VCSURL, &f.VCSRef, &f.VCSCommit, &f.ContentLocation, &acquiredAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Facts{}, false, nil
	}
	if err != nil {
		return domain.Facts{}, false, fmt.Errorf("querying stdlib facts: %w", err)
	}
	f.VerificationStatus = domain.VerificationStatus(status)
	t, err := time.Parse(time.RFC3339, acquiredAt)
	if err != nil {
		return domain.Facts{}, false, fmt.Errorf("parsing acquired_at %q: %w", acquiredAt, err)
	}
	f.AcquiredAt = t.UTC()
	return f, true, nil
}

var _ ports.Store = (*Store)(nil)
