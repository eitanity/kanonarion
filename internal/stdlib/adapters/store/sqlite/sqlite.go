// Package sqlite implements ports.Store for standard-library facts using the
// shared mirror.db via modernc.org/sqlite (pure Go, no CGO). Facts are keyed by
// the canonical Go version so a tarball is acquired and verified at most once
// per version across projects.
package sqlite

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
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
		// Migration v2: stdlib_facts becomes an append-only ledger.
		//
		// The table was keyed on go_version alone, so every acquisition REPLACED its
		// predecessor. That is the defect: one transient go.dev/dl failure records the
		// standard library as UnverifiedGoDevUnavailable, and because the cache check
		// returns any stored row regardless of status, the downgrade is then served on
		// every later run until --force. The evidence that a stronger anchor was ever
		// established is gone, not merely unserved.
		//
		// THE KEY. (go_version, acquisition_route, digest_sha256, acquired_at,
		// content_hash). The route and the digest are the identity — which bytes, and
		// which way in — and the time plus the seal make two distinct measurements two
		// rows. The shipped fetch ledger uses exactly this shape, and it is not the
		// artefact identity alone: keyed on identity only, a re-measurement of the same
		// bytes with a STRONGER anchor could not be stored at all, which is the case
		// this conversion exists to fix.
		//
		// THE NEW COLUMNS. acquisition_route and content_hash are back-filled '' and
		// that is honest for both: neither was ever recorded, so the existing row
		// genuinely says nothing about its route and carries no seal. It is a
		// first-generation row, readable throughout, and it gains both on its next
		// re-acquisition. (Contrast a column denormalised from a value already inside a
		// record, where '' would contradict the row it copies.)
		//
		// NO PURGE. The one existing row carries in. Nothing is deleted.
		{Module: "stdlib", Version: 2, SQL: `
CREATE TABLE stdlib_facts_ledger (
    go_version          TEXT NOT NULL,
    acquisition_route   TEXT NOT NULL DEFAULT '',
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
    acquired_at         TEXT NOT NULL,
    content_hash        TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (go_version, acquisition_route, zip_sha256, acquired_at, content_hash)
);

INSERT INTO stdlib_facts_ledger (
    go_version, zip_sha256, zip_sha384, zip_sha512, published_sha256,
    verification_status, verification_detail, license_spdx, source_url,
    vcs_url, vcs_ref, vcs_commit, content_location, acquired_at
)
SELECT
    go_version, zip_sha256, zip_sha384, zip_sha512, published_sha256,
    verification_status, verification_detail, license_spdx, source_url,
    vcs_url, vcs_ref, vcs_commit, content_location, acquired_at
FROM stdlib_facts;

DROP TABLE stdlib_facts;
ALTER TABLE stdlib_facts_ledger RENAME TO stdlib_facts;

CREATE INDEX IF NOT EXISTS stdlib_facts_generation_idx
    ON stdlib_facts(go_version, acquired_at)`},
	}
}

// New returns a Store using the provided database handle.
func New(db sqlitestore.DB) *Store { return &Store{db: db} }

// Open opens (or creates) the SQLite database at dsn and runs migrations.
// Use ":memory:" for tests.
func Open(dsn string) (*Store, error) {
	db, err := sqlitestore.Open(dsn, Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		return nil, fmt.Errorf("opening stdlib store: %w", err)
	}
	return &Store{db: db}, nil
}

// Put APPENDS a measurement to the ledger.
//
// It never updates. The key carries the acquisition route, the artefact digest,
// the time of measurement and the measurement's own seal, so two distinct
// acquisitions are always two rows; the same measurement written twice is a
// no-op, because it is one measurement rather than two — and it must not be an
// error, or a retried write would fail a run that had already succeeded.
func (s *Store) Put(ctx context.Context, f domain.Facts) error {
	if f.GoVersion == "" {
		// A row keyed on the empty version reads back later as a genuine measurement
		// of a toolchain that does not exist, on the same terms the coordinate stores
		// refuse the zero coordinate.
		return domain.ErrNoGoVersion
	}
	var h domain.FactsHasher
	if err := h.VerifyContentHash(f); err != nil {
		return fmt.Errorf("verifying stdlib facts seal before put: %w", err)
	}

	const q = `
INSERT INTO stdlib_facts (
    go_version, acquisition_route, zip_sha256, zip_sha384, zip_sha512, published_sha256,
    verification_status, verification_detail, license_spdx, source_url,
    vcs_url, vcs_ref, vcs_commit, content_location, acquired_at, content_hash
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (go_version, acquisition_route, zip_sha256, acquired_at, content_hash)
DO NOTHING`

	_, err := s.db.DB().ExecContext(ctx, q,
		f.GoVersion, string(f.AcquisitionRoute),
		f.Digests.SHA256, f.Digests.SHA384, f.Digests.SHA512, f.PublishedSHA256,
		string(f.VerificationStatus), f.VerificationDetail, f.LicenseSPDX, f.SourceURL,
		f.VCSURL, f.VCSRef, f.VCSCommit, f.ContentLocation,
		f.AcquiredAt.UTC().Format(time.RFC3339), f.ContentHash,
	)
	if err != nil {
		return fmt.Errorf("inserting stdlib facts: %w", err)
	}
	return nil
}

// Get returns the COMPOSED facts for goVersion. The bool is false when the
// ledger holds none.
//
// Composition serves the most definite anchor, then the most recent — see
// domain.Compose. Recency alone never wins: a run that could not reach go.dev/dl
// states nothing about the published checksum, so it must not displace a run that
// matched it, which is the overwrite this conversion removed.
func (s *Store) Get(ctx context.Context, goVersion string) (domain.Facts, bool, error) {
	return s.composeFor(ctx, goVersion, domain.ComposeRequest{})
}

// GetVia answers the same question as Get but restricted to one acquisition
// route, so a caller that specifically wants the local toolchain's custody — or
// specifically the published tarball's — can ask for it rather than take the
// default.
func (s *Store) GetVia(ctx context.Context, goVersion string, route domain.AcquisitionRoute) (domain.Facts, bool, error) {
	return s.composeFor(ctx, goVersion, domain.ComposeRequest{Route: route})
}

func (s *Store) composeFor(ctx context.Context, goVersion string, req domain.ComposeRequest) (domain.Facts, bool, error) {
	measurements, err := s.ListFactsFor(ctx, goVersion)
	if err != nil {
		return domain.Facts{}, false, err
	}
	if len(measurements) == 0 {
		return domain.Facts{}, false, nil
	}
	composed, err := domain.Compose(measurements, req)
	if errors.Is(err, domain.ErrNoFactsToCompose) {
		// The ledger holds measurements, but none via the route asked for. That is an
		// absence of an answer to THIS question, not a failure.
		return domain.Facts{}, false, nil
	}
	if err != nil {
		return domain.Facts{}, false, fmt.Errorf("%w: %w", ports.ErrFactsConflict, err)
	}
	return composed, true, nil
}

// ListFactsFor returns every measurement the ledger holds for one toolchain
// version, in the order they were appended, each with its seal verified.
//
// This is what makes the ledger observable: a downgrade that was previously
// invisible — because it had replaced the record it downgraded — is now a row
// beside the one it lost to.
//
// The secondary sort is the row id, not the content hash. acquired_at persists at
// second precision, which is the precision the seal covers, so two acquisitions
// within one second carry the same timestamp and only insertion order separates
// them.
func (s *Store) ListFactsFor(ctx context.Context, goVersion string) ([]domain.Facts, error) {
	if goVersion == "" {
		return nil, domain.ErrNoGoVersion
	}
	const q = `
SELECT go_version, acquisition_route, zip_sha256, zip_sha384, zip_sha512, published_sha256,
       verification_status, verification_detail, license_spdx, source_url,
       vcs_url, vcs_ref, vcs_commit, content_location, acquired_at, content_hash
FROM stdlib_facts WHERE go_version = ?
ORDER BY acquired_at ASC, rowid ASC`

	rows, err := s.db.DB().QueryContext(ctx, q, goVersion)
	if err != nil {
		return nil, fmt.Errorf("querying stdlib facts: %w", err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck // rows.Err() checked below
	}()

	var out []domain.Facts
	var h domain.FactsHasher
	for rows.Next() {
		var (
			f             domain.Facts
			status, route string
			acquiredAt    string
		)
		if serr := rows.Scan(
			&f.GoVersion, &route, &f.Digests.SHA256, &f.Digests.SHA384, &f.Digests.SHA512, &f.PublishedSHA256,
			&status, &f.VerificationDetail, &f.LicenseSPDX, &f.SourceURL,
			&f.VCSURL, &f.VCSRef, &f.VCSCommit, &f.ContentLocation, &acquiredAt, &f.ContentHash,
		); serr != nil {
			return nil, fmt.Errorf("scanning stdlib facts: %w", serr)
		}
		f.VerificationStatus = domain.VerificationStatus(status)
		f.AcquisitionRoute = domain.AcquisitionRoute(route)
		t, perr := time.Parse(time.RFC3339, acquiredAt)
		if perr != nil {
			return nil, fmt.Errorf("parsing acquired_at %q: %w", acquiredAt, perr)
		}
		f.AcquiredAt = t.UTC()
		// A row written before the seal existed carries none and verifies vacuously;
		// one that carries a seal must match it, or the row was altered after it was
		// written and must not be served as evidence.
		if verr := h.VerifyContentHash(f); verr != nil {
			return nil, fmt.Errorf("%w: %s: %w", ports.ErrFactsIntegrity, f.GoVersion, verr)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating stdlib facts: %w", err)
	}
	return out, nil
}

var (
	_ ports.Store       = (*Store)(nil)
	_ ports.FactsLister = (*Store)(nil)
	_ ports.RouteReader = (*Store)(nil)
)
