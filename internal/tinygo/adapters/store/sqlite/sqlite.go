// Package sqlite keeps TinyGo release measurements in the shared mirror.db.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/recordstamp"
	"github.com/eitanity/kanonarion/internal/tinygo/domain"
	"github.com/eitanity/kanonarion/internal/tinygo/ports"
)

// Migrations returns the schema migrations of the tinygo module.
func Migrations() []sqlitestore.Migration {
	return []sqlitestore.Migration{
		// v1: one append-only row per measurement of a release archive. The
		// archive is never kept; the manifest is its files' SHA-256, one
		// "<hex>  <path>" line each.
		{Module: "tinygo", Version: 1, SQL: `CREATE TABLE IF NOT EXISTS tinygo_release_measurements (
    tinygo_version   TEXT NOT NULL,
    asset            TEXT NOT NULL,
    url              TEXT NOT NULL,
    published_sha256 TEXT NOT NULL,
    observed_sha256  TEXT NOT NULL,
    outcome          TEXT NOT NULL,
    reason           TEXT NOT NULL DEFAULT '',
    manifest         TEXT NOT NULL DEFAULT '',
    measured_at      TEXT NOT NULL,
    PRIMARY KEY (tinygo_version, asset, measured_at, observed_sha256)
)`},
	}
}

// Store is the SQLite-backed measurement store.
type Store struct{ db sqlitestore.DB }

// New returns a Store over db.
func New(db sqlitestore.DB) *Store { return &Store{db: db} }

// Append adds m. A measurement already held is one row, not an error, so a
// retried write cannot fail a run that succeeded.
func (s *Store) Append(ctx context.Context, m domain.Measurement) error {
	if err := m.Validate(); err != nil {
		return fmt.Errorf("refusing the TinyGo release measurement: %w", err)
	}
	const q = `
INSERT INTO tinygo_release_measurements (
    tinygo_version, asset, url, published_sha256, observed_sha256, outcome, reason, manifest, measured_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (tinygo_version, asset, measured_at, observed_sha256) DO NOTHING`
	if _, err := s.db.DB().ExecContext(ctx, q, m.Version, m.Asset, m.URL, m.PublishedDigest, m.ObservedDigest,
		string(m.Outcome), m.Reason, domain.FormatManifest(m.Manifest), recordstamp.Format(m.MeasuredAt)); err != nil {
		return fmt.Errorf("inserting the TinyGo release measurement: %w", err)
	}
	return nil
}

// Latest returns the measurement of version's asset appended last. Rowid, not
// the stamp, orders: a whole-second stamp sorts after a fractional one inside
// the same second.
func (s *Store) Latest(ctx context.Context, version, asset string) (domain.Measurement, bool, error) {
	const q = `
SELECT tinygo_version, asset, url, published_sha256, observed_sha256, outcome, reason, manifest, measured_at
FROM tinygo_release_measurements WHERE tinygo_version = ? AND asset = ?
ORDER BY rowid DESC LIMIT 1`
	var (
		m                 domain.Measurement
		outcome, manifest string
		measuredAt        string
	)
	err := s.db.DB().QueryRowContext(ctx, q, version, asset).Scan(&m.Version, &m.Asset, &m.URL,
		&m.PublishedDigest, &m.ObservedDigest, &outcome, &m.Reason, &manifest, &measuredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Measurement{}, false, nil
	}
	if err != nil {
		return domain.Measurement{}, false, fmt.Errorf("reading the TinyGo release measurement: %w", err)
	}
	m.Outcome = domain.Outcome(outcome)
	if m.MeasuredAt, err = recordstamp.Parse(measuredAt); err != nil {
		return domain.Measurement{}, false, fmt.Errorf("reading the TinyGo release measurement time: %w", err)
	}
	if m.Manifest, err = domain.ParseManifest(manifest); err != nil {
		return domain.Measurement{}, false, fmt.Errorf("reading the TinyGo release manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return domain.Measurement{}, false, fmt.Errorf("reading the TinyGo release measurement: %w", err)
	}
	return m, true, nil
}

var _ ports.Store = (*Store)(nil)

// Open opens (or creates) the database at dsn with this module's migrations;
// ":memory:" for tests.
func Open(dsn string) (*Store, error) {
	db, err := sqlitestore.Open(dsn, Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		return nil, fmt.Errorf("opening the TinyGo release store: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("closing the TinyGo release store: %w", err)
	}
	return nil
}
