// Package sqlite implements ports.Ledger using the shared SQLite database.
//
// The staleness ledger owns its own migration series ("staleness", version 1)
// rather than joining the fetch series. A fetch record is a sealed, hashed
// custody fact about a specific version that was acquired; a staleness row is a
// mutable, expiring cache of what a proxy currently says about a module PATH.
// They have different keys (path versus coordinate), different lifetimes, and
// different truth conditions, and putting an overwritable row in the fact
// table would put a class of record that cannot be verified where every other
// row can be. A separate module also keeps the two version numbers independent,
// so a ledger change never forces a migration on the fetch pipeline.
//
// Rows are stored as plain columns, not a sealed blob: there is nothing here to
// verify. The only thing that qualifies the row is looked_up_at, and every
// consumer is required to state it.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/eitanity/kanonarion/internal/sqlitestore"
	"github.com/eitanity/kanonarion/internal/staleness/domain"
)

// Store is the SQLite-backed staleness ledger.
type Store struct {
	db sqlitestore.DB
}

// New returns a Store using the provided shared database handle.
func New(db sqlitestore.DB) *Store { return &Store{db: db} }

// Migrations returns the schema migrations for the staleness module.
func Migrations() []sqlitestore.Migration {
	return []sqlitestore.Migration{
		{Module: "staleness", Version: 1, SQL: `CREATE TABLE IF NOT EXISTS staleness_records (
            module_path              TEXT NOT NULL PRIMARY KEY,
            latest_version           TEXT NOT NULL,
            latest_published_at      TEXT NOT NULL DEFAULT '',
            -- major_probe_from is 0 when no probe has run. It is not merged with
            -- an empty newer_major_path: "nobody asked" and "asked, none exists"
            -- are different answers and only the second may be reported.
            major_probe_from         INTEGER NOT NULL DEFAULT 0,
            newer_major_path         TEXT NOT NULL DEFAULT '',
            newer_major_version      TEXT NOT NULL DEFAULT '',
            newer_major_published_at TEXT NOT NULL DEFAULT '',
            looked_up_at             TEXT NOT NULL
        )`},
	}
}

// PutStaleness inserts or replaces the row for rec.ModulePath.
func (s *Store) PutStaleness(ctx context.Context, rec domain.Record) error {
	if rec.ModulePath == "" {
		return errors.New("staleness record has no module path")
	}
	if rec.LatestVersion == "" {
		return fmt.Errorf("staleness record for %s has no latest version", rec.ModulePath)
	}
	if rec.LookedUpAt.IsZero() {
		return fmt.Errorf("staleness record for %s has no lookup time", rec.ModulePath)
	}

	const q = `
INSERT INTO staleness_records (
    module_path, latest_version, latest_published_at,
    major_probe_from, newer_major_path, newer_major_version, newer_major_published_at,
    looked_up_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (module_path) DO UPDATE SET
    latest_version           = excluded.latest_version,
    latest_published_at      = excluded.latest_published_at,
    major_probe_from         = excluded.major_probe_from,
    newer_major_path         = excluded.newer_major_path,
    newer_major_version      = excluded.newer_major_version,
    newer_major_published_at = excluded.newer_major_published_at,
    looked_up_at             = excluded.looked_up_at`

	probeFrom := 0
	if rec.NewerMajor.Probed {
		probeFrom = rec.NewerMajor.FromMajor
	}
	if _, err := s.db.DB().ExecContext(ctx, q,
		rec.ModulePath, rec.LatestVersion, formatTime(rec.LatestPublishedAt),
		probeFrom, rec.NewerMajor.Path, rec.NewerMajor.Version, formatTime(rec.NewerMajor.PublishedAt),
		rec.LookedUpAt.UTC().Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("inserting staleness record for %s: %w", rec.ModulePath, err)
	}
	return nil
}

// GetStaleness returns the stored row for path. found is false, with no error,
// when there is none.
func (s *Store) GetStaleness(ctx context.Context, path string) (domain.Record, bool, error) {
	const q = `SELECT latest_version, latest_published_at,
       major_probe_from, newer_major_path, newer_major_version, newer_major_published_at,
       looked_up_at
FROM staleness_records WHERE module_path = ?`

	var latestVersion, latestPublished, majorPath, majorVersion, majorPublished, lookedUp string
	var probeFrom int
	row := s.db.DB().QueryRowContext(ctx, q, path)
	if err := row.Scan(&latestVersion, &latestPublished, &probeFrom,
		&majorPath, &majorVersion, &majorPublished, &lookedUp); errors.Is(err, sql.ErrNoRows) {
		return domain.Record{}, false, nil
	} else if err != nil {
		return domain.Record{}, false, fmt.Errorf("querying staleness record for %s: %w", path, err)
	}

	lookedUpAt, err := parseTime(lookedUp)
	if err != nil {
		return domain.Record{}, false, fmt.Errorf("staleness record for %s has an unreadable lookup time: %w", path, err)
	}
	latestAt, err := parseTime(latestPublished)
	if err != nil {
		return domain.Record{}, false, fmt.Errorf("staleness record for %s has an unreadable publication time: %w", path, err)
	}
	majorAt, err := parseTime(majorPublished)
	if err != nil {
		return domain.Record{}, false, fmt.Errorf("staleness record for %s has an unreadable major publication time: %w", path, err)
	}

	return domain.Record{
		ModulePath:        path,
		LatestVersion:     latestVersion,
		LatestPublishedAt: latestAt,
		NewerMajor: domain.NewerMajor{
			Probed:      probeFrom > 0,
			FromMajor:   probeFrom,
			Path:        majorPath,
			Version:     majorVersion,
			PublishedAt: majorAt,
		},
		LookedUpAt: lookedUpAt,
	}, true, nil
}

// formatTime renders a timestamp, mapping the zero time to the empty string. A
// module whose publication date the proxy did not supply must not acquire a
// fabricated "0001-01-01" on the way through the store.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}
