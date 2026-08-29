// Package sqlite implements ports.Ledger using the shared SQLite database.
//
// The staleness ledger owns its own migration series ("staleness")
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

	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
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
		// The republication is the module's OWN major published at /vN. It gets
		// its own columns rather than sharing newer_major_*: the two are
		// different facts about different majors, a +incompatible pin can carry
		// both at once, and one set of columns could only hold one of them.
		//
		// republication_asked is separate from major_probe_from for the reason
		// major_probe_from is separate from newer_major_path: the question is
		// only put for a +incompatible pin on a bare path, so "not asked" and
		// "asked, not republished" are different answers and only the second may
		// be reported.
		//
		// The UPDATE moves a same-major answer written by the previous shape out
		// of the newer_major_* columns, where it was rendered as a major-number
		// change that had not happened. It is exact: the walk starts at
		// major_probe_from, so a path it found always names that major or above,
		// and only the same-major question can have written the major BELOW the
		// start. Rows the move does not touch keep republication_asked 0 and are
		// re-probed the next time a pin asks the question — see Resolver.Resolve.
		{Module: "staleness", Version: 2, SQL: `
ALTER TABLE staleness_records ADD COLUMN republication_asked        INTEGER NOT NULL DEFAULT 0;
ALTER TABLE staleness_records ADD COLUMN republication_path         TEXT NOT NULL DEFAULT '';
ALTER TABLE staleness_records ADD COLUMN republication_version      TEXT NOT NULL DEFAULT '';
ALTER TABLE staleness_records ADD COLUMN republication_published_at TEXT NOT NULL DEFAULT '';

UPDATE staleness_records SET
    republication_asked        = 1,
    republication_path         = newer_major_path,
    republication_version      = newer_major_version,
    republication_published_at = newer_major_published_at,
    newer_major_path           = '',
    newer_major_version        = '',
    newer_major_published_at   = ''
WHERE major_probe_from > 1
  AND newer_major_path <> ''
  AND (newer_major_path LIKE '%/v' || (major_probe_from - 1)
    OR newer_major_path LIKE '%.v' || (major_probe_from - 1));`},
		// The module's own deprecation notice — the `// Deprecated:` comment on
		// its go.mod module directive — is a FOURTH fact, and it gets its own
		// columns for the reason the republication got its own: it is a different
		// claim by a different mechanism, and the successor it names is often at
		// a path no /vN walk can reach.
		//
		// deprecation_checked is separate from deprecation_notice for the reason
		// major_probe_from is separate from newer_major_path. The notice is
		// answered only where the answer's source can see it, and an empty notice
		// alone cannot say whether the module declares none or was never asked —
		// which is precisely the absence-as-answer this ledger exists to prevent.
		//
		// No pipeline bump and no back-fill: this table carries neither a content
		// hash nor a pipeline version, and there is nothing stored to derive the
		// notice from. Existing rows keep deprecation_checked = 0, which reads as
		// "not established" and is the truth about them — nothing asked. They
		// acquire the fact the next time their latest is resolved.
		{Module: "staleness", Version: 3, SQL: `
ALTER TABLE staleness_records ADD COLUMN deprecation_checked INTEGER NOT NULL DEFAULT 0;
ALTER TABLE staleness_records ADD COLUMN deprecation_notice  TEXT NOT NULL DEFAULT '';`},
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
    republication_asked, republication_path, republication_version, republication_published_at,
    deprecation_checked, deprecation_notice,
    looked_up_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (module_path) DO UPDATE SET
    latest_version             = excluded.latest_version,
    latest_published_at        = excluded.latest_published_at,
    major_probe_from           = excluded.major_probe_from,
    newer_major_path           = excluded.newer_major_path,
    newer_major_version        = excluded.newer_major_version,
    newer_major_published_at   = excluded.newer_major_published_at,
    republication_asked        = excluded.republication_asked,
    republication_path         = excluded.republication_path,
    republication_version      = excluded.republication_version,
    republication_published_at = excluded.republication_published_at,
    deprecation_checked        = excluded.deprecation_checked,
    deprecation_notice         = excluded.deprecation_notice,
    looked_up_at               = excluded.looked_up_at`

	probeFrom := 0
	if rec.NewerMajor.Probed {
		probeFrom = rec.NewerMajor.FromMajor
	}
	repAsked := 0
	if rec.Republication.Asked {
		repAsked = 1
	}
	depChecked := 0
	if rec.Deprecation.Checked {
		depChecked = 1
	}
	if _, err := s.db.DB().ExecContext(ctx, q,
		rec.ModulePath, rec.LatestVersion, formatTime(rec.LatestPublishedAt),
		probeFrom, rec.NewerMajor.Path, rec.NewerMajor.Version, formatTime(rec.NewerMajor.PublishedAt),
		repAsked, rec.Republication.Path, rec.Republication.Version, formatTime(rec.Republication.PublishedAt),
		depChecked, rec.Deprecation.Notice,
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
       republication_asked, republication_path, republication_version, republication_published_at,
       deprecation_checked, deprecation_notice,
       looked_up_at
FROM staleness_records WHERE module_path = ?`

	var latestVersion, latestPublished, majorPath, majorVersion, majorPublished, lookedUp string
	var repPath, repVersion, repPublished, depNotice string
	var probeFrom, repAsked, depChecked int
	row := s.db.DB().QueryRowContext(ctx, q, path)
	if err := row.Scan(&latestVersion, &latestPublished, &probeFrom,
		&majorPath, &majorVersion, &majorPublished,
		&repAsked, &repPath, &repVersion, &repPublished,
		&depChecked, &depNotice, &lookedUp); errors.Is(err, sql.ErrNoRows) {
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
	repAt, err := parseTime(repPublished)
	if err != nil {
		return domain.Record{}, false, fmt.Errorf("staleness record for %s has an unreadable republication time: %w", path, err)
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
		Republication: domain.Republication{
			Asked:       repAsked != 0,
			Path:        repPath,
			Version:     repVersion,
			PublishedAt: repAt,
		},
		Deprecation: domain.Deprecation{
			Checked: depChecked != 0,
			Notice:  depNotice,
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
