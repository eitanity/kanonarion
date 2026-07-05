package sqlitestore

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // register the sqlite3 driver
)

// Migration represents a single schema migration for a specific module.
type Migration struct {
	Module  string
	Version int
	SQL     string
}

// DB is a shared SQLite interface that handles opening the database,
// setting up connection pools, and running migrations.
type DB interface {
	DB() *sql.DB
	Close() error
}

// FakeDB is a mock implementation of DB for testing.
type FakeDB struct {
	SqlDB *sql.DB
}

func (f *FakeDB) DB() *sql.DB { return f.SqlDB }

func (f *FakeDB) Close() error {
	if f.SqlDB != nil {
		if err := f.SqlDB.Close(); err != nil {
			return fmt.Errorf("closing sqlite: %w", err)
		}
	}
	return nil
}

var _ DB = (*FakeDB)(nil)

type db struct {
	sqlDB *sql.DB
}

func (d *db) DB() *sql.DB {
	return d.sqlDB
}

func (d *db) Close() error {
	if d.sqlDB == nil {
		return nil
	}
	if err := d.sqlDB.Close(); err != nil {
		return fmt.Errorf("closing sqlite: %w", err)
	}
	return nil
}

// Open opens (or creates) the SQLite database at dsn and runs migrations.
// Use ":memory:" for tests.
func Open(dsn string, migrations []Migration) (DB, error) {
	if dsn != ":memory:" && !strings.HasPrefix(dsn, "file::memory:") {
		dir := filepath.Dir(dsn)
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("creating directory for sqlite: %w", err)
		}
	}

	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite at %s: %w", dsn, err)
	}
	sqlDB.SetMaxOpenConns(1)

	for _, pragma := range []string{
		// First: bound cross-process lock waits. The store is a single-writer
		// SQLite file shared by every kanonarion invocation; without this a
		// command blocked behind another's write transaction waits forever
		// with no feedback. 10s is long enough for normal short transactions
		// and short enough to fail fast (clear "database is locked") under
		// real contention. Set before migrate so startup DDL is covered too.
		`PRAGMA busy_timeout = 10000`,
		`PRAGMA journal_mode = WAL`,
		`PRAGMA synchronous = NORMAL`,
		`PRAGMA cache_size = -65536`,
		`PRAGMA mmap_size = 268435456`,
		`PRAGMA temp_store = MEMORY`,
	} {
		if _, err := sqlDB.Exec(pragma); err != nil {
			cerr := sqlDB.Close()
			return nil, fmt.Errorf("setting pragma %q: %w", pragma, errors.Join(err, cerr))
		}
	}

	if err := migrate(sqlDB, migrations); err != nil {
		cerr := sqlDB.Close()
		return nil, fmt.Errorf("migrating schema: %w", errors.Join(err, cerr))
	}

	return &db{sqlDB: sqlDB}, nil
}

// New returns a DB interface from an already open *sql.DB.
func New(dbHandle DB) DB {
	return dbHandle
}

func migrate(db *sql.DB, migrations []Migration) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
        module     TEXT NOT NULL,
        version    INTEGER NOT NULL,
        applied_at TEXT NOT NULL,
        PRIMARY KEY (module, version)
    )`); err != nil {
		return fmt.Errorf("creating migrations table: %w", err)
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS _store_meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )`); err != nil {
		return fmt.Errorf("creating _store_meta table: %w", err)
	}

	for _, m := range migrations {
		var exists bool
		err := db.QueryRow(`SELECT 1 FROM schema_migrations WHERE module = ? AND version = ?`, m.Module, m.Version).Scan(&exists)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("checking migration %s v%d: %w", m.Module, m.Version, err)
		}
		if exists {
			continue
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("beginning migration transaction: %w", err)
		}
		if _, err := tx.Exec(m.SQL); err != nil {
			rerr := tx.Rollback()
			return fmt.Errorf("migration %s v%d: %w", m.Module, m.Version, errors.Join(err, rerr))
		}
		if _, err := tx.Exec(
			`INSERT INTO schema_migrations (module, version, applied_at) VALUES (?, ?, ?)`,
			m.Module, m.Version, time.Now().UTC().Format(time.RFC3339),
		); err != nil {
			rerr := tx.Rollback()
			return fmt.Errorf("recording migration %s v%d: %w", m.Module, m.Version, errors.Join(err, rerr))
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing migration %s v%d: %w", m.Module, m.Version, err)
		}
	}

	if _, err := db.Exec(`INSERT OR REPLACE INTO _store_meta (key, value)
        SELECT 'schema_version', CAST(COUNT(*) AS TEXT) FROM schema_migrations`); err != nil {
		return fmt.Errorf("updating schema_version in _store_meta: %w", err)
	}

	return nil
}
