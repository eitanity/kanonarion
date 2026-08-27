package sqlitestore_test

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

func TestOpen(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		db, err := sqlitestore.Open(":memory:", nil, sqlitestore.IntentCreate)
		if err != nil {
			t.Fatalf("failed to open memory db: %v", err)
		}
		if db == nil {
			t.Fatal("expected db to be non-nil")
		}
		if db.DB() == nil {
			t.Fatal("expected internal sql.DB to be non-nil")
		}
		if err := db.Close(); err != nil {
			t.Errorf("failed to close db: %v", err)
		}
	})

	t.Run("file", func(t *testing.T) {
		tmpDir := t.TempDir()
		dbPath := filepath.Join(tmpDir, "test.db")
		db, err := sqlitestore.Open(dbPath, nil, sqlitestore.IntentCreate)
		if err != nil {
			t.Fatalf("failed to open file db: %v", err)
		}
		_ = db.Close()

		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			t.Errorf("expected db file %s to exist", dbPath)
		}
	})

	t.Run("invalid path", func(t *testing.T) {
		// This might not fail on Open because sql.Open is lazy,
		// but our sqlite.Open runs migrations which should trigger it.
		_, err := sqlitestore.Open("/non/existent/path/db.sqlite", nil, sqlitestore.IntentCreate)
		if err == nil {
			t.Fatal("expected error for invalid path")
		}
	})

	// A read intent must leave the disk exactly as it found it. The whole
	// reason the parameter exists is that a directory made to answer a read is
	// a store the caller never asked for, answering truthfully about itself
	// and falsely about the one they meant.
	t.Run("read intent refuses a missing directory", func(t *testing.T) {
		parent := t.TempDir()
		dir := filepath.Join(parent, "typo-store")

		_, err := sqlitestore.Open(filepath.Join(dir, "mirror.db"), nil, sqlitestore.IntentRead)
		if err == nil {
			t.Fatal("opening a database in a directory that does not exist succeeded")
		}
		if !errors.Is(err, sqlitestore.ErrDirMissing) {
			t.Errorf("error = %v, want one wrapping ErrDirMissing so a caller can route on it", err)
		}
		if !strings.Contains(err.Error(), dir) {
			t.Errorf("the refusal does not name the directory it looked at: %v", err)
		}

		if entries, rerr := os.ReadDir(parent); rerr != nil {
			t.Fatalf("reading %s: %v", parent, rerr)
		} else if len(entries) != 0 {
			t.Errorf("the refused open created %d entry/entries under %s", len(entries), parent)
		}
	})

	// The zero value is the refusing one, so a caller that says nothing about
	// its intent cannot create a store by omission.
	t.Run("the zero intent is the refusing one", func(t *testing.T) {
		var zero sqlitestore.Intent
		if zero != sqlitestore.IntentRead {
			t.Errorf("the zero Intent is %v, want IntentRead: a caller that says nothing must not create", zero)
		}
	})

	t.Run("read intent opens an existing directory", func(t *testing.T) {
		dir := t.TempDir()
		db, err := sqlitestore.Open(filepath.Join(dir, "mirror.db"), nil, sqlitestore.IntentRead)
		if err != nil {
			t.Fatalf("a read against an existing directory was refused: %v", err)
		}
		_ = db.Close()
	})
}

func TestMigrate(t *testing.T) {
	migrations := []sqlitestore.Migration{
		{Version: 1, SQL: "CREATE TABLE t1 (id INTEGER PRIMARY KEY)"},
		{Version: 2, SQL: "CREATE TABLE t2 (id INTEGER PRIMARY KEY)"},
	}

	t.Run("fresh start", func(t *testing.T) {
		db, err := sqlitestore.Open(":memory:", migrations, sqlitestore.IntentCreate)
		if err != nil {
			t.Fatalf("failed to open and migrate: %v", err)
		}
		defer func() {
			_ = db.Close()
		}()

		// Verify tables exist
		for _, table := range []string{"t1", "t2", "schema_migrations"} {
			var name string
			err := db.DB().QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
			if err != nil {
				t.Errorf("table %s not found: %v", table, err)
			}
		}

		var version int
		err = db.DB().QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version)
		if err != nil {
			t.Fatalf("failed to query version: %v", err)
		}
		if version != 2 {
			t.Errorf("expected version 2, got %d", version)
		}
	})

	t.Run("incremental", func(t *testing.T) {
		tmpDir := t.TempDir()
		dbPath := filepath.Join(tmpDir, "test.db")

		// First migration
		db1, err := sqlitestore.Open(dbPath, migrations[:1], sqlitestore.IntentCreate)
		if err != nil {
			t.Fatalf("first migration failed: %v", err)
		}
		_ = db1.Close()

		// Second migration
		db2, err := sqlitestore.Open(dbPath, migrations, sqlitestore.IntentCreate)
		if err != nil {
			t.Fatalf("second migration failed: %v", err)
		}
		defer func() {
			_ = db2.Close()
		}()

		var version int
		err = db2.DB().QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version)
		if err != nil {
			t.Fatalf("failed to query version: %v", err)
		}
		if version != 2 {
			t.Errorf("expected version 2, got %d", version)
		}
	})

	t.Run("fail and rollback", func(t *testing.T) {
		badMigrations := []sqlitestore.Migration{
			{Version: 1, SQL: "CREATE TABLE good (id INTEGER PRIMARY KEY)"},
			{Version: 2, SQL: "INVALID SQL"},
		}
		_, err := sqlitestore.Open(":memory:", badMigrations, sqlitestore.IntentCreate)
		if err == nil {
			t.Fatal("expected error for bad migration")
		}

		// Since it's:memory: and Open failed, we can't easily check if 'good' was rolled back
		// without keeping the connection. But the code uses transactions.
	})
}

func TestMigrate_StoreMetaTracking(t *testing.T) {
	migrations := []sqlitestore.Migration{
		{Module: "m", Version: 1, SQL: "CREATE TABLE t1 (id INTEGER PRIMARY KEY)"},
		{Module: "m", Version: 2, SQL: "CREATE TABLE t2 (id INTEGER PRIMARY KEY)"},
	}

	db, err := sqlitestore.Open(":memory:", migrations, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	var schemaVersion string
	err = db.DB().QueryRow(`SELECT value FROM _store_meta WHERE key = 'schema_version'`).Scan(&schemaVersion)
	if err != nil {
		t.Fatalf("querying _store_meta: %v", err)
	}
	if schemaVersion != "2" {
		t.Errorf("schema_version: got %q, want %q", schemaVersion, "2")
	}
}

func TestMigrate_StoreMetaUpdatesOnNewMigration(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	first := []sqlitestore.Migration{
		{Module: "m", Version: 1, SQL: "CREATE TABLE t1 (id INTEGER PRIMARY KEY)"},
	}
	db1, err := sqlitestore.Open(dbPath, first, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	var v1 string
	if err := db1.DB().QueryRow(`SELECT value FROM _store_meta WHERE key = 'schema_version'`).Scan(&v1); err != nil {
		t.Fatalf("reading schema_version after v1: %v", err)
	}
	_ = db1.Close()

	second := []sqlitestore.Migration{
		{Module: "m", Version: 1, SQL: "CREATE TABLE t1 (id INTEGER PRIMARY KEY)"},
		{Module: "m", Version: 2, SQL: "CREATE TABLE t2 (id INTEGER PRIMARY KEY)"},
	}
	db2, err := sqlitestore.Open(dbPath, second, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	var v2 string
	if err := db2.DB().QueryRow(`SELECT value FROM _store_meta WHERE key = 'schema_version'`).Scan(&v2); err != nil {
		t.Fatalf("reading schema_version after v2: %v", err)
	}
	_ = db2.Close()

	if v1 != "1" {
		t.Errorf("after first open: schema_version = %q, want %q", v1, "1")
	}
	if v2 != "2" {
		t.Errorf("after second open: schema_version = %q, want %q", v2, "2")
	}
}

func TestFakeDB(t *testing.T) {
	// FakeDB is just a wrapper, but let's test it for completeness
	sqlDB, _ := sql.Open("sqlite", ":memory:")
	f := &sqlitestore.FakeDB{SqlDB: sqlDB}
	if f.DB() != sqlDB {
		t.Error("FakeDB.DB() returned wrong pointer")
	}
	if err := f.Close(); err != nil {
		t.Errorf("FakeDB.Close() failed: %v", err)
	}

	// Nil SqlDB
	f2 := &sqlitestore.FakeDB{}
	if err := f2.Close(); err != nil {
		t.Errorf("FakeDB.Close() with nil sqlDB failed: %v", err)
	}
}

// TestMigration_GoStepRunsInsideTheSameTransaction pins the two properties the Fn
// hook exists for and would be useless without: it runs, and it runs inside the
// transaction carrying the SQL beside it — so a back-fill that fails leaves the
// schema change it accompanies rolled back rather than half-applied.
func TestMigration_GoStepRunsInsideTheSameTransaction(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "t.db")

	ran := false
	db, err := sqlitestore.Open(dsn, []sqlitestore.Migration{
		{Module: "m", Version: 1, SQL: `CREATE TABLE t (v TEXT NOT NULL DEFAULT '')`},
		{Module: "m", Version: 2, SQL: `INSERT INTO t (v) VALUES ('before')`,
			Fn: func(tx *sql.Tx) error {
				ran = true
				// Visible inside the same transaction: the row the SQL above inserted
				// is readable here, which is what "same transaction" means.
				var v string
				if err := tx.QueryRow(`SELECT v FROM t`).Scan(&v); err != nil {
					return fmt.Errorf("reading the row the SQL step inserted: %w", err)
				}
				if v != "before" {
					return fmt.Errorf("go step could not see the SQL beside it: %q", v)
				}
				if _, err := tx.Exec(`UPDATE t SET v = 'after'`); err != nil {
					return fmt.Errorf("writing from the go step: %w", err)
				}
				return nil
			}},
	}, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if !ran {
		t.Fatal("the go step never ran")
	}
	var v string
	if err := db.DB().QueryRow(`SELECT v FROM t`).Scan(&v); err != nil {
		t.Fatalf("QueryRow: %v", err)
	}
	if v != "after" {
		t.Fatalf("v = %q, want the go step's write to have committed", v)
	}
}

// TestMigration_GoStepFailureRollsBackTheWholeMigration: a half-applied migration
// is a store whose columns disagree with its rows, and the version must not be
// recorded as applied either — otherwise the next open skips it and the store is
// permanently inconsistent.
func TestMigration_GoStepFailureRollsBackTheWholeMigration(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "t.db")

	_, err := sqlitestore.Open(dsn, []sqlitestore.Migration{
		{Module: "m", Version: 1, SQL: `CREATE TABLE t (v TEXT NOT NULL DEFAULT '')`},
		{Module: "m", Version: 2, SQL: `INSERT INTO t (v) VALUES ('x')`,
			Fn: func(*sql.Tx) error { return errors.New("back-fill failed") }},
	}, sqlitestore.IntentCreate)
	if err == nil {
		t.Fatal("a failing go step did not fail the open")
	}
	if !strings.Contains(err.Error(), "back-fill failed") {
		t.Fatalf("error does not name the go step's failure: %v", err)
	}

	// Re-open with only the first migration: the second must not be recorded, and
	// its SQL must not have taken effect.
	db, err := sqlitestore.Open(dsn, []sqlitestore.Migration{
		{Module: "m", Version: 1, SQL: `CREATE TABLE IF NOT EXISTS t (v TEXT NOT NULL DEFAULT '')`},
	}, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	defer func() { _ = db.Close() }()

	var n int
	if err := db.DB().QueryRow(`SELECT COUNT(*) FROM t`).Scan(&n); err != nil {
		t.Fatalf("QueryRow: %v", err)
	}
	if n != 0 {
		t.Fatalf("the failed migration's SQL survived: %d rows", n)
	}
	if err := db.DB().QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE module='m' AND version=2`).Scan(&n); err != nil {
		t.Fatalf("QueryRow: %v", err)
	}
	if n != 0 {
		t.Fatal("the failed migration was recorded as applied")
	}
}
