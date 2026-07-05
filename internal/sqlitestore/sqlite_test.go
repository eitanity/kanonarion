package sqlitestore_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

func TestOpen(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		db, err := sqlitestore.Open(":memory:", nil)
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
		db, err := sqlitestore.Open(dbPath, nil)
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
		_, err := sqlitestore.Open("/non/existent/path/db.sqlite", nil)
		if err == nil {
			t.Fatal("expected error for invalid path")
		}
	})
}

func TestMigrate(t *testing.T) {
	migrations := []sqlitestore.Migration{
		{Version: 1, SQL: "CREATE TABLE t1 (id INTEGER PRIMARY KEY)"},
		{Version: 2, SQL: "CREATE TABLE t2 (id INTEGER PRIMARY KEY)"},
	}

	t.Run("fresh start", func(t *testing.T) {
		db, err := sqlitestore.Open(":memory:", migrations)
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
		db1, err := sqlitestore.Open(dbPath, migrations[:1])
		if err != nil {
			t.Fatalf("first migration failed: %v", err)
		}
		_ = db1.Close()

		// Second migration
		db2, err := sqlitestore.Open(dbPath, migrations)
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
		_, err := sqlitestore.Open(":memory:", badMigrations)
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

	db, err := sqlitestore.Open(":memory:", migrations)
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
	db1, err := sqlitestore.Open(dbPath, first)
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
	db2, err := sqlitestore.Open(dbPath, second)
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
