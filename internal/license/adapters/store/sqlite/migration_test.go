package sqlite_test

import (
	"path/filepath"
	"testing"

	licensesqlite "github.com/eitanity/kanonarion/internal/license/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

// TestMigration6_PurgesTheUnverifiableGeneration pins what migration 6 deletes
// and, more importantly, what it does not. The 1.0.0 generation cannot verify
// its own content hashes, so it goes; every other generation is evidence and
// stays. A predicate that purged "anything not current" would have passed a test
// that only checked the 1.0.0 rows were gone.
func TestMigration6_PurgesTheUnverifiableGeneration(t *testing.T) {
	t.Parallel()

	dsn := filepath.Join(t.TempDir(), "mirror.db")

	// Open at migration 5: the schema as it stood when the broken generation was
	// written. Seeding through the store instead would seal each row with the
	// current shape, which is the one thing the 1.0.0 rows demonstrably are not.
	all := licensesqlite.Migrations()
	db, err := sqlitestore.Open(dsn, all[:5])
	if err != nil {
		t.Fatalf("opening at migration 5: %v", err)
	}

	const insert = `INSERT INTO licence_records (
        module_path, module_version, pipeline_version,
        primary_spdx, overall_status, extracted_at, content_hash, serialised
    ) VALUES (?, ?, ?, 'MIT', 1, '2026-01-01T00:00:00Z', 'sha256:stale', x'00')`
	seeded := []struct{ path, version, pipeline string }{
		{"example.com/a", "v1.0.0", "1.0.0"},
		{"example.com/a", "v1.0.0", "1.1.0"},
		{"example.com/b", "v2.0.0", "1.0.0"},
		{"example.com/b", "v2.0.0", "1.1.0"},
		{"example.com/c", "v3.0.0", "1.2.0"},
	}
	for _, s := range seeded {
		if _, err := db.DB().Exec(insert, s.path, s.version, s.pipeline); err != nil {
			t.Fatalf("seeding %s@%s at %s: %v", s.path, s.version, s.pipeline, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing at migration 5: %v", err)
	}

	store, err := licensesqlite.Open(dsn)
	if err != nil {
		t.Fatalf("migrating to head: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	rows, err := store.InternalDB().DB().Query(
		`SELECT pipeline_version, count(*) FROM licence_records GROUP BY 1 ORDER BY 1`)
	if err != nil {
		t.Fatalf("counting by pipeline version: %v", err)
	}
	defer func() { _ = rows.Close() }()

	got := map[string]int{}
	for rows.Next() {
		var pv string
		var n int
		if err := rows.Scan(&pv, &n); err != nil {
			t.Fatalf("scanning: %v", err)
		}
		got[pv] = n
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating: %v", err)
	}

	if n := got["1.0.0"]; n != 0 {
		t.Errorf("licence_records still holds %d rows at pipeline 1.0.0, want 0", n)
	}
	if n := got["1.1.0"]; n != 2 {
		t.Errorf("licence_records holds %d rows at pipeline 1.1.0, want 2 — the purge took evidence with it", n)
	}
	if n := got["1.2.0"]; n != 1 {
		t.Errorf("licence_records holds %d rows at pipeline 1.2.0, want 1 — the purge is not scoped to the generation it measured", n)
	}
}
