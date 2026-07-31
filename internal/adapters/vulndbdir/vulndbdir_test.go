package vulndbdir_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/vulndbdir"
)

// write creates path with trivial content, making its parents as needed.
func write(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// The measurement is only worth anything if it counts advisories and nothing
// else. Each case here is something that has to NOT be counted for a zero to
// still mean "this database holds no advisories".
func TestCountAdvisories(t *testing.T) {
	t.Parallel()

	t.Run("a database with no ID tree at all counts zero", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		write(t, filepath.Join(dir, "index", "db.json"))
		write(t, filepath.Join(dir, "index", "modules.json"))

		count, err := vulndbdir.CountAdvisories(dir)
		if err != nil {
			t.Fatalf("a well-formed empty database is readable, not an error: %v", err)
		}
		if count != 0 {
			t.Errorf("expected 0 advisories, got %d", count)
		}
	})

	t.Run("advisories are counted", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		write(t, filepath.Join(dir, "index", "db.json"))
		for _, id := range []string{"GO-2026-0001", "GO-2026-0002", "GO-2026-0003"} {
			write(t, filepath.Join(dir, "ID", id+".json"))
		}

		count, err := vulndbdir.CountAdvisories(dir)
		if err != nil {
			t.Fatalf("CountAdvisories: %v", err)
		}
		if count != 3 {
			t.Errorf("expected 3 advisories, got %d", count)
		}
	})

	// A database holding nothing but its own table of contents holds no
	// advisories. Counting the index would report one and turn the empty case
	// into a plausible-looking non-empty one.
	t.Run("the index is not an advisory", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		write(t, filepath.Join(dir, "ID", "index.json"))

		count, err := vulndbdir.CountAdvisories(dir)
		if err != nil {
			t.Fatalf("CountAdvisories: %v", err)
		}
		if count != 0 {
			t.Errorf("an ID tree holding only its index holds no advisories, got %d", count)
		}
	})

	t.Run("non-JSON files are not advisories", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		write(t, filepath.Join(dir, "ID", "README"))
		write(t, filepath.Join(dir, "ID", "GO-2026-0001.json"))

		count, err := vulndbdir.CountAdvisories(dir)
		if err != nil {
			t.Fatalf("CountAdvisories: %v", err)
		}
		if count != 1 {
			t.Errorf("expected 1 advisory, got %d", count)
		}
	})

	// The layout is defined by a prefix and a suffix and has never promised to
	// stay flat, so a nested entry still counts.
	t.Run("a nested ID tree is walked", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		write(t, filepath.Join(dir, "ID", "2026", "GO-2026-0001.json"))
		write(t, filepath.Join(dir, "ID", "GO-2025-0009.json"))

		count, err := vulndbdir.CountAdvisories(dir)
		if err != nil {
			t.Fatalf("CountAdvisories: %v", err)
		}
		if count != 2 {
			t.Errorf("expected 2 advisories, got %d", count)
		}
	})
}
