package modcache_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/modcache"
)

// writeReadOnlyModCache builds a directory tree that mimics a Go module cache:
// a read-only file inside a read-only directory. It returns the root.
func writeReadOnlyModCache(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	cache := filepath.Join(root, "cache")
	sub := filepath.Join(cache, "download", "example.com", "@v")
	if err := os.MkdirAll(sub, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	file := filepath.Join(sub, "v1.0.0.zip")
	if err := os.WriteFile(file, []byte("zipdata"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Make the entries read-only the way the Go toolchain does: file 0o444,
	// containing directory 0o555 (no write bit). os.RemoveAll cannot unlink a
	// child of a read-only directory — this is the leak being reproduced.
	if err := os.Chmod(file, 0o444); err != nil { // #nosec G302 -- read-only is the fixture
		t.Fatalf("Chmod file: %v", err)
	}
	if err := os.Chmod(sub, 0o555); err != nil { // #nosec G302 -- read-only is the fixture
		t.Fatalf("Chmod dir: %v", err)
	}
	return cache
}

func TestRemove_ReadOnlyModCache(t *testing.T) {
	cache := writeReadOnlyModCache(t)

	if err := modcache.Remove(cache); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Fatalf("cache dir still present after Remove: stat err = %v", err)
	}
}

// TestRemove_PlainRemoveAllFails proves the read-only fixture genuinely defeats a
// naive os.RemoveAll — i.e. that Remove's chmod pass is load-bearing, not
// redundant. (Skipped for root, which ignores permission bits.)
func TestRemove_PlainRemoveAllFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits are not enforced")
	}
	cache := writeReadOnlyModCache(t)
	if err := os.RemoveAll(cache); err == nil {
		t.Fatal("expected os.RemoveAll to fail on a read-only module cache tree; " +
			"if this passes, the fixture no longer reproduces the leak")
	}
	// Clean up the fixture via the real helper so t.TempDir removal succeeds.
	if err := modcache.Remove(cache); err != nil {
		t.Fatalf("cleanup Remove: %v", err)
	}
}

func TestRemove_EmptyDirIsNoop(t *testing.T) {
	if err := modcache.Remove(""); err != nil {
		t.Errorf("Remove(\"\") = %v, want nil", err)
	}
}

func TestRemove_MissingDirIsNoop(t *testing.T) {
	// os.RemoveAll treats a missing path as success; Remove must too.
	if err := modcache.Remove(filepath.Join(t.TempDir(), "does-not-exist")); err != nil {
		t.Errorf("Remove(missing) = %v, want nil", err)
	}
}
