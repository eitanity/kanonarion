package domain

import (
	"path/filepath"
	"testing"
)

func TestStorageConfig_SumDBCacheDir(t *testing.T) {
	root := filepath.FromSlash("/store")
	for _, tc := range []struct{ in, want string }{
		{"", filepath.Join(root, "sumdb")},
		{filepath.FromSlash("/var/cache/sumdb"), filepath.FromSlash("/var/cache/sumdb")},
		{"cache", filepath.Join(root, "cache")},
	} {
		if got := (StorageConfig{SumDBCache: tc.in}).SumDBCacheDir(root); got != tc.want {
			t.Errorf("SumDBCacheDir(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if DefaultConfig().Storage.Backend != DefaultStorageBackend {
		t.Errorf("DefaultConfig names backend %q", DefaultConfig().Storage.Backend)
	}
}
