package modcache

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Remove deletes a GOMODCACHE directory previously created for a scan. A plain
// os.RemoveAll is not enough: when the Go toolchain (or a govulncheck worker
// running with GOMODCACHE set to this directory) downloads or extracts modules,
// it writes cache entries read-only — files 0o444, directories 0o555. os.RemoveAll
// cannot unlink a child of a read-only directory, so it fails partway with a
// permission error and leaks the (potentially multi-GB) tree. Remove first
// restores write permission on every entry, then deletes — the same approach
// `go clean -modcache` takes.
//
// An empty dir is a no-op. The returned error is non-nil only when the tree could
// not be fully removed even after the chmod pass.
func Remove(dir string) error {
	if dir == "" {
		return nil
	}

	// Best-effort chmod pass. A directory needs write+execute to unlink its
	// children; a regular file needs write to be removed on stricter
	// filesystems. Walk errors are ignored here — os.RemoveAll below surfaces
	// the real failure if anything is still unremovable.
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, _ error) error {
		// Best-effort: skip entries WalkDir could not stat (d == nil); the final
		// os.RemoveAll surfaces anything still unremovable.
		if d == nil {
			return nil
		}
		// Never chmod through a symlink: os.Chmod follows links, and a module
		// cache that extracted a crafted zip could contain one pointing outside
		// the tree. WalkDir does not descend into symlinked directories, so
		// skipping the link entry itself fully scopes the chmod to the cache.
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		mode := os.FileMode(0o600)
		if d.IsDir() {
			mode = 0o700
		}
		// #nosec G122 -- dir is a process-private os.MkdirTemp tree we created and
		// own; symlinks are skipped above, so there is no untrusted-path traversal.
		_ = os.Chmod(path, mode)
		return nil
	})

	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("removing module cache %s: %w", dir, err)
	}
	return nil
}
