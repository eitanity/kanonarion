// Package walkdir provides an fs.WalkDir-based SnapshotBuilder.
package walkdir

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/local/domain"
)

// Builder implements ports.SnapshotBuilder using fs.WalkDir on os.DirFS.
// All file reads are scoped to the resolved root directory, preventing
// path traversal outside it.
type Builder struct{}

// Build walks root and reads all.go, go.mod, and go.sum files into a
// Snapshot. Absolute paths are used as keys. Context cancellation is checked
// before each file read.
func (Builder) Build(ctx context.Context, root string) (domain.Snapshot, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return domain.Snapshot{}, fmt.Errorf("resolving root %q: %w", root, err)
	}

	fsys := os.DirFS(abs)
	files := make(map[string][]byte)

	err = fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walking %q: %w", path, err)
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if !isRelevant(d.Name()) {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		content, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("reading %q: %w", path, err)
		}
		// Reconstruct absolute path for go/packages Config.Overlay compatibility.
		files[filepath.Join(abs, path)] = content
		return nil
	})
	if err != nil {
		return domain.Snapshot{}, fmt.Errorf("snapshot walk of %q: %w", abs, err)
	}
	return domain.NewSnapshot(files), nil
}

func isRelevant(name string) bool {
	return strings.HasSuffix(name, ".go") || name == "go.mod" || name == "go.sum"
}
