package govulncheck

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func (s *Scanner) extractZip(ctx context.Context, r io.Reader, dest string) error {
	// 1. Write the source to a temporary file instead of reading all into memory
	tmpZip, err := os.CreateTemp("", "kanonarion-vuln-scan-zip-*")
	if err != nil {
		return fmt.Errorf("create temp zip file: %w", err)
	}
	defer func() {
		_ = tmpZip.Close()
		_ = os.Remove(tmpZip.Name())
	}()

	n, err := io.Copy(tmpZip, r)
	if err != nil {
		return fmt.Errorf("write temp zip file: %w", err)
	}

	if _, err := tmpZip.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek temp zip file: %w", err)
	}

	s.logMem(ctx, "zip_written_to_disk")

	// 2. Open zip.Reader from the file
	zr, err := zip.NewReader(tmpZip, n)
	if err != nil {
		return fmt.Errorf("open zip reader: %w", err)
	}

	for _, f := range zr.File {
		// G305: sanitise path to prevent zip-slip
		clean := filepath.Join(dest, filepath.Clean("/"+f.Name))
		if !strings.HasPrefix(clean, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("zip entry %q escapes destination directory", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(clean, 0750); err != nil { /* #nosec G301 -- 0750 is intentional */
				return fmt.Errorf("create directory %q: %w", clean, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(clean), 0750); err != nil { /* #nosec G301 -- 0750 is intentional */
			return fmt.Errorf("create parent directory for %q: %w", clean, err)
		}

		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open zip entry %q: %w", f.Name, err)
		}

		dst, err := os.OpenFile(clean, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode()) /* #nosec G304 -- path sanitised against zip-slip above */
		if err != nil {
			_ = rc.Close()
			return fmt.Errorf("create destination file %q: %w", clean, err)
		}

		if _, err := io.Copy(dst, rc); err != nil { /* #nosec G110 -- zip sourced from Go module proxy, size bounded by fetch stage */
			_ = dst.Close()
			_ = rc.Close()
			return fmt.Errorf("copy zip entry %q: %w", f.Name, err)
		}
		_ = dst.Close()
		_ = rc.Close()
	}
	return nil
}

// findFirstGoPackage returns a "./..." relative package pattern for the first
// directory under root that contains at least one non-test.go file.
// Falls back to "./..." if no such directory is found.
func findFirstGoPackage(root string) string {
	var found string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if found != "" || err != nil {
			return filepath.SkipAll
		}
		if d.IsDir() && d.Name() == "vendor" {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".go") && !strings.HasSuffix(d.Name(), "_test.go") {
			rel, relErr := filepath.Rel(root, filepath.Dir(path))
			if relErr == nil {
				found = "./" + rel
			}
			return filepath.SkipAll
		}
		return nil
	})
	if found == "" {
		return "./..."
	}
	return found
}
