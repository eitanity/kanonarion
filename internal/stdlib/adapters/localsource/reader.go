// Package localsource implements ports.LocalSourceReader over the local Go
// toolchain's install tree: it exposes $GOROOT/src as an fs.FS for digesting and
// reads $GOROOT/LICENSE for classification. All access is filesystem-only — the
// offline custody path performs no network I/O.
package localsource

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/eitanity/kanonarion/internal/stdlib/ports"
)

// maxLicenseBytes caps how much of the LICENSE file is read into memory. The Go
// LICENSE is ~1.5 KB; the cap guards against a corrupt or hostile file.
const maxLicenseBytes = 1 << 20 // 1 MiB

// Reader reads the standard-library source and licence from a local GOROOT.
type Reader struct{}

// New constructs a Reader.
func New() *Reader { return &Reader{} }

// SourceFS returns an fs.FS rooted at $GOROOT/src. It verifies the directory
// exists so a missing or malformed toolchain fails at acquisition rather than
// yielding empty digests.
func (r *Reader) SourceFS(goRoot string) (fs.FS, error) {
	srcDir := filepath.Join(goRoot, "src")
	info, err := os.Stat(srcDir)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", srcDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", srcDir)
	}
	return os.DirFS(srcDir), nil
}

// LicenseText returns the bytes of $GOROOT/LICENSE, bounded by maxLicenseBytes.
func (r *Reader) LicenseText(goRoot string) ([]byte, error) {
	licensePath := filepath.Join(goRoot, "LICENSE")
	f, err := os.Open(licensePath) // #nosec G304 -- path derived from the trusted toolchain GOROOT
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", licensePath, err)
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, maxLicenseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", licensePath, err)
	}
	return data, nil
}

var _ ports.LocalSourceReader = (*Reader)(nil)
