package domain

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
)

// ErrLicenseNotFound means the source tarball did not contain the top-level
// LICENSE file the standard-library licence is extracted from.
var ErrLicenseNotFound = errors.New("stdlib: LICENSE file not found in source tarball")

// licensePath is the tarball path of the standard library's licence file. The
// go{VERSION}.src.tar.gz archive roots every entry under "go/", so the licence
// is at "go/LICENSE".
const licensePath = "go/LICENSE"

// maxLicenseBytes caps how much of the LICENSE entry is read into memory. The
// Go LICENSE is ~1.5 KB; the cap guards against a hostile or corrupt archive
// declaring an enormous LICENSE entry.
const maxLicenseBytes = 1 << 20 // 1 MiB

// ExtractLicense reads the standard library's LICENSE text out of the gzip'd
// source tarball bytes. It returns ErrLicenseNotFound when no go/LICENSE entry
// is present, so the caller can record the licence as unresolved rather than
// fail acquisition.
//
// The read is bounded (maxLicenseBytes) so a malformed archive cannot exhaust
// memory, and the archive is scanned entry-by-entry without extracting anything
// else.
func ExtractLicense(tarball []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return nil, fmt.Errorf("opening gzip stream: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, terr := tr.Next()
		if errors.Is(terr, io.EOF) {
			break
		}
		if terr != nil {
			return nil, fmt.Errorf("reading tar entry: %w", terr)
		}
		if hdr.Name != licensePath || hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, rerr := io.ReadAll(io.LimitReader(tr, maxLicenseBytes))
		if rerr != nil {
			return nil, fmt.Errorf("reading %s: %w", licensePath, rerr)
		}
		return data, nil
	}
	return nil, ErrLicenseNotFound
}
