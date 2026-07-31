// Package blobstore implements ports.VerifiedModuleZipSource over the
// content-addressed blob store the fetch pipeline writes.
//
// The store addresses an artefact by the h1 hash of its bytes, so a lookup keyed
// on the h1 go.sum records for a module version returns that artefact or nothing
// at all. There is no separate verification step to forget: a zip reachable at
// the go.sum h1's address is a zip whose bytes were measured to hash to the
// value the project trusts, and any other bytes live at a different address.
package blobstore

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/vendortree/ports"
)

// Source reads published module file sets out of a blob store.
type Source struct {
	blobs fetchports.BlobStore
}

var _ ports.VerifiedModuleZipSource = (*Source)(nil)

// New returns a Source reading from blobs. A nil store is legitimate — it is
// the "kanonarion holds nothing" case — and every lookup reports not found, so
// the domain reports the affected modules as unverified rather than clean.
func New(blobs fetchports.BlobStore) *Source { return &Source{blobs: blobs} }

// PublishedFiles returns the file set of the held zip whose bytes hash to h1.
//
// Zip entries are named "<modulePath>@<version>/<file>"; the prefix is stripped
// so the keys line up with the module-relative paths the vendored tree is walked
// into. An entry that does not carry the expected prefix is refused rather than
// skipped: it would mean the artefact at this address is not the module the
// caller asked about, and silently comparing against a partial file set would
// turn every unaccounted vendored file into a drift finding.
func (s *Source) PublishedFiles(
	ctx context.Context, modulePath, version, h1 string,
) (map[string]string, bool, error) {
	if s.blobs == nil || h1 == "" {
		return nil, false, nil
	}

	hash, err := fetchdomain.ParseModuleHash(h1)
	if err != nil {
		return nil, false, fmt.Errorf("parsing go.sum checksum for %s@%s: %w", modulePath, version, err)
	}
	identity, err := fetchports.NewBlobIdentity(fetchports.BlobKindZip, hash)
	if err != nil {
		return nil, false, fmt.Errorf("addressing the module zip for %s@%s: %w", modulePath, version, err)
	}

	held, err := s.blobs.Exists(ctx, identity)
	if err != nil {
		return nil, false, fmt.Errorf("checking for the module zip of %s@%s: %w", modulePath, version, err)
	}
	if !held {
		return nil, false, nil
	}

	r, closeFn, err := s.open(ctx, identity)
	if err != nil {
		return nil, false, fmt.Errorf("opening the module zip for %s@%s: %w", modulePath, version, err)
	}
	defer closeFn()

	files, err := digestEntries(r, modulePath+"@"+version+"/")
	if err != nil {
		return nil, false, fmt.Errorf("reading the module zip for %s@%s: %w", modulePath, version, err)
	}
	return files, true, nil
}

// open returns a zip reader over the addressed artefact plus the cleanup the
// caller owes it. A store that can hand out a filesystem path is read in place;
// otherwise the bytes are staged to a temp file, because a zip is read by offset
// and the generic store offers only a stream.
func (s *Source) open(ctx context.Context, identity fetchports.BlobIdentity) (*zip.Reader, func(), error) {
	if opt, ok := s.blobs.(fetchports.BlobPathOptimizer); ok {
		path, err := opt.GetPath(ctx, identity)
		if err == nil {
			rc, oerr := zip.OpenReader(path)
			if oerr != nil {
				return nil, nil, fmt.Errorf("opening zip %s: %w", path, oerr)
			}
			return &rc.Reader, func() { _ = rc.Close() }, nil
		}
	}

	rc, err := s.blobs.Get(ctx, identity)
	if err != nil {
		return nil, nil, fmt.Errorf("reading blob %s: %w", identity, err)
	}
	defer func() { _ = rc.Close() }()

	tmp, err := os.CreateTemp("", "kanonarion-vendor-zip-*")
	if err != nil {
		return nil, nil, fmt.Errorf("staging module zip: %w", err)
	}
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}
	size, err := io.Copy(tmp, rc)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("staging module zip: %w", err)
	}
	zr, err := zip.NewReader(tmp, size)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("opening staged module zip: %w", err)
	}
	return zr, cleanup, nil
}

// ErrForeignZipEntry is the refusal owed a zip entry named outside the module
// the caller asked about.
var ErrForeignZipEntry = errors.New("module zip holds an entry outside the module's own prefix")

// digestEntries maps each file entry under prefix to the digest of its bytes.
// Directory entries carry no content and are skipped.
func digestEntries(r *zip.Reader, prefix string) (map[string]string, error) {
	out := make(map[string]string, len(r.File))
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if len(f.Name) <= len(prefix) || f.Name[:len(prefix)] != prefix {
			return nil, fmt.Errorf("%w: %q is not under %q", ErrForeignZipEntry, f.Name, prefix)
		}
		digest, err := digestEntry(f)
		if err != nil {
			return nil, err
		}
		out[f.Name[len(prefix):]] = digest
	}
	return out, nil
}

// digestEntry returns the "sha256:<hex>" digest of one zip entry's content.
func digestEntry(f *zip.File) (string, error) {
	rc, err := f.Open()
	if err != nil {
		return "", fmt.Errorf("opening zip entry %q: %w", f.Name, err)
	}
	defer func() { _ = rc.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, rc); err != nil { /* #nosec G110 -- the zip is the artefact whose bytes hash to a checksum go.sum records, held by the store; its size is bounded by the fetch stage that admitted it */
		return "", fmt.Errorf("hashing zip entry %q: %w", f.Name, err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
