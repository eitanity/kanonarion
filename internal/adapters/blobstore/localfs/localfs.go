// Package localfs implements ports.BlobStore using the local filesystem.
//
// Blobs are stored content-addressably at:
//
//	{root}/blobs/{sha256[:2]}/{sha256}
//
// This layout mirrors the OCI blob storage convention and makes large stores
// navigable without hitting directory entry limits.
package localfs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

var ErrBlobNotFound = errors.New("blob not found")

// Compile-time checks: the local FS store is a full BlobStore and also offers
// the optional path capability.
var (
	_ ports.BlobStore         = (*Store)(nil)
	_ ports.BlobPathOptimizer = (*Store)(nil)
)

// Store is the local filesystem blob store.
type Store struct {
	root string
}

// New constructs a Store rooted at root. root need not exist yet; Put creates
// it on first write.
func New(root string) *Store {
	return &Store{root: root}
}

// Put stores content and returns a BlobHandle derived from the SHA-256 of the
// content. Idempotent: if the blob already exists, returns the handle immediately.
// Content is streamed to a temp file via io.TeeReader so memory use is bounded
// by the copy buffer (~32 KB) regardless of blob size.
func (s *Store) Put(_ context.Context, content io.Reader) (ports.BlobHandle, error) {
	blobsDir := filepath.Join(s.root, "blobs")
	if err := os.MkdirAll(blobsDir, 0o750); err != nil {
		return "", fmt.Errorf("creating blobs dir: %w", err)
	}

	tmp, err := os.CreateTemp(blobsDir, ".tmp-*")
	if err != nil {
		return "", fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()

	h := sha256.New()
	if _, err := io.Copy(tmp, io.TeeReader(content, h)); err != nil {
		cerr := tmp.Close()
		rerr := os.Remove(tmpName)
		return "", fmt.Errorf("streaming blob: %w", errors.Join(err, cerr, rerr))
	}
	if err := tmp.Close(); err != nil {
		rerr := os.Remove(tmpName)
		return "", fmt.Errorf("closing temp file: %w", errors.Join(err, rerr))
	}

	digest := hex.EncodeToString(h.Sum(nil))
	handle := ports.BlobHandle("sha256:" + digest)
	blobPath := s.blobPath(digest)

	if _, err := os.Stat(blobPath); err == nil {
		// Already exists; idempotent — discard temp.
		if rerr := os.Remove(tmpName); rerr != nil {
			return "", fmt.Errorf("removing duplicate temp file: %w", rerr)
		}
		return handle, nil
	}

	if err := os.MkdirAll(filepath.Dir(blobPath), 0o750); err != nil {
		rerr := os.Remove(tmpName)
		return "", fmt.Errorf("creating blob dir: %w", errors.Join(err, rerr))
	}
	if err := os.Rename(tmpName, blobPath); err != nil {
		rerr := os.Remove(tmpName)
		return "", fmt.Errorf("renaming blob: %w", errors.Join(err, rerr))
	}
	return handle, nil
}

// Get opens the blob identified by handle for reading.
func (s *Store) Get(_ context.Context, handle ports.BlobHandle) (io.ReadCloser, error) {
	digest, err := parseHandle(handle)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(s.blobPath(digest))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrBlobNotFound
		}
		return nil, fmt.Errorf("opening blob %s: %w", handle, err)
	}
	return f, nil
}

// GetPath returns the local filesystem path to the blob identified by handle.
// It satisfies the optional ports.BlobPathOptimizer capability.
func (s *Store) GetPath(_ context.Context, handle ports.BlobHandle) (string, error) {
	digest, err := parseHandle(handle)
	if err != nil {
		return "", err
	}
	path := s.blobPath(digest)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return "", ErrBlobNotFound
		}
		return "", fmt.Errorf("checking blob %s: %w", handle, err)
	}
	return path, nil
}

// Exists reports whether the blob exists in the store.
func (s *Store) Exists(_ context.Context, handle ports.BlobHandle) (bool, error) {
	digest, err := parseHandle(handle)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(s.blobPath(digest))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checking blob existence: %w", err)
	}
	return true, nil
}

// CleanOrphanedTemps removes any.tmp-* files left in the blobs directory by
// interrupted Put operations. Safe to call at startup because a completed Put
// always renames the temp file to its final content-addressed path.
// Returns the number of files removed.
func (s *Store) CleanOrphanedTemps() (int, error) {
	blobsDir := filepath.Join(s.root, "blobs")
	entries, err := os.ReadDir(blobsDir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("reading blobs dir: %w", err)
	}
	var errs []error
	removed := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			if rerr := os.Remove(filepath.Join(blobsDir, e.Name())); rerr != nil && !os.IsNotExist(rerr) {
				errs = append(errs, rerr)
			} else {
				removed++
			}
		}
	}
	return removed, errors.Join(errs...)
}

func (s *Store) blobPath(digest string) string {
	return filepath.Join(s.root, "blobs", digest[:2], digest)
}

func parseHandle(h ports.BlobHandle) (string, error) {
	s := string(h)
	if len(s) < 8 || s[:7] != "sha256:" {
		return "", fmt.Errorf("invalid blob handle %q: expected sha256:<hex>", h)
	}
	return s[7:], nil
}
