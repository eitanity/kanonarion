// Package modcache implements a ports.BlobStore backed by a Go module cache
// ($GOMODCACHE). It is the blob adapter used in --from-modcache mode.
//
// It has no handle namespace of its own. Artefacts are addressed by identity,
// exactly as in every other mode, and the adapter's whole job is population: it
// brings bytes that already exist in the module cache into that address space.
// This is the port's fourth obligation — how bytes arrive is the adapter's
// business, and the port guarantees only that after Put, Exists(identity) is
// true.
//
// Population is by hard link. A hard link survives `go clean -modcache`: the
// toolchain unlinks its own name, the inode persists while kanonarion's link
// holds it, and the evidence base stays intact. A soft link would dangle and the
// bytes would be gone. That is the difference between a module-cache-primary
// configuration being a durable evidence store with zero duplication and being a
// space convenience whose store is not self-contained. A cross-device link falls
// back to a copy.
//
// The adapter previously derived "modcache:zip:<coord>@<version>" handles and
// wrote them into fact records. Those handles were mode-locked — only this
// adapter could resolve them — so a coordinate measured in module-cache mode
// produced a record the default store could not read, and a network measurement
// of the same artefact produced an irreconcilable second record. Addressing by
// identity is what removes that defect rather than guarding against it.
package modcache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/fetch/ports"
	"golang.org/x/mod/module"
)

// ErrBlobNotFound is returned when an artefact is not held.
var ErrBlobNotFound = errors.New("blob not found in module cache")

const (
	zipExtension   = ".zip"
	goModExtension = ".mod"
)

// Delegate is the identity-addressed store the module-cache adapter populates
// and reads through. The local filesystem store satisfies it, including the
// optional path capability.
type Delegate interface {
	ports.BlobStore
	ports.BlobPathOptimizer
}

// Store populates an identity-addressed store from a Go module cache directory.
type Store struct {
	dir      string
	delegate Delegate
}

var (
	_ ports.BlobStore         = (*Store)(nil)
	_ ports.BlobPathOptimizer = (*Store)(nil)
)

// New constructs a Store rooted at the module-cache directory dir (the value of
// `go env GOMODCACHE`), holding artefacts in delegate.
func New(dir string, delegate Delegate) *Store {
	return &Store{dir: dir, delegate: delegate}
}

// Put stores content under identity. The delegate hard-links rather than copying
// whenever the content is an open file, which is what makes population from a
// module cache cost no disk.
func (s *Store) Put(ctx context.Context, identity ports.BlobIdentity, content io.Reader) error {
	if err := s.delegate.Put(ctx, identity, content); err != nil {
		return fmt.Errorf("delegate put: %w", err)
	}
	return nil
}

// Get opens the artefact identified by identity.
func (s *Store) Get(ctx context.Context, identity ports.BlobIdentity) (io.ReadCloser, error) {
	rc, err := s.delegate.Get(ctx, identity)
	if err != nil {
		return nil, fmt.Errorf("delegate get: %w", err)
	}
	return rc, nil
}

// GetPath returns the filesystem path to the artefact identified by identity.
func (s *Store) GetPath(ctx context.Context, identity ports.BlobIdentity) (string, error) {
	p, err := s.delegate.GetPath(ctx, identity)
	if err != nil {
		return "", fmt.Errorf("delegate get path: %w", err)
	}
	return p, nil
}

// Exists reports whether the artefact is held.
func (s *Store) Exists(ctx context.Context, identity ports.BlobIdentity) (bool, error) {
	exists, err := s.delegate.Exists(ctx, identity)
	if err != nil {
		return false, fmt.Errorf("delegate exists: %w", err)
	}
	return exists, nil
}

// OpenZip opens a coordinate's module zip in the cache directory, for the fetch
// pipeline to hash and Put under the identity it measures. It is the population
// source, not an address: the returned file's path is the cache's own layout and
// is never recorded.
func (s *Store) OpenZip(coord coordinate.ModuleCoordinate) (*os.File, error) {
	return s.openCacheFile(coord, zipExtension)
}

// OpenGoMod opens a coordinate's standalone go.mod in the cache directory.
func (s *Store) OpenGoMod(coord coordinate.ModuleCoordinate) (*os.File, error) {
	return s.openCacheFile(coord, goModExtension)
}

// CachePath returns the path a coordinate's artefact occupies in the module
// cache, without opening it.
func (s *Store) CachePath(coord coordinate.ModuleCoordinate, ext string) (string, error) {
	escapedPath, err := module.EscapePath(coord.Path())
	if err != nil {
		return "", fmt.Errorf("escaping module path %q: %w", coord.Path(), err)
	}
	escapedVersion, err := module.EscapeVersion(coord.Version())
	if err != nil {
		return "", fmt.Errorf("escaping module version %q: %w", coord.Version(), err)
	}
	return filepath.Join(s.dir, "cache", "download", filepath.FromSlash(escapedPath), "@v", escapedVersion+ext), nil
}

// ZipExtension and GoModExtension name the module-cache file suffixes, for
// callers of CachePath.
const (
	ZipExtension   = zipExtension
	GoModExtension = goModExtension
)

func (s *Store) openCacheFile(coord coordinate.ModuleCoordinate, ext string) (*os.File, error) {
	path, err := s.CachePath(coord, ext)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path) // #nosec G304 -- path derived from an escaped module coordinate under the cache dir
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s%s", ErrBlobNotFound, coord, ext)
		}
		return nil, fmt.Errorf("opening module-cache file for %s: %w", coord, err)
	}
	return f, nil
}
