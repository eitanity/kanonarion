// Package modcache implements a ports.BlobStore that resolves module bytes from
// a Go module cache ($GOMODCACHE) instead of kanonarion's content-addressed blob
// store. It is the blob adapter used in --from-modcache mode.
//
// Two handle namespaces coexist:
//
//   - "modcache:zip:<escapedPath>@<escapedVersion>" and
//     "modcache:mod:<escapedPath>@<escapedVersion>" resolve to
//     $GOMODCACHE/cache/download/<escapedPath>/@v/<escapedVersion>.{zip,mod}.
//     These are produced by the fetch pipeline in modcache mode, which derives
//     them from the coordinate and never calls Put.
//   - Any other handle (a "sha256:<hex>" content address) is delegated to an
//     underlying content-addressed store. Local modules — the project root and
//     local-replace targets — have no module-cache entry, so their zipped bytes
//     are still Put into and Got from the delegate.
//
// The module-cache namespace is read-only: Put only ever writes through the
// delegate.
package modcache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
	"golang.org/x/mod/module"
)

// ErrBlobNotFound is returned when a module-cache handle names a file that is
// not present in the cache directory.
var ErrBlobNotFound = errors.New("blob not found in module cache")

const (
	handlePrefix   = "modcache:"
	kindZip        = "zip"
	kindGoMod      = "mod"
	zipExtension   = ".zip"
	goModExtension = ".mod"
)

// Delegate is the subset of the blob-store contract the module-cache store
// falls back to for content-addressed (non-module-cache) handles. The local
// filesystem store satisfies it, including the optional path capability.
type Delegate interface {
	ports.BlobStore
	ports.BlobPathOptimizer
}

// Store resolves module-cache handles from dir and delegates all other handles
// to a content-addressed store.
type Store struct {
	dir      string
	delegate Delegate
}

var (
	_ ports.BlobStore         = (*Store)(nil)
	_ ports.BlobPathOptimizer = (*Store)(nil)
)

// New constructs a Store rooted at the module-cache directory dir (the value of
// `go env GOMODCACHE`), delegating content-addressed handles to delegate.
func New(dir string, delegate Delegate) *Store {
	return &Store{dir: dir, delegate: delegate}
}

// ZipHandle returns the deterministic module-cache handle for a coordinate's
// zip. It never touches the filesystem, so the fetch pipeline can record it
// without a Put.
func ZipHandle(coord domain.ModuleCoordinate) (ports.BlobHandle, error) {
	return deriveHandle(kindZip, coord)
}

// GoModHandle returns the deterministic module-cache handle for a coordinate's
// standalone go.mod.
func GoModHandle(coord domain.ModuleCoordinate) (ports.BlobHandle, error) {
	return deriveHandle(kindGoMod, coord)
}

// ZipHandle satisfies the fetch pipeline's ModcacheHandleDeriver so the Store
// can be injected as both the blob adapter and the handle source in
// --from-modcache mode.
func (s *Store) ZipHandle(coord domain.ModuleCoordinate) (ports.BlobHandle, error) {
	return ZipHandle(coord)
}

// GoModHandle satisfies the fetch pipeline's ModcacheHandleDeriver.
func (s *Store) GoModHandle(coord domain.ModuleCoordinate) (ports.BlobHandle, error) {
	return GoModHandle(coord)
}

func deriveHandle(kind string, coord domain.ModuleCoordinate) (ports.BlobHandle, error) {
	escapedPath, err := module.EscapePath(coord.Path)
	if err != nil {
		return "", fmt.Errorf("escaping module path %q: %w", coord.Path, err)
	}
	escapedVersion, err := module.EscapeVersion(coord.Version)
	if err != nil {
		return "", fmt.Errorf("escaping module version %q: %w", coord.Version, err)
	}
	return ports.BlobHandle(handlePrefix + kind + ":" + escapedPath + "@" + escapedVersion), nil
}

// Put stores content via the delegate and returns its content-addressed handle.
// Module-cache entries are never written here; the fetch pipeline derives their
// handles instead. Local modules (root, replace targets) still flow through.
func (s *Store) Put(ctx context.Context, content io.Reader) (ports.BlobHandle, error) {
	h, err := s.delegate.Put(ctx, content)
	if err != nil {
		return "", fmt.Errorf("delegate put: %w", err)
	}
	return h, nil
}

// Get opens the blob for handle. Module-cache handles resolve to a file in the
// cache directory; all other handles are delegated.
func (s *Store) Get(ctx context.Context, handle ports.BlobHandle) (io.ReadCloser, error) {
	path, ok, err := s.resolve(handle)
	if err != nil {
		return nil, err
	}
	if !ok {
		rc, derr := s.delegate.Get(ctx, handle)
		if derr != nil {
			return nil, fmt.Errorf("delegate get: %w", derr)
		}
		return rc, nil
	}
	f, err := os.Open(path) // #nosec G304 -- path derived from an escaped module coordinate under the cache dir
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrBlobNotFound, handle)
		}
		return nil, fmt.Errorf("opening module-cache blob %s: %w", handle, err)
	}
	return f, nil
}

// GetPath returns the filesystem path for handle. Module-cache handles resolve
// directly; other handles are delegated to the content-addressed store.
func (s *Store) GetPath(ctx context.Context, handle ports.BlobHandle) (string, error) {
	path, ok, err := s.resolve(handle)
	if err != nil {
		return "", err
	}
	if !ok {
		p, derr := s.delegate.GetPath(ctx, handle)
		if derr != nil {
			return "", fmt.Errorf("delegate get path: %w", derr)
		}
		return p, nil
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%w: %s", ErrBlobNotFound, handle)
		}
		return "", fmt.Errorf("checking module-cache blob %s: %w", handle, err)
	}
	return path, nil
}

// Exists reports whether the blob for handle is present.
func (s *Store) Exists(ctx context.Context, handle ports.BlobHandle) (bool, error) {
	path, ok, err := s.resolve(handle)
	if err != nil {
		return false, err
	}
	if !ok {
		exists, derr := s.delegate.Exists(ctx, handle)
		if derr != nil {
			return false, fmt.Errorf("delegate exists: %w", derr)
		}
		return exists, nil
	}
	_, statErr := os.Stat(path)
	if os.IsNotExist(statErr) {
		return false, nil
	}
	if statErr != nil {
		return false, fmt.Errorf("checking module-cache blob existence: %w", statErr)
	}
	return true, nil
}

// resolve maps a module-cache handle to its on-disk path. ok is false when the
// handle is not a module-cache handle (the caller then delegates).
func (s *Store) resolve(handle ports.BlobHandle) (path string, ok bool, err error) {
	h := string(handle)
	if !strings.HasPrefix(h, handlePrefix) {
		return "", false, nil
	}
	rest := strings.TrimPrefix(h, handlePrefix)
	kind, coordPart, found := strings.Cut(rest, ":")
	if !found {
		return "", false, fmt.Errorf("malformed module-cache handle %q", handle)
	}
	var ext string
	switch kind {
	case kindZip:
		ext = zipExtension
	case kindGoMod:
		ext = goModExtension
	default:
		return "", false, fmt.Errorf("unknown module-cache handle kind %q in %q", kind, handle)
	}
	escapedPath, escapedVersion, found := cutLast(coordPart, "@")
	if !found || escapedPath == "" || escapedVersion == "" {
		return "", false, fmt.Errorf("malformed module-cache handle %q", handle)
	}
	full := filepath.Join(s.dir, "cache", "download", filepath.FromSlash(escapedPath), "@v", escapedVersion+ext)
	return full, true, nil
}

// cutLast splits s around the last instance of sep.
func cutLast(s, sep string) (before, after string, found bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}
