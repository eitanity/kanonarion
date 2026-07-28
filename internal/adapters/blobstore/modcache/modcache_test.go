package modcache

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	localfs "github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"

	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

func newCoord(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate(%s, %s): %v", path, version, err)
	}
	return c
}

func identity(kind ports.BlobKind, value string) ports.BlobIdentity {
	return fetchtest.Blob(kind, fetchtest.H1(value))
}

// seedCacheEntry writes bytes to the module-cache path for coord + ext, mirroring
// the on-disk layout `go mod download` produces.
func seedCacheEntry(t *testing.T, dir string, coord coordinate.ModuleCoordinate, ext string, content []byte) string {
	t.Helper()
	store := New(dir, localfs.New(t.TempDir()))
	path, err := store.CachePath(coord, ext)
	if err != nil {
		t.Fatalf("CachePath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// The cache path is derived from the coordinate with the module-escaping rules
// the Go toolchain uses, so an uppercase path resolves to the !-escaped
// directory the toolchain actually wrote.
func TestCachePath_EscapesUppercase(t *testing.T) {
	dir := t.TempDir()
	store := New(dir, localfs.New(t.TempDir()))
	coord := newCoord(t, "github.com/BurntSushi/toml", "v1.2.0")

	path, err := store.CachePath(coord, ZipExtension)
	if err != nil {
		t.Fatalf("CachePath: %v", err)
	}
	if !strings.Contains(path, "!burnt!sushi") {
		t.Errorf("CachePath = %q, want the !-escaped form of BurntSushi", path)
	}
}

// The adapter's job is population: bringing bytes that already exist in the
// module cache into the identity-addressed space. After Put, the artefact is
// reachable by identity alone, with no trace of the cache layout it came from.
func TestPut_PopulatesIdentityAddressedSpace(t *testing.T) {
	cacheDir := t.TempDir()
	store := New(cacheDir, localfs.New(t.TempDir()))
	ctx := context.Background()
	coord := newCoord(t, "example.com/mod", "v1.0.0")
	seedCacheEntry(t, cacheDir, coord, ZipExtension, []byte("zip bytes"))

	f, err := store.OpenZip(coord)
	if err != nil {
		t.Fatalf("OpenZip: %v", err)
	}
	defer func() { _ = f.Close() }()

	id := identity(ports.BlobKindZip, "mod-zip")
	if err := store.Put(ctx, id, f); err != nil {
		t.Fatalf("Put: %v", err)
	}

	exists, err := store.Exists(ctx, id)
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !exists {
		t.Fatal("artefact should be reachable by identity after Put")
	}

	rc, err := store.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = rc.Close() }()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "zip bytes" {
		t.Errorf("got %q, want %q", got, "zip bytes")
	}
}

// Population is by hard link, which is what makes a module-cache-primary
// configuration cost no disk AND survive `go clean -modcache`: the toolchain
// unlinks its own name and the inode persists while this link holds it. A soft
// link would dangle and the evidence would be gone.
func TestPut_HardLinksSoTheEvidenceSurvivesCacheCleaning(t *testing.T) {
	cacheDir := t.TempDir()
	blobRoot := t.TempDir()
	store := New(cacheDir, localfs.New(blobRoot))
	ctx := context.Background()
	coord := newCoord(t, "example.com/mod", "v1.0.0")
	cachePath := seedCacheEntry(t, cacheDir, coord, ZipExtension, []byte("durable bytes"))

	f, err := store.OpenZip(coord)
	if err != nil {
		t.Fatalf("OpenZip: %v", err)
	}
	id := identity(ports.BlobKindZip, "durable")
	if err := store.Put(ctx, id, f); err != nil {
		_ = f.Close()
		t.Fatalf("Put: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Simulate `go clean -modcache`: the toolchain removes its own name.
	if err := os.Remove(cachePath); err != nil {
		t.Fatalf("removing cache entry: %v", err)
	}

	rc, err := store.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get after cache clean: %v; the link did not survive", err)
	}
	defer func() { _ = rc.Close() }()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "durable bytes" {
		t.Errorf("got %q, want %q", got, "durable bytes")
	}
}

// An artefact the cache does not hold is absence, not a failure: the fetch
// pipeline re-acquires it.
func TestOpenZip_MissingEntryIsNotFound(t *testing.T) {
	store := New(t.TempDir(), localfs.New(t.TempDir()))
	_, err := store.OpenZip(newCoord(t, "example.com/absent", "v1.0.0"))
	if !errors.Is(err, ErrBlobNotFound) {
		t.Errorf("OpenZip(absent): got %v, want ErrBlobNotFound", err)
	}
}

// An artefact this mode never populated is simply absent — there is no separate
// namespace for it to be looked up in. That is the whole point of removing the
// mode-locked handles: a record written by any mode names one address, and a
// store either holds it or does not.
func TestGet_UnpopulatedIdentityIsAbsent(t *testing.T) {
	store := New(t.TempDir(), localfs.New(t.TempDir()))
	exists, err := store.Exists(context.Background(), identity(ports.BlobKindZip, "never-put"))
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if exists {
		t.Error("Exists(unpopulated) = true, want false")
	}
}

// GetPath satisfies the optional path capability, which the consumers that shell
// out to external tools rely on.
func TestGetPath_ReturnsAMaterialisedPath(t *testing.T) {
	cacheDir := t.TempDir()
	store := New(cacheDir, localfs.New(t.TempDir()))
	ctx := context.Background()
	coord := newCoord(t, "example.com/mod", "v1.0.0")
	seedCacheEntry(t, cacheDir, coord, GoModExtension, []byte("module example.com/mod\n"))

	f, err := store.OpenGoMod(coord)
	if err != nil {
		t.Fatalf("OpenGoMod: %v", err)
	}
	id := identity(ports.BlobKindGoMod, "mod-gomod")
	if err := store.Put(ctx, id, f); err != nil {
		_ = f.Close()
		t.Fatalf("Put: %v", err)
	}
	_ = f.Close()

	path, err := store.GetPath(ctx, id)
	if err != nil {
		t.Fatalf("GetPath: %v", err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path produced by the store under test
	if err != nil {
		t.Fatalf("reading materialised path: %v", err)
	}
	if string(data) != "module example.com/mod\n" {
		t.Errorf("materialised path holds %q, want the go.mod bytes", data)
	}
}
