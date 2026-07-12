package modcache

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	localfs "github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

func newCoord(t *testing.T, path, version string) domain.ModuleCoordinate {
	t.Helper()
	c, err := domain.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate(%s, %s): %v", path, version, err)
	}
	return c
}

// seedCacheEntry writes bytes to the module-cache path for coord + ext, mirroring
// the on-disk layout `go mod download` produces.
func seedCacheEntry(t *testing.T, dir string, coord domain.ModuleCoordinate, ext string, content []byte) {
	t.Helper()
	base := filepath.Join(dir, "cache", "download", filepath.FromSlash(coord.Path), "@v")
	if err := os.MkdirAll(base, 0o750); err != nil {
		t.Fatalf("mkdir cache: %v", err)
	}
	if err := os.WriteFile(filepath.Join(base, coord.Version+ext), content, 0o600); err != nil {
		t.Fatalf("writing cache entry: %v", err)
	}
}

func TestHandleDerivation(t *testing.T) {
	coord := newCoord(t, "github.com/example/mod", "v1.2.3")
	zh, err := ZipHandle(coord)
	if err != nil {
		t.Fatalf("ZipHandle: %v", err)
	}
	if want := ports.BlobHandle("modcache:zip:github.com/example/mod@v1.2.3"); zh != want {
		t.Errorf("ZipHandle = %q, want %q", zh, want)
	}
	mh, err := GoModHandle(coord)
	if err != nil {
		t.Fatalf("GoModHandle: %v", err)
	}
	if want := ports.BlobHandle("modcache:mod:github.com/example/mod@v1.2.3"); mh != want {
		t.Errorf("GoModHandle = %q, want %q", mh, want)
	}
}

func TestHandleDerivation_EscapesUppercase(t *testing.T) {
	coord := newCoord(t, "github.com/Example/Mod", "v1.0.0")
	zh, err := ZipHandle(coord)
	if err != nil {
		t.Fatalf("ZipHandle: %v", err)
	}
	if !strings.Contains(string(zh), "!example/!mod") {
		t.Errorf("ZipHandle = %q, want escaped uppercase (!example/!mod)", zh)
	}
}

func TestGet_ModcacheHandleReadsFile(t *testing.T) {
	dir := t.TempDir()
	coord := newCoord(t, "github.com/example/mod", "v1.2.3")
	seedCacheEntry(t, dir, coord, ".zip", []byte("zip-content"))
	seedCacheEntry(t, dir, coord, ".mod", []byte("module github.com/example/mod\n"))

	store := New(dir, localfs.New(t.TempDir()))

	zh, _ := ZipHandle(coord)
	rc, err := store.Get(context.Background(), zh)
	if err != nil {
		t.Fatalf("Get(zip): %v", err)
	}
	defer func() { _ = rc.Close() }()
	got, _ := io.ReadAll(rc)
	if string(got) != "zip-content" {
		t.Errorf("zip content = %q, want zip-content", got)
	}

	mh, _ := GoModHandle(coord)
	rc2, err := store.Get(context.Background(), mh)
	if err != nil {
		t.Fatalf("Get(mod): %v", err)
	}
	defer func() { _ = rc2.Close() }()
	got2, _ := io.ReadAll(rc2)
	if string(got2) != "module github.com/example/mod\n" {
		t.Errorf("mod content = %q", got2)
	}
}

func TestGet_MissingModcacheEntryNotFound(t *testing.T) {
	store := New(t.TempDir(), localfs.New(t.TempDir()))
	zh, _ := ZipHandle(newCoord(t, "github.com/example/mod", "v1.2.3"))
	_, err := store.Get(context.Background(), zh)
	if !errors.Is(err, ErrBlobNotFound) {
		t.Fatalf("err = %v, want ErrBlobNotFound", err)
	}
}

func TestGetPathAndExists_ModcacheHandle(t *testing.T) {
	dir := t.TempDir()
	coord := newCoord(t, "github.com/example/mod", "v1.2.3")
	seedCacheEntry(t, dir, coord, ".zip", []byte("z"))
	store := New(dir, localfs.New(t.TempDir()))
	zh, _ := ZipHandle(coord)

	path, err := store.GetPath(context.Background(), zh)
	if err != nil {
		t.Fatalf("GetPath: %v", err)
	}
	if !strings.HasSuffix(path, filepath.Join("@v", "v1.2.3.zip")) {
		t.Errorf("GetPath = %q, want a .../@v/v1.2.3.zip path", path)
	}

	ok, err := store.Exists(context.Background(), zh)
	if err != nil || !ok {
		t.Errorf("Exists = (%v, %v), want (true, nil)", ok, err)
	}

	missing, _ := ZipHandle(newCoord(t, "github.com/example/mod", "v9.9.9"))
	ok, err = store.Exists(context.Background(), missing)
	if err != nil || ok {
		t.Errorf("Exists(missing) = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestDelegation_ContentAddressedHandles(t *testing.T) {
	delegate := localfs.New(t.TempDir())
	store := New(t.TempDir(), delegate)

	// Put flows through the delegate; the returned handle is content-addressed.
	handle, err := store.Put(context.Background(), strings.NewReader("local-module-zip"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if strings.HasPrefix(string(handle), handlePrefix) {
		t.Fatalf("Put returned a module-cache handle %q; want a delegate handle", handle)
	}

	rc, err := store.Get(context.Background(), handle)
	if err != nil {
		t.Fatalf("Get(delegate): %v", err)
	}
	defer func() { _ = rc.Close() }()
	got, _ := io.ReadAll(rc)
	if string(got) != "local-module-zip" {
		t.Errorf("delegate content = %q", got)
	}

	ok, err := store.Exists(context.Background(), handle)
	if err != nil || !ok {
		t.Errorf("Exists(delegate) = (%v, %v), want (true, nil)", ok, err)
	}
	if _, err := store.GetPath(context.Background(), handle); err != nil {
		t.Errorf("GetPath(delegate): %v", err)
	}
}

func TestGet_MalformedHandle(t *testing.T) {
	store := New(t.TempDir(), localfs.New(t.TempDir()))
	for _, h := range []ports.BlobHandle{
		"modcache:zip:no-at-sign",
		"modcache:boguskind:mod@v1",
		"modcache:onlyprefix",
	} {
		if _, err := store.Get(context.Background(), h); err == nil {
			t.Errorf("Get(%q): expected error, got nil", h)
		}
	}
}
