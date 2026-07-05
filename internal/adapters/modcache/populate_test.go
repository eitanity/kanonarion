package modcache_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/modcache"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
)

// fakeFactStore holds a fixed map of records, keyed by "path@version|pipeline".
type fakeFactStore struct {
	records map[string]fetchdomain.FactRecord
}

func (s *fakeFactStore) PutFetchRecord(_ context.Context, r fetchdomain.FactRecord) error {
	s.records[r.ModulePath+"@"+r.ModuleVersion+"|"+r.PipelineVersion] = r
	return nil
}

func (s *fakeFactStore) GetFetchRecord(_ context.Context, coord fetchdomain.ModuleCoordinate, pipelineVersion string) (fetchdomain.FactRecord, bool, error) {
	rec, ok := s.records[coord.Path+"@"+coord.Version+"|"+pipelineVersion]
	return rec, ok, nil
}

// fakeBlobStore stores blob content in memory. It deliberately does NOT
// implement fetchports.BlobPathOptimizer, so Populate's type assertion misses
// and it falls back to the copy path (not the symlink path) — mirroring an
// object-store backend that cannot expose a filesystem path.
type fakeBlobStore struct {
	blobs map[fetchports.BlobHandle][]byte
}

func (s *fakeBlobStore) Put(_ context.Context, r io.Reader) (fetchports.BlobHandle, error) {
	data, _ := io.ReadAll(r)
	h := fetchports.BlobHandle("fake:" + string(data[:min(4, len(data))]))
	s.blobs[h] = data
	return h, nil
}

func (s *fakeBlobStore) Get(_ context.Context, h fetchports.BlobHandle) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(s.blobs[h])), nil
}

func (s *fakeBlobStore) Exists(_ context.Context, h fetchports.BlobHandle) (bool, error) {
	_, ok := s.blobs[h]
	return ok, nil
}

// Compile-time checks: fakeBlobStore is a BlobStore but NOT a path optimizer;
// pathBlobStore adds the optional path capability.
var (
	_ fetchports.BlobStore         = (*fakeBlobStore)(nil)
	_ fetchports.BlobPathOptimizer = (*pathBlobStore)(nil)
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func newCoord(t *testing.T, path, version string) fetchdomain.ModuleCoordinate {
	t.Helper()
	c, err := fetchdomain.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestPopulate_WritesExpectedFiles verifies that Populate creates the.info,
// .zip,.ziphash and.lock files for a module that is present in the fact store.
func TestPopulate_WritesExpectedFiles(t *testing.T) {
	zipContent := []byte("fake-zip-content")
	blobHandle := fetchports.BlobHandle("fake:zip")

	facts := &fakeFactStore{records: map[string]fetchdomain.FactRecord{
		"example.com/mod@v1.0.0|0.1.0": {
			ModulePath:      "example.com/mod",
			ModuleVersion:   "v1.0.0",
			ModuleHash:      "h1:abcdef",
			PipelineVersion: "0.1.0",
			FetchedAt:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			ContentLocation: string(blobHandle),
		},
	}}
	blobs := &fakeBlobStore{blobs: map[fetchports.BlobHandle][]byte{
		blobHandle: zipContent,
	}}

	cacheDir := t.TempDir()
	coord := newCoord(t, "example.com/mod", "v1.0.0")

	if err := modcache.Populate(context.Background(), facts, blobs, cacheDir, []fetchdomain.ModuleCoordinate{coord}, "0.1.0"); err != nil {
		t.Fatalf("Populate: %v", err)
	}

	base := filepath.Join(cacheDir, "cache", "download", "example.com", "mod", "@v", "v1.0.0")
	for _, ext := range []string{".zip", ".info", ".ziphash", ".lock"} {
		if _, err := os.Stat(base + ext); err != nil {
			t.Errorf("expected file %s: %v", base+ext, err)
		}
	}

	// .zip must contain the blob content
	got, err := os.ReadFile(base + ".zip") // #nosec G304 -- path is t.TempDir()-based, not user input
	if err != nil {
		t.Fatalf("reading zip: %v", err)
	}
	if !bytes.Equal(got, zipContent) {
		t.Errorf("zip content = %q, want %q", got, zipContent)
	}
}

// TestPopulate_IdempotentSecondCall: calling Populate twice writes once and
// does not error on the second call (writeIfAbsent skips existing files).
func TestPopulate_IdempotentSecondCall(t *testing.T) {
	blobHandle := fetchports.BlobHandle("fake:zip2")
	facts := &fakeFactStore{records: map[string]fetchdomain.FactRecord{
		"example.com/mod@v1.0.0|0.1.0": {
			ModulePath: "example.com/mod", ModuleVersion: "v1.0.0",
			ModuleHash: "h1:abcdef", PipelineVersion: "0.1.0",
			FetchedAt: time.Now(), ContentLocation: string(blobHandle),
		},
	}}
	blobs := &fakeBlobStore{blobs: map[fetchports.BlobHandle][]byte{blobHandle: []byte("data")}}
	cacheDir := t.TempDir()
	coord := newCoord(t, "example.com/mod", "v1.0.0")

	for i := range 2 {
		if err := modcache.Populate(context.Background(), facts, blobs, cacheDir, []fetchdomain.ModuleCoordinate{coord}, "0.1.0"); err != nil {
			t.Fatalf("call %d: %v", i+1, err)
		}
	}
}

// TestPopulate_MissingRecordSkipped: a coordinate with no stored fact record
// is skipped silently — Populate never errors for individual misses.
func TestPopulate_MissingRecordSkipped(t *testing.T) {
	facts := &fakeFactStore{records: map[string]fetchdomain.FactRecord{}}
	blobs := &fakeBlobStore{blobs: map[fetchports.BlobHandle][]byte{}}
	coord := newCoord(t, "example.com/missing", "v1.0.0")

	if err := modcache.Populate(context.Background(), facts, blobs, t.TempDir(), []fetchdomain.ModuleCoordinate{coord}, "0.1.0"); err != nil {
		t.Fatalf("Populate must not error for missing records: %v", err)
	}
}

// pathBlobStore is a fakeBlobStore that also implements
// fetchports.BlobPathOptimizer, returning a real on-disk path so Populate takes
// the symlink branch.
type pathBlobStore struct {
	fakeBlobStore
	dir string
}

func (s *pathBlobStore) GetPath(_ context.Context, h fetchports.BlobHandle) (string, error) {
	data, ok := s.blobs[h]
	if !ok {
		return "", os.ErrNotExist
	}
	p := filepath.Join(s.dir, "blob")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return "", err //nolint:wrapcheck // test fake
	}
	return p, nil
}

// TestPopulate_SymlinksWhenPathAvailable: a store implementing
// BlobPathOptimizer makes Populate symlink the cache entry to the blob path
// rather than copying its bytes.
func TestPopulate_SymlinksWhenPathAvailable(t *testing.T) {
	zipContent := []byte("symlinked-zip-content")
	blobHandle := fetchports.BlobHandle("fake:zip")
	facts := &fakeFactStore{records: map[string]fetchdomain.FactRecord{
		"example.com/mod@v1.0.0|0.1.0": {
			ModulePath: "example.com/mod", ModuleVersion: "v1.0.0",
			ModuleHash: "h1:abcdef", PipelineVersion: "0.1.0",
			FetchedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), ContentLocation: string(blobHandle),
		},
	}}
	blobs := &pathBlobStore{
		fakeBlobStore: fakeBlobStore{blobs: map[fetchports.BlobHandle][]byte{blobHandle: zipContent}},
		dir:           t.TempDir(),
	}
	cacheDir := t.TempDir()
	coord := newCoord(t, "example.com/mod", "v1.0.0")

	if err := modcache.Populate(context.Background(), facts, blobs, cacheDir, []fetchdomain.ModuleCoordinate{coord}, "0.1.0"); err != nil {
		t.Fatalf("Populate: %v", err)
	}

	zipPath := filepath.Join(cacheDir, "cache", "download", "example.com", "mod", "@v", "v1.0.0.zip")
	info, err := os.Lstat(zipPath)
	if err != nil {
		t.Fatalf("lstat zip: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("expected %s to be a symlink, mode = %v", zipPath, info.Mode())
	}
	got, err := os.ReadFile(zipPath) // #nosec G304 -- path is t.TempDir()-based
	if err != nil {
		t.Fatalf("reading symlinked zip: %v", err)
	}
	if !bytes.Equal(got, zipContent) {
		t.Errorf("zip content = %q, want %q", got, zipContent)
	}
}

// TestPopulate_WithGoModBlob: when GoModLocation is set, a.mod file must
// be written alongside the.zip.
func TestPopulate_WithGoModBlob(t *testing.T) {
	zipHandle := fetchports.BlobHandle("fake:zip3")
	modHandle := fetchports.BlobHandle("fake:mod3")
	facts := &fakeFactStore{records: map[string]fetchdomain.FactRecord{
		"example.com/mod@v1.0.0|0.1.0": {
			ModulePath: "example.com/mod", ModuleVersion: "v1.0.0",
			ModuleHash: "h1:abc", PipelineVersion: "0.1.0",
			FetchedAt:       time.Now(),
			ContentLocation: string(zipHandle), GoModLocation: string(modHandle),
		},
	}}
	blobs := &fakeBlobStore{blobs: map[fetchports.BlobHandle][]byte{
		zipHandle: []byte("zip"),
		modHandle: []byte("module example.com/mod\n\ngo 1.22\n"),
	}}
	cacheDir := t.TempDir()
	coord := newCoord(t, "example.com/mod", "v1.0.0")

	if err := modcache.Populate(context.Background(), facts, blobs, cacheDir, []fetchdomain.ModuleCoordinate{coord}, "0.1.0"); err != nil {
		t.Fatalf("Populate: %v", err)
	}

	base := filepath.Join(cacheDir, "cache", "download", "example.com", "mod", "@v", "v1.0.0")
	if _, err := os.Stat(base + ".mod"); err != nil {
		t.Errorf("expected .mod file: %v", err)
	}
}

// TestPopulateGoMod_WritesModNotZip verifies the go.mod-only path writes the
// .mod (plus .info and .lock) for a superseded intermediate version and never
// writes a .zip or .ziphash — that version is read for graph bookkeeping only,
// never compiled.
func TestPopulateGoMod_WritesModNotZip(t *testing.T) {
	zipHandle := fetchports.BlobHandle("fake:zipS")
	modHandle := fetchports.BlobHandle("fake:modS")
	facts := &fakeFactStore{records: map[string]fetchdomain.FactRecord{
		"github.com/go-logr/logr@v1.2.2|0.3.0": {
			ModulePath: "github.com/go-logr/logr", ModuleVersion: "v1.2.2",
			ModuleHash: "h1:abc", PipelineVersion: "0.3.0",
			FetchedAt:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			ContentLocation: string(zipHandle), GoModLocation: string(modHandle),
		},
	}}
	blobs := &fakeBlobStore{blobs: map[fetchports.BlobHandle][]byte{
		zipHandle: []byte("zip-should-not-be-written"),
		modHandle: []byte("module github.com/go-logr/logr\n\ngo 1.16\n"),
	}}
	cacheDir := t.TempDir()
	c := newCoord(t, "github.com/go-logr/logr", "v1.2.2")

	if err := modcache.PopulateGoMod(context.Background(), facts, blobs, cacheDir, []fetchdomain.ModuleCoordinate{c}, "0.3.0"); err != nil {
		t.Fatalf("PopulateGoMod: %v", err)
	}

	base := filepath.Join(cacheDir, "cache", "download", "github.com", "go-logr", "logr", "@v", "v1.2.2")
	for _, ext := range []string{".mod", ".info", ".lock"} {
		if _, err := os.Stat(base + ext); err != nil {
			t.Errorf("expected %s file: %v", ext, err)
		}
	}
	for _, ext := range []string{".zip", ".ziphash"} {
		if _, err := os.Stat(base + ext); err == nil {
			t.Errorf("%s must NOT be written for a go.mod-only entry", ext)
		}
	}
	got, err := os.ReadFile(base + ".mod") // #nosec G304 -- t.TempDir()-based path
	if err != nil {
		t.Fatalf("reading mod: %v", err)
	}
	if !bytes.Contains(got, []byte("go 1.16")) {
		t.Errorf("mod content = %q, want the cached go.mod bytes", got)
	}
}

// TestPopulateGoMod_SkipsRecordWithoutGoMod: a fact record with no standalone
// go.mod blob is skipped without error, and no cache entry is created.
func TestPopulateGoMod_SkipsRecordWithoutGoMod(t *testing.T) {
	facts := &fakeFactStore{records: map[string]fetchdomain.FactRecord{
		"example.com/mod@v1.0.0|0.3.0": {
			ModulePath: "example.com/mod", ModuleVersion: "v1.0.0",
			PipelineVersion: "0.3.0", FetchedAt: time.Now(),
			ContentLocation: "fake:zip", // no GoModLocation
		},
	}}
	blobs := &fakeBlobStore{blobs: map[fetchports.BlobHandle][]byte{}}
	cacheDir := t.TempDir()
	c := newCoord(t, "example.com/mod", "v1.0.0")

	if err := modcache.PopulateGoMod(context.Background(), facts, blobs, cacheDir, []fetchdomain.ModuleCoordinate{c}, "0.3.0"); err != nil {
		t.Fatalf("PopulateGoMod must not error for a record without a go.mod blob: %v", err)
	}
	base := filepath.Join(cacheDir, "cache", "download", "example.com", "mod", "@v", "v1.0.0")
	if _, err := os.Stat(base + ".mod"); err == nil {
		t.Error("no .mod entry should be written when the record has no go.mod blob")
	}
}

// TestPopulateGoMod_MissingRecordSkipped: a coordinate absent from the fact
// store is skipped silently.
func TestPopulateGoMod_MissingRecordSkipped(t *testing.T) {
	facts := &fakeFactStore{records: map[string]fetchdomain.FactRecord{}}
	blobs := &fakeBlobStore{blobs: map[fetchports.BlobHandle][]byte{}}
	c := newCoord(t, "example.com/missing", "v1.0.0")

	if err := modcache.PopulateGoMod(context.Background(), facts, blobs, t.TempDir(), []fetchdomain.ModuleCoordinate{c}, "0.3.0"); err != nil {
		t.Fatalf("PopulateGoMod must not error for missing records: %v", err)
	}
}
