package localfs_test

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/walk/adapters/localfs"
)

// ---- fakes ----

type fakeBlob struct {
	mu   sync.Mutex
	data map[fetchports.BlobHandle][]byte
}

func newFakeBlob() *fakeBlob { return &fakeBlob{data: make(map[fetchports.BlobHandle][]byte)} }

func (f *fakeBlob) Put(_ context.Context, content io.Reader) (fetchports.BlobHandle, error) {
	b, err := io.ReadAll(content)
	if err != nil {
		return "", fmt.Errorf("reading content: %w", err)
	}
	h := fetchports.BlobHandle(fmt.Sprintf("blob:%x", len(b)))
	f.mu.Lock()
	f.data[h] = b
	f.mu.Unlock()
	return h, nil
}

func (f *fakeBlob) Get(_ context.Context, h fetchports.BlobHandle) (io.ReadCloser, error) {
	f.mu.Lock()
	b := f.data[h]
	f.mu.Unlock()
	return io.NopCloser(strings.NewReader(string(b))), nil
}

func (f *fakeBlob) GetPath(_ context.Context, h fetchports.BlobHandle) (string, error) {
	f.mu.Lock()
	_, ok := f.data[h]
	f.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("blob not found: %s", h)
	}
	return "/fake/" + string(h), nil
}

func (f *fakeBlob) Exists(_ context.Context, h fetchports.BlobHandle) (bool, error) {
	f.mu.Lock()
	_, ok := f.data[h]
	f.mu.Unlock()
	return ok, nil
}

type fakeFacts struct {
	mu      sync.Mutex
	records map[string]fetchdomain.FactRecord
}

func newFakeFacts() *fakeFacts {
	return &fakeFacts{records: make(map[string]fetchdomain.FactRecord)}
}

func (f *fakeFacts) PutFetchRecord(_ context.Context, r fetchdomain.FactRecord) error {
	key := r.ModulePath + "@" + r.ModuleVersion + "#" + r.PipelineVersion
	f.mu.Lock()
	f.records[key] = r
	f.mu.Unlock()
	return nil
}

func (f *fakeFacts) GetFetchRecord(_ context.Context, coord fetchdomain.ModuleCoordinate, pv string) (fetchdomain.FactRecord, bool, error) {
	key := coord.Path + "@" + coord.Version + "#" + pv
	f.mu.Lock()
	r, ok := f.records[key]
	f.mu.Unlock()
	return r, ok, nil
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// ---- helpers ----

func writeLocalModule(t *testing.T, dir, modulePath, version string) {
	t.Helper()
	goModContent := fmt.Sprintf("module %s\n\ngo 1.21\n", modulePath)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goModContent), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	// A minimal.go file so the zip is non-empty.
	src := fmt.Sprintf("package %s\n", filepath.Base(modulePath))
	if err := os.WriteFile(filepath.Join(dir, "lib.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("writing lib.go: %v", err)
	}
	_ = version
}

// ---- tests ----

func TestEnsureFetchedFromPath_OK(t *testing.T) {
	dir := t.TempDir()
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/local", Version: "v1.0.0"}
	writeLocalModule(t, dir, coord.Path, coord.Version)

	blobs := newFakeBlob()
	facts := newFakeFacts()
	clk := fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	f := localfs.New(blobs, facts, clk)

	res, err := f.EnsureFetchedFromPath(context.Background(), coord, dir)
	if err != nil {
		t.Fatalf("EnsureFetchedFromPath: %v", err)
	}
	if res.FromCache {
		t.Error("expected FromCache=false on first call")
	}

	rec := res.Record
	if rec.ModulePath != coord.Path {
		t.Errorf("ModulePath = %q, want %q", rec.ModulePath, coord.Path)
	}
	if rec.ModuleVersion != coord.Version {
		t.Errorf("ModuleVersion = %q, want %q", rec.ModuleVersion, coord.Version)
	}
	if rec.VerificationStatus != string(fetchdomain.LocalSource) {
		t.Errorf("VerificationStatus = %q, want %q", rec.VerificationStatus, fetchdomain.LocalSource)
	}
	if rec.PipelineVersion != localfs.PipelineVersion {
		t.Errorf("PipelineVersion = %q, want %q", rec.PipelineVersion, localfs.PipelineVersion)
	}
	if rec.ContentLocation == "" {
		t.Error("ContentLocation is empty; zip blob was not stored")
	}
	if rec.GoModLocation == "" {
		t.Error("GoModLocation is empty; go.mod blob was not stored")
	}
	if rec.ContentHash == "" {
		t.Error("ContentHash is empty")
	}
	if !strings.HasPrefix(rec.ContentHash, "sha256:") {
		t.Errorf("ContentHash has unexpected prefix: %q", rec.ContentHash)
	}
	if !strings.Contains(rec.VerificationDetail, dir) {
		t.Errorf("VerificationDetail %q does not contain local path %q", rec.VerificationDetail, dir)
	}
}

func TestEnsureFetchedFromPath_Cache(t *testing.T) {
	dir := t.TempDir()
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/local", Version: "v1.0.0"}
	writeLocalModule(t, dir, coord.Path, coord.Version)

	blobs := newFakeBlob()
	facts := newFakeFacts()
	clk := fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	f := localfs.New(blobs, facts, clk)

	first, err := f.EnsureFetchedFromPath(context.Background(), coord, dir)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if first.FromCache {
		t.Error("first call: expected FromCache=false")
	}

	second, err := f.EnsureFetchedFromPath(context.Background(), coord, dir)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !second.FromCache {
		t.Error("second call: expected FromCache=true")
	}
	if second.Record.ContentHash != first.Record.ContentHash {
		t.Errorf("cached record ContentHash differs: %q vs %q", second.Record.ContentHash, first.Record.ContentHash)
	}
}

func TestEnsureFetchedFromPath_MissingGoMod(t *testing.T) {
	dir := t.TempDir()
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/local", Version: "v1.0.0"}
	// Do NOT write go.mod.

	f := localfs.New(newFakeBlob(), newFakeFacts(), fixedClock{t: time.Now()})
	_, err := f.EnsureFetchedFromPath(context.Background(), coord, dir)
	if err == nil {
		t.Fatal("expected error for missing go.mod, got nil")
	}
}

func TestEnsureFetchedFromPath_NonexistentDir(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/local", Version: "v1.0.0"}
	f := localfs.New(newFakeBlob(), newFakeFacts(), fixedClock{t: time.Now()})
	_, err := f.EnsureFetchedFromPath(context.Background(), coord, "/nonexistent/does/not/exist")
	if err == nil {
		t.Fatal("expected error for nonexistent dir, got nil")
	}
}

func TestEnsureFetchedFromPath_HashStability(t *testing.T) {
	dir := t.TempDir()
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/local", Version: "v1.2.3"}
	writeLocalModule(t, dir, coord.Path, coord.Version)

	clk := fixedClock{t: time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)}

	res1, err := localfs.New(newFakeBlob(), newFakeFacts(), clk).EnsureFetchedFromPath(context.Background(), coord, dir)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	res2, err := localfs.New(newFakeBlob(), newFakeFacts(), clk).EnsureFetchedFromPath(context.Background(), coord, dir)
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if res1.Record.ContentHash != res2.Record.ContentHash {
		t.Errorf("ContentHash not stable: %q vs %q", res1.Record.ContentHash, res2.Record.ContentHash)
	}
	if res1.Record.ModuleHash != res2.Record.ModuleHash {
		t.Errorf("ModuleHash not stable: %q vs %q", res1.Record.ModuleHash, res2.Record.ModuleHash)
	}
}

// The project-walk root pins the synthetic local version, which does not pin
// content: the working tree mutates between runs. A local coordinate must
// bypass the cache and re-read the tree on every call, so an edit between two
// calls is reflected in the second record.
func TestEnsureFetchedFromPath_LocalVersionIsNeverServedFromCache(t *testing.T) {
	dir := t.TempDir()
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/project", Version: fetchdomain.LocalVersion}
	writeLocalModule(t, dir, coord.Path, coord.Version)

	blobs := newFakeBlob()
	facts := newFakeFacts()
	f := localfs.New(blobs, facts, fixedClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})

	first, err := f.EnsureFetchedFromPath(context.Background(), coord, dir)
	if err != nil {
		t.Fatalf("first EnsureFetchedFromPath: %v", err)
	}

	// Mutate the working tree between calls.
	if werr := os.WriteFile(filepath.Join(dir, "extra.go"), []byte("package project\n"), 0o600); werr != nil {
		t.Fatalf("writing extra.go: %v", werr)
	}

	second, err := f.EnsureFetchedFromPath(context.Background(), coord, dir)
	if err != nil {
		t.Fatalf("second EnsureFetchedFromPath: %v", err)
	}
	if second.FromCache {
		t.Error("FromCache = true for a local coordinate, want a fresh re-read")
	}
	if second.Record.ModuleHash == first.Record.ModuleHash {
		t.Error("ModuleHash unchanged after editing the tree; stale cached content was served")
	}
}

// The root's zip entries must sit under the coordinate-derived prefix
// (path@local/) so every consumer that strips the prefix from the coordinate
// (license, interface, callgraph, example, vuln) can read the archive.
func TestEnsureFetchedFromPath_LocalVersionZipUsesLocalPrefix(t *testing.T) {
	dir := t.TempDir()
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/project", Version: fetchdomain.LocalVersion}
	writeLocalModule(t, dir, coord.Path, coord.Version)

	blobs := newFakeBlob()
	facts := newFakeFacts()
	f := localfs.New(blobs, facts, fixedClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})

	res, err := f.EnsureFetchedFromPath(context.Background(), coord, dir)
	if err != nil {
		t.Fatalf("EnsureFetchedFromPath: %v", err)
	}

	rc, err := blobs.Get(context.Background(), fetchports.BlobHandle(res.Record.ContentLocation))
	if err != nil {
		t.Fatalf("Get blob: %v", err)
	}
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading blob: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("opening zip: %v", err)
	}
	if len(zr.File) == 0 {
		t.Fatal("zip is empty")
	}
	wantPrefix := coord.Path + "@" + coord.Version + "/"
	for _, zf := range zr.File {
		if !strings.HasPrefix(zf.Name, wantPrefix) {
			t.Errorf("zip entry %q lacks prefix %q", zf.Name, wantPrefix)
		}
	}
}
