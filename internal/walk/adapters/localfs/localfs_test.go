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

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/walk/adapters/localfs"
)

// ---- fakes ----

type fakeBlob struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newFakeBlob() *fakeBlob { return &fakeBlob{data: make(map[string][]byte)} }

func (f *fakeBlob) Put(_ context.Context, identity fetchports.BlobIdentity, content io.Reader) error {
	b, err := io.ReadAll(content)
	if err != nil {
		return fmt.Errorf("reading content: %w", err)
	}
	f.mu.Lock()
	f.data[identity.String()] = b
	f.mu.Unlock()
	return nil
}

func (f *fakeBlob) Get(_ context.Context, identity fetchports.BlobIdentity) (io.ReadCloser, error) {
	f.mu.Lock()
	b := f.data[identity.String()]
	f.mu.Unlock()
	return io.NopCloser(strings.NewReader(string(b))), nil
}

func (f *fakeBlob) GetPath(_ context.Context, identity fetchports.BlobIdentity) (string, error) {
	f.mu.Lock()
	_, ok := f.data[identity.String()]
	f.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("blob not found: %s", identity)
	}
	return "/fake/" + identity.String(), nil
}

func (f *fakeBlob) Exists(_ context.Context, identity fetchports.BlobIdentity) (bool, error) {
	f.mu.Lock()
	_, ok := f.data[identity.String()]
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

func (f *fakeFacts) PutFetchRecord(_ context.Context, sealed fetchdomain.SealedRecord) error {
	if sealed.IsZero() {
		return fetchdomain.ErrUnsealedRecord
	}
	r := sealed.Record()
	key := r.ModulePath + "@" + r.ModuleVersion + "#" + r.PipelineVersion
	f.mu.Lock()
	f.records[key] = r
	f.mu.Unlock()
	return nil
}

func (f *fakeFacts) GetFetchRecord(_ context.Context, coord coordinate.ModuleCoordinate, pv string) (fetchdomain.CompositeRecord, bool, error) {
	key := coord.Path() + "@" + coord.Version() + "#" + pv
	f.mu.Lock()
	r, ok := f.records[key]
	f.mu.Unlock()
	if !ok {
		return fetchdomain.CompositeRecord{}, false, nil
	}
	c, cerr := fetchdomain.Compose([]fetchdomain.FactRecord{r})
	if cerr != nil {
		return fetchdomain.CompositeRecord{}, false, cerr //nolint:wrapcheck // test fake
	}
	return c, true, nil
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
	// A minimal.go file so the zip is non-empty. The package name is fixed
	// rather than derived from the path: a module path ending "/v2" or ".v1"
	// has a last element that is not a usable package name, and the fixture
	// classes that matter here are exactly those.
	src := "package lib\n"
	_ = filepath.Base(modulePath)
	if err := os.WriteFile(filepath.Join(dir, "lib.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("writing lib.go: %v", err)
	}
	_ = version
}

// ---- tests ----

func TestEnsureFetchedFromPath_OK(t *testing.T) {
	dir := t.TempDir()
	coord := coordinatetest.MustNew("example.com/local", "v1.0.0")
	writeLocalModule(t, dir, coord.Path(), coord.Version())

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
	if rec.ModulePath != coord.Path() {
		t.Errorf("ModulePath = %q, want %q", rec.ModulePath, coord.Path())
	}
	if rec.ModuleVersion != coord.Version() {
		t.Errorf("ModuleVersion = %q, want %q", rec.ModuleVersion, coord.Version())
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
	coord := coordinatetest.MustNew("example.com/local", "v1.0.0")
	writeLocalModule(t, dir, coord.Path(), coord.Version())

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
	coord := coordinatetest.MustNew("example.com/local", "v1.0.0")
	// Do NOT write go.mod.

	f := localfs.New(newFakeBlob(), newFakeFacts(), fixedClock{t: time.Now()})
	_, err := f.EnsureFetchedFromPath(context.Background(), coord, dir)
	if err == nil {
		t.Fatal("expected error for missing go.mod, got nil")
	}
}

func TestEnsureFetchedFromPath_NonexistentDir(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/local", "v1.0.0")
	f := localfs.New(newFakeBlob(), newFakeFacts(), fixedClock{t: time.Now()})
	_, err := f.EnsureFetchedFromPath(context.Background(), coord, "/nonexistent/does/not/exist")
	if err == nil {
		t.Fatal("expected error for nonexistent dir, got nil")
	}
}

func TestEnsureFetchedFromPath_HashStability(t *testing.T) {
	dir := t.TempDir()
	coord := coordinatetest.MustNew("example.com/local", "v1.2.3")
	writeLocalModule(t, dir, coord.Path(), coord.Version())

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
	coord := coordinatetest.MustNew("example.com/project", coordinate.LocalVersion)
	writeLocalModule(t, dir, coord.Path(), coord.Version())

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
	coord := coordinatetest.MustNew("example.com/project", coordinate.LocalVersion)
	writeLocalModule(t, dir, coord.Path(), coord.Version())

	blobs := newFakeBlob()
	facts := newFakeFacts()
	f := localfs.New(blobs, facts, fixedClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})

	res, err := f.EnsureFetchedFromPath(context.Background(), coord, dir)
	if err != nil {
		t.Fatalf("EnsureFetchedFromPath: %v", err)
	}

	rc, err := blobs.Get(context.Background(), fetchtest.ZipIdentity(t, res.Record.FactRecord))
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
	wantPrefix := coord.Path() + "@" + coord.Version() + "/"
	for _, zf := range zr.File {
		if !strings.HasPrefix(zf.Name, wantPrefix) {
			t.Errorf("zip entry %q lacks prefix %q", zf.Name, wantPrefix)
		}
	}
}

// TestEnsureFetchedFromPath_StatesThatNoChecksumWasAvailable: a filesystem
// source has no go.sum entry by construction — the toolchain writes a checksum
// for a module it downloads, never for one it reads off disk. The record says
// so, so a local-path replacement reads as an unavailability rather than as a
// check that quietly passed.
func TestEnsureFetchedFromPath_StatesThatNoChecksumWasAvailable(t *testing.T) {
	dir := t.TempDir()
	coord := coordinatetest.MustNew("example.com/local", "v1.0.0")
	writeLocalModule(t, dir, coord.Path(), coord.Version())
	f := localfs.New(newFakeBlob(), newFakeFacts(), fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)})

	res, err := f.EnsureFetchedFromPath(context.Background(), coord, dir)
	if err != nil {
		t.Fatalf("EnsureFetchedFromPath: %v", err)
	}
	rec := res.Record
	if rec.VerificationStatus != string(fetchdomain.LocalSource) {
		t.Errorf("VerificationStatus = %q, want LocalSource", rec.VerificationStatus)
	}
	if !strings.Contains(rec.VerificationDetail, "no checksum is available") {
		t.Errorf("VerificationDetail %q does not state that no checksum was available", rec.VerificationDetail)
	}
}

// TestEnsureFetchedFromPath_LocalVersionAtMajorSuffixPath: the project-walk
// root is zipped under a placeholder version before its entry prefix is
// rewritten, and modzip validates the path/version pair before it writes
// anything. Go requires a path carrying a major suffix to carry a version of
// that major, so a fixed v0.0.0 placeholder rejected every module at major 2
// or above — the whole class that has ever done a major bump properly. The
// fixture must carry the suffix: one at major 0 or 1 passes on the broken
// code and proves nothing.
func TestEnsureFetchedFromPath_LocalVersionAtMajorSuffixPath(t *testing.T) {
	for _, modulePath := range []string{
		"example.com/project/v2",
		"example.com/project/v10",
		// gopkg.in spells the major as a dot on the last element, not a
		// slash-separated one. A "/vN" parser builds a path that cannot exist,
		// and v0.0.0 is rejected here too — gopkg.in/check.v1 needs v1.
		"gopkg.in/check.v1",
		"gopkg.in/project.v4",
	} {
		t.Run(modulePath, func(t *testing.T) {
			dir := t.TempDir()
			coord := coordinatetest.MustNew(modulePath, coordinate.LocalVersion)
			writeLocalModule(t, dir, coord.Path(), coord.Version())

			blobs := newFakeBlob()
			facts := newFakeFacts()
			f := localfs.New(blobs, facts, fixedClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})

			res, err := f.EnsureFetchedFromPath(context.Background(), coord, dir)
			if err != nil {
				t.Fatalf("EnsureFetchedFromPath: %v", err)
			}

			// The rewrite back to the synthetic local coordinate is symmetric in
			// the placeholder, so every consumer still derives the prefix from
			// the coordinate whatever major the path carried.
			rc, err := blobs.Get(context.Background(), fetchtest.ZipIdentity(t, res.Record.FactRecord))
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
			wantPrefix := coord.Path() + "@" + coord.Version() + "/"
			for _, zf := range zr.File {
				if !strings.HasPrefix(zf.Name, wantPrefix) {
					t.Errorf("zip entry %q lacks prefix %q", zf.Name, wantPrefix)
				}
			}
		})
	}
}

// TestEnsureFetchedFromPath_LocalVersionAtUnsuffixedPathIsUnchanged: the
// control. Majors 0 and 1 share the unsuffixed path and keep the v0.0.0
// placeholder, so the zip an unsuffixed project produces is byte-identical to
// what it produced before the major was derived from the path. The golden is
// the h1 this exact fixture yielded from the constant-placeholder code, and
// the assertion is on the module hash because that is what every downstream
// record keys on. The fixture is written here rather than through the shared
// helper so a later edit to the helper cannot silently move the golden.
func TestEnsureFetchedFromPath_LocalVersionAtUnsuffixedPathIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/project\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lib.go"), []byte("package project\n"), 0o600); err != nil {
		t.Fatalf("writing lib.go: %v", err)
	}
	coord := coordinatetest.MustNew("example.com/project", coordinate.LocalVersion)

	blobs := newFakeBlob()
	facts := newFakeFacts()
	f := localfs.New(blobs, facts, fixedClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})

	res, err := f.EnsureFetchedFromPath(context.Background(), coord, dir)
	if err != nil {
		t.Fatalf("EnsureFetchedFromPath: %v", err)
	}
	const want = "h1:MpJUZoU8nNl0L8/OVcpSxW+nhKT+mnZU2ldLZrzPeVc="
	if got := res.Record.ModuleHash; got != want {
		t.Errorf("module hash = %s, want %s (the unsuffixed placeholder must not have moved)", got, want)
	}
}
