package application_test

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"testing"
	"testing/fstest"
	"time"

	"github.com/eitanity/kanonarion/internal/stdlib/application"
	"github.com/eitanity/kanonarion/internal/stdlib/domain"
)

// --- offline fakes ---

type fakeToolchain struct {
	goRoot  string
	version string
	err     error
	calls   int
}

func (f *fakeToolchain) Locate(context.Context) (string, string, error) {
	f.calls++
	return f.goRoot, f.version, f.err
}

type fakeSource struct {
	fsys       fs.FS
	fsErr      error
	license    []byte
	licenseErr error
}

func (f fakeSource) SourceFS(string) (fs.FS, error) {
	if f.fsErr != nil {
		return nil, f.fsErr
	}
	return f.fsys, nil
}

func (f fakeSource) LicenseText(string) ([]byte, error) { return f.license, f.licenseErr }

func newLocalAcquirer(t *testing.T, tc *fakeToolchain, src fakeSource, lic fakeLicense, store *memStore) *application.LocalAcquirer {
	t.Helper()
	return application.NewLocalAcquirer(tc, src, lic, store, fixedClock{t: time.Unix(1_700_000_000, 0)},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func stdlibSrcFS() fs.FS {
	return fstest.MapFS{
		"runtime/proc.go":   {Data: []byte("package runtime\n")},
		"fmt/print.go":      {Data: []byte("package fmt\n")},
		"internal/abi/x.go": {Data: []byte("package abi\n")},
	}
}

// --- tests ---

func TestLocalAcquire_HappyPath(t *testing.T) {
	tc := &fakeToolchain{goRoot: "/opt/go", version: "go1.26.4"}
	src := fakeSource{fsys: stdlibSrcFS(), license: []byte("BSD-3-Clause text")}
	store := newMemStore()
	acq := newLocalAcquirer(t, tc, src, fakeLicense{spdx: "BSD-3-Clause"}, store)

	facts, err := acq.Acquire(context.Background(), "v1.26.4", application.Options{})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if facts.VerificationStatus != domain.VerifiedLocalToolchain {
		t.Errorf("status = %s, want VerifiedLocalToolchain", facts.VerificationStatus)
	}
	if facts.VerificationStatus.Verified() {
		t.Error("VerifiedLocalToolchain must not report Verified() true")
	}
	if facts.Digests.IsZero() {
		t.Error("expected non-zero digests over the local source tree")
	}
	if facts.LicenseSPDX != "BSD-3-Clause" {
		t.Errorf("license = %q, want BSD-3-Clause", facts.LicenseSPDX)
	}
	if facts.GoVersion != "go1.26.4" {
		t.Errorf("go version = %q, want go1.26.4", facts.GoVersion)
	}
	if facts.VCSCommit != "" {
		t.Errorf("VCSCommit = %q, want empty (offline never resolves VCS)", facts.VCSCommit)
	}
	if facts.PublishedSHA256 != "" {
		t.Errorf("PublishedSHA256 = %q, want empty (go.dev/dl not consulted)", facts.PublishedSHA256)
	}
	if store.puts != 1 {
		t.Errorf("store.puts = %d, want 1", store.puts)
	}
}

func TestLocalAcquire_DigestsAreDeterministic(t *testing.T) {
	src := fakeSource{fsys: stdlibSrcFS(), license: []byte("x")}
	a := newLocalAcquirer(t, &fakeToolchain{goRoot: "/opt/go", version: "go1.26.4"}, src, fakeLicense{}, newMemStore())
	b := newLocalAcquirer(t, &fakeToolchain{goRoot: "/other/go", version: "go1.26.4"}, src, fakeLicense{}, newMemStore())

	fa, err := a.Acquire(context.Background(), "go1.26.4", application.Options{})
	if err != nil {
		t.Fatal(err)
	}
	fb, err := b.Acquire(context.Background(), "go1.26.4", application.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if fa.Digests != fb.Digests {
		t.Errorf("digests differ for identical source: %+v vs %+v", fa.Digests, fb.Digests)
	}
}

func TestLocalAcquire_CacheHitSkipsToolchain(t *testing.T) {
	store := newMemStore()
	store.m["go1.26.4"] = domain.Facts{GoVersion: "go1.26.4", VerificationStatus: domain.VerifiedGoDevChecksum}
	tc := &fakeToolchain{err: errors.New("must not be called")}
	acq := newLocalAcquirer(t, tc, fakeSource{}, fakeLicense{}, store)

	facts, err := acq.Acquire(context.Background(), "go1.26.4", application.Options{})
	if err != nil {
		t.Fatalf("Acquire cache hit: %v", err)
	}
	if facts.VerificationStatus != domain.VerifiedGoDevChecksum {
		t.Errorf("cache hit should preserve stronger online anchor, got %s", facts.VerificationStatus)
	}
	if tc.calls != 0 {
		t.Errorf("toolchain probed %d times on cache hit, want 0", tc.calls)
	}
}

func TestLocalAcquire_UndeterminableVersion(t *testing.T) {
	acq := newLocalAcquirer(t, &fakeToolchain{}, fakeSource{}, fakeLicense{}, newMemStore())
	_, err := acq.Acquire(context.Background(), "", application.Options{})
	if !errors.Is(err, application.ErrUndeterminableVersion) {
		t.Errorf("err = %v, want ErrUndeterminableVersion", err)
	}
}

func TestLocalAcquire_ToolchainFailureIsHardError(t *testing.T) {
	tc := &fakeToolchain{err: errors.New("go not found")}
	acq := newLocalAcquirer(t, tc, fakeSource{}, fakeLicense{}, newMemStore())
	_, err := acq.Acquire(context.Background(), "go1.26.4", application.Options{})
	if err == nil {
		t.Error("toolchain probe failure should be a hard error")
	}
}

func TestLocalAcquire_SourceFailureIsHardError(t *testing.T) {
	src := fakeSource{fsErr: errors.New("no src dir")}
	acq := newLocalAcquirer(t, &fakeToolchain{goRoot: "/opt/go", version: "go1.26.4"}, src, fakeLicense{}, newMemStore())
	_, err := acq.Acquire(context.Background(), "go1.26.4", application.Options{})
	if err == nil {
		t.Error("unreadable source tree should be a hard error")
	}
}

func TestLocalAcquire_MissingLicenseIsCoverageGap(t *testing.T) {
	src := fakeSource{fsys: stdlibSrcFS(), licenseErr: errors.New("no LICENSE")}
	acq := newLocalAcquirer(t, &fakeToolchain{goRoot: "/opt/go", version: "go1.26.4"}, src, fakeLicense{}, newMemStore())
	facts, err := acq.Acquire(context.Background(), "go1.26.4", application.Options{})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if facts.LicenseSPDX != "" {
		t.Errorf("LicenseSPDX = %q, want empty on unreadable LICENSE", facts.LicenseSPDX)
	}
}
