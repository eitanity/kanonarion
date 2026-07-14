package application_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/stdlib/application"
	"github.com/eitanity/kanonarion/internal/stdlib/domain"
)

// --- fakes ---

type fakeManifest struct {
	releases []domain.Release
	err      error
}

func (f fakeManifest) FetchReleases(context.Context) ([]domain.Release, error) {
	return f.releases, f.err
}

type fakeTarball struct {
	data []byte
	err  error
	url  string
}

func (f *fakeTarball) Download(_ context.Context, url string) ([]byte, error) {
	f.url = url
	return f.data, f.err
}

type fakeCommits struct {
	commit string
	err    error
	calls  int
}

func (f *fakeCommits) ResolveCommit(context.Context, string, string) (string, error) {
	f.calls++
	return f.commit, f.err
}

type fakeLicense struct {
	spdx string
	err  error
}

func (f fakeLicense) Identify(context.Context, []byte) (string, error) { return f.spdx, f.err }

type memStore struct {
	m     map[string]domain.Facts
	puts  int
	getErr error
}

func newMemStore() *memStore { return &memStore{m: map[string]domain.Facts{}} }

func (s *memStore) Get(_ context.Context, v string) (domain.Facts, bool, error) {
	if s.getErr != nil {
		return domain.Facts{}, false, s.getErr
	}
	f, ok := s.m[v]
	return f, ok, nil
}

func (s *memStore) Put(_ context.Context, f domain.Facts) error {
	s.puts++
	s.m[f.GoVersion] = f
	return nil
}

type memBlobs struct{ puts int }

func (b *memBlobs) Put(_ context.Context, r io.Reader) (fetchports.BlobHandle, error) {
	b.puts++
	data, _ := io.ReadAll(r)
	sum := sha256.Sum256(data)
	return fetchports.BlobHandle("sha256:" + hex.EncodeToString(sum[:])), nil
}
func (b *memBlobs) Get(context.Context, fetchports.BlobHandle) (io.ReadCloser, error) { return nil, nil }
func (b *memBlobs) Exists(context.Context, fetchports.BlobHandle) (bool, error)       { return false, nil }
func (b *memBlobs) GetPath(context.Context, fetchports.BlobHandle) (string, error)    { return "", nil }

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// buildTarball assembles a gzip'd tar containing the given entries.
func buildTarball(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func newAcquirer(t *testing.T, m fakeManifest, tb *fakeTarball, c *fakeCommits, l fakeLicense, store *memStore, blobs fetchports.BlobStore) *application.Acquirer {
	t.Helper()
	return application.NewAcquirer(m, tb, c, l, store, blobs, fixedClock{t: time.Unix(1_700_000_000, 0)}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// --- tests ---

func TestAcquire_HappyPath_VerifiedChecksum(t *testing.T) {
	tb := buildTarball(t, map[string]string{"go/LICENSE": "BSD-3-Clause text"})
	sum := sha256hex(tb)
	m := fakeManifest{releases: []domain.Release{{Version: "go1.26.4", Files: []domain.ReleaseFile{{Filename: "go1.26.4.src.tar.gz", Kind: "source", SHA256: sum}}}}}
	store := newMemStore()
	blobs := &memBlobs{}
	acq := newAcquirer(t, m, &fakeTarball{data: tb}, &fakeCommits{commit: "abc123"}, fakeLicense{spdx: "BSD-3-Clause"}, store, blobs)

	facts, err := acq.Acquire(context.Background(), "v1.26.4", application.Options{})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if facts.VerificationStatus != domain.VerifiedGoDevChecksum {
		t.Errorf("status = %s, want VerifiedGoDevChecksum", facts.VerificationStatus)
	}
	if facts.Digests.SHA256 != sum || facts.PublishedSHA256 != sum {
		t.Errorf("digest/published mismatch: %s / %s / want %s", facts.Digests.SHA256, facts.PublishedSHA256, sum)
	}
	if facts.LicenseSPDX != "BSD-3-Clause" {
		t.Errorf("license = %q, want BSD-3-Clause", facts.LicenseSPDX)
	}
	if facts.VCSCommit != "abc123" {
		t.Errorf("commit = %q, want abc123", facts.VCSCommit)
	}
	if facts.GoVersion != "go1.26.4" {
		t.Errorf("go version = %q, want go1.26.4", facts.GoVersion)
	}
	if facts.ContentLocation == "" {
		t.Error("expected tarball to be cached in blob store")
	}
	if store.puts != 1 || blobs.puts != 1 {
		t.Errorf("store.puts=%d blobs.puts=%d, want 1/1", store.puts, blobs.puts)
	}
}

func TestAcquire_ChecksumMismatch_RecordedNotFailed(t *testing.T) {
	tb := buildTarball(t, map[string]string{"go/LICENSE": "x"})
	m := fakeManifest{releases: []domain.Release{{Version: "go1.26.4", Files: []domain.ReleaseFile{{Kind: "source", SHA256: "deadbeef"}}}}}
	acq := newAcquirer(t, m, &fakeTarball{data: tb}, &fakeCommits{}, fakeLicense{spdx: "BSD-3-Clause"}, newMemStore(), nil)

	facts, err := acq.Acquire(context.Background(), "go1.26.4", application.Options{})
	if err != nil {
		t.Fatalf("Acquire should not fail on mismatch: %v", err)
	}
	if facts.VerificationStatus != domain.GoDevChecksumMismatch {
		t.Errorf("status = %s, want GoDevChecksumMismatch", facts.VerificationStatus)
	}
	if facts.ContentLocation != "" {
		t.Error("no blob store wired; ContentLocation should be empty")
	}
}

func TestAcquire_ManifestUnavailable(t *testing.T) {
	tb := buildTarball(t, map[string]string{"go/LICENSE": "x"})
	m := fakeManifest{err: errors.New("offline")}
	acq := newAcquirer(t, m, &fakeTarball{data: tb}, &fakeCommits{commit: "c1"}, fakeLicense{spdx: "BSD-3-Clause"}, newMemStore(), nil)

	facts, err := acq.Acquire(context.Background(), "go1.26.4", application.Options{})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if facts.VerificationStatus != domain.UnverifiedGoDevUnavailable {
		t.Errorf("status = %s, want UnverifiedGoDevUnavailable", facts.VerificationStatus)
	}
}

func TestAcquire_SkipVCS(t *testing.T) {
	tb := buildTarball(t, map[string]string{"go/LICENSE": "x"})
	m := fakeManifest{releases: []domain.Release{{Version: "go1.26.4", Files: []domain.ReleaseFile{{Kind: "source", SHA256: sha256hex(tb)}}}}}
	commits := &fakeCommits{commit: "c1"}
	acq := newAcquirer(t, m, &fakeTarball{data: tb}, commits, fakeLicense{spdx: "BSD-3-Clause"}, newMemStore(), nil)

	facts, err := acq.Acquire(context.Background(), "go1.26.4", application.Options{SkipVCS: true})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if commits.calls != 0 {
		t.Errorf("commit resolver called %d times under SkipVCS, want 0", commits.calls)
	}
	if facts.VCSCommit != "" {
		t.Errorf("VCSCommit = %q under SkipVCS, want empty", facts.VCSCommit)
	}
}

func TestAcquire_CacheHitSkipsDownload(t *testing.T) {
	store := newMemStore()
	store.m["go1.26.4"] = domain.Facts{GoVersion: "go1.26.4", VerificationStatus: domain.VerifiedGoDevChecksum}
	tb := &fakeTarball{err: errors.New("must not be called")}
	acq := newAcquirer(t, fakeManifest{}, tb, &fakeCommits{}, fakeLicense{}, store, nil)

	facts, err := acq.Acquire(context.Background(), "go1.26.4", application.Options{})
	if err != nil {
		t.Fatalf("Acquire cache hit: %v", err)
	}
	if facts.VerificationStatus != domain.VerifiedGoDevChecksum {
		t.Errorf("unexpected facts from cache: %+v", facts)
	}
	if tb.url != "" {
		t.Error("tarball download should not run on cache hit")
	}
}

func TestAcquire_ForceReacquires(t *testing.T) {
	tb := buildTarball(t, map[string]string{"go/LICENSE": "x"})
	store := newMemStore()
	store.m["go1.26.4"] = domain.Facts{GoVersion: "go1.26.4", VerificationStatus: domain.GoDevChecksumMismatch}
	m := fakeManifest{releases: []domain.Release{{Version: "go1.26.4", Files: []domain.ReleaseFile{{Kind: "source", SHA256: sha256hex(tb)}}}}}
	acq := newAcquirer(t, m, &fakeTarball{data: tb}, &fakeCommits{commit: "c1"}, fakeLicense{spdx: "BSD-3-Clause"}, store, nil)

	facts, err := acq.Acquire(context.Background(), "go1.26.4", application.Options{Force: true})
	if err != nil {
		t.Fatalf("Acquire force: %v", err)
	}
	if facts.VerificationStatus != domain.VerifiedGoDevChecksum {
		t.Errorf("force should re-verify: status = %s", facts.VerificationStatus)
	}
}

func TestAcquire_UndeterminableVersion(t *testing.T) {
	acq := newAcquirer(t, fakeManifest{}, &fakeTarball{}, &fakeCommits{}, fakeLicense{}, newMemStore(), nil)
	_, err := acq.Acquire(context.Background(), "", application.Options{})
	if !errors.Is(err, application.ErrUndeterminableVersion) {
		t.Errorf("err = %v, want ErrUndeterminableVersion", err)
	}
}

func TestAcquire_DownloadFailureIsHardError(t *testing.T) {
	acq := newAcquirer(t, fakeManifest{}, &fakeTarball{err: errors.New("404")}, &fakeCommits{}, fakeLicense{}, newMemStore(), nil)
	_, err := acq.Acquire(context.Background(), "go1.26.4", application.Options{})
	if err == nil {
		t.Error("download failure should be a hard error")
	}
}

func TestAcquire_MissingLicenseIsCoverageGap(t *testing.T) {
	tb := buildTarball(t, map[string]string{"go/README": "x"})
	m := fakeManifest{releases: []domain.Release{{Version: "go1.26.4", Files: []domain.ReleaseFile{{Kind: "source", SHA256: sha256hex(tb)}}}}}
	acq := newAcquirer(t, m, &fakeTarball{data: tb}, &fakeCommits{commit: "c1"}, fakeLicense{}, newMemStore(), nil)

	facts, err := acq.Acquire(context.Background(), "go1.26.4", application.Options{})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if facts.LicenseSPDX != "" {
		t.Errorf("LicenseSPDX = %q, want empty on missing LICENSE", facts.LicenseSPDX)
	}
}
