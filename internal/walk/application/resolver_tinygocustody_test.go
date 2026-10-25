package application_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/walk/adapters/gomod/xmod"
	"github.com/eitanity/kanonarion/internal/walk/application"
	domain3 "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

const tinygoAt = "github.com/tinygo-org/tinygo@v0.42.0"

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// fakeRelease is the release leg, recording what it was asked.
type fakeRelease struct {
	release domain3.TinyGoRelease
	asked   []string
	forced  []bool
}

func (f *fakeRelease) AcquireTinyGoRelease(_ context.Context, version, goos, goarch string, force bool) domain3.TinyGoRelease {
	f.asked = append(f.asked, version+" "+goos+"/"+goarch)
	f.forced = append(f.forced, force)
	return f.release
}

// tinyGoZip is TinyGo's module zip holding src files.
func tinyGoZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, body := range files {
		f, err := w.Create(tinygoAt + "/src/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// custodyResolver wires a TinyGo walk whose module zip carries machine.go and
// whose install also compiles a generated rp2040.go.
func custodyResolver(t *testing.T, rel *fakeRelease, zipFiles map[string]string, status domain2.VerificationStatus, log *bytes.Buffer) (*application.GraphResolver, *fakeModuleFetcher) {
	t.Helper()
	blobs, fetcher := newFakeBlobStore(), newFakeFetcher()
	bl := tinyGoBuildList()
	bl.TinyGoHostGOOS, bl.TinyGoHostGOARCH = "linux", "amd64"
	bl.TinyGoFiles = []domain3.TinyGoSourceFile{
		{Path: "device/rp/rp2040.go", SHA256: sha("generated")},
		{Path: "machine/machine.go", SHA256: sha("package machine")},
	}
	if zipFiles != nil {
		rec := fetchtest.Record(t, fetchtest.Module("github.com/tinygo-org/tinygo", "v0.42.0"),
			fetchtest.PipelineVersion("1.0.0"), fetchtest.Content(tinygoAt), fetchtest.SchemaVersion("2"), fetchtest.Status(status))
		fetcher.records[tinygoAt] = mustComposeOne(t, rec)
		seedZipBlob(t, blobs, rec, tinyGoZip(t, zipFiles))
	}
	r := newResolver(fetcher, blobs).WithBuildListResolver(&fakeBuildListResolver{list: bl})
	if log != nil {
		r = application.NewGraphResolver(xmod.New(), fetcher, blobs, fixedClock{fixedNow}, "", slog.New(slog.NewTextHandler(log, nil))).
			WithBuildListResolver(&fakeBuildListResolver{list: bl})
	}
	if rel != nil {
		r = r.WithTinyGoReleaseAcquirer(rel)
	}
	return r, fetcher
}

func resolveCustody(t *testing.T, ctx context.Context, r *application.GraphResolver, force bool) *domain3.TinyGoCustody {
	t.Helper()
	target := coord("example.com/project", coordinate.LocalVersion)
	g, err := r.ResolveProject(ctx, target, []byte("module example.com/project\n\ngo 1.21\n"), "/proj",
		domain3.DefaultDepthPolicy().FetchStage(), nil, false, force)
	if err != nil {
		t.Fatalf("ResolveProject: %v", err)
	}
	for _, n := range g.Nodes {
		if n.TinyGo != nil {
			return n.TinyGo.Custody
		}
	}
	t.Fatal("no node carries the TinyGo split")
	return nil
}

func matched() domain3.TinyGoRelease {
	return domain3.TinyGoRelease{Asset: "tinygo0.42.0.linux-amd64.tar.gz", Outcome: domain3.TinyGoReleaseDigestMatched,
		MeasuredAt: time.Date(2026, 10, 23, 2, 0, 0, 0, time.UTC), Manifest: map[string]string{"device/rp/rp2040.go": sha("generated")}}
}

func TestResolveProject_TinyGoCustody_BothAnchors(t *testing.T) {
	rel := &fakeRelease{release: matched()}
	r, fetcher := custodyResolver(t, rel, map[string]string{"machine/machine.go": "package machine"}, domain2.Verified, nil)

	c := resolveCustody(t, context.Background(), r, true)

	if c == nil || c.VerifiedByModule != 1 || c.VerifiedByRelease != 1 || len(c.Differs) != 0 || len(c.NotEstablished) != 0 {
		t.Fatalf("custody = %+v", c)
	}
	if c.Module != tinygoAt || c.ModuleVerification != "Verified" || c.ReleaseAsset != "tinygo0.42.0.linux-amd64.tar.gz" {
		t.Errorf("custody anchors = %+v", c)
	}
	if !fetcher.fetched("github.com/tinygo-org/tinygo") {
		t.Error("the module was not fetched through the walk's fetcher")
	}
	if len(rel.asked) != 1 || rel.asked[0] != "0.42.0 linux/amd64" || !rel.forced[0] {
		t.Errorf("release asked %v forced %v, want once for the host platform with force passed through", rel.asked, rel.forced)
	}
}

func TestResolveProject_TinyGoCustody_NoReleaseWhenTheZipCarriesEveryFile(t *testing.T) {
	rel := &fakeRelease{release: matched()}
	r, _ := custodyResolver(t, rel, map[string]string{"machine/machine.go": "package machine", "device/rp/rp2040.go": "generated"}, domain2.Verified, nil)
	c := resolveCustody(t, context.Background(), r, false)
	if c.VerifiedByModule != 2 || c.ReleaseAsset != "" || len(rel.asked) != 0 {
		t.Errorf("custody %+v after %d release requests, want the module alone", c, len(rel.asked))
	}
}

func TestResolveProject_TinyGoCustody_ADifferingFileIsReportedAndWarned(t *testing.T) {
	var log bytes.Buffer
	rel := &fakeRelease{release: matched()}
	r, _ := custodyResolver(t, rel, map[string]string{"machine/machine.go": "package machine // altered"}, domain2.Verified, &log)
	c := resolveCustody(t, context.Background(), r, false)
	if len(c.Differs) != 1 || c.Differs[0] != (domain3.TinyGoFileDiffers{Path: "machine/machine.go", Anchor: domain3.TinyGoAnchorModule}) {
		t.Errorf("differs = %+v", c.Differs)
	}
	if !strings.Contains(log.String(), "walk.tinygo.custody.differs") {
		t.Errorf("no warning names the difference:\n%s", log.String())
	}
}

func TestResolveProject_TinyGoCustody_AnUnmeasuredReleaseIsWarned(t *testing.T) {
	var log bytes.Buffer
	rel := &fakeRelease{release: domain3.TinyGoRelease{Asset: "a", Outcome: domain3.TinyGoReleaseUnavailable, Reason: "release archive unavailable offline"}}
	r, _ := custodyResolver(t, rel, map[string]string{"machine/machine.go": "package machine"}, domain2.Verified, &log)
	c := resolveCustody(t, context.Background(), r, false)
	if len(c.NotEstablished) != 1 || c.NotEstablished[0].Reason != "release archive unavailable offline" {
		t.Errorf("not established = %+v", c.NotEstablished)
	}
	if !strings.Contains(log.String(), "walk.tinygo.custody.release_unavailable") {
		t.Errorf("no warning names the release leg:\n%s", log.String())
	}
}

func TestResolveProject_TinyGoCustody_AModuleThatCannotBeReadLeavesEveryFileNotEstablished(t *testing.T) {
	for name, setup := range map[string]func(*fakeModuleFetcher, *fakeBlobStore){
		"fetch fails": func(f *fakeModuleFetcher, _ *fakeBlobStore) {
			delete(f.records, tinygoAt)
			f.addError("github.com/tinygo-org/tinygo", "v0.42.0", errors.New("proxy unreachable"))
		},
		"the blob is gone":         func(_ *fakeModuleFetcher, b *fakeBlobStore) { clear(b.data) },
		"the blob is not a zip":    func(_ *fakeModuleFetcher, b *fakeBlobStore) { overwriteBlobs(b, []byte("not a zip")) },
		"the zip entry is corrupt": func(_ *fakeModuleFetcher, b *fakeBlobStore) { corruptBlobs(b) },
	} {
		t.Run(name, func(t *testing.T) {
			var log bytes.Buffer
			rel := &fakeRelease{release: matched()}
			blobs, fetcher := newFakeBlobStore(), newFakeFetcher()
			bl := tinyGoBuildList()
			bl.TinyGoFiles = []domain3.TinyGoSourceFile{{Path: "machine/machine.go", SHA256: sha("package machine")}}
			rec := fetchtest.Record(t, fetchtest.Module("github.com/tinygo-org/tinygo", "v0.42.0"),
				fetchtest.PipelineVersion("1.0.0"), fetchtest.Content(tinygoAt), fetchtest.SchemaVersion("2"))
			fetcher.records[tinygoAt] = mustComposeOne(t, rec)
			seedStoredZip(t, blobs, rec, map[string]string{"machine/machine.go": "package machine"})
			setup(fetcher, blobs)
			r := application.NewGraphResolver(xmod.New(), fetcher, blobs, fixedClock{fixedNow}, "", slog.New(slog.NewTextHandler(&log, nil))).
				WithBuildListResolver(&fakeBuildListResolver{list: bl}).WithTinyGoReleaseAcquirer(rel)

			c := resolveCustody(t, context.Background(), r, false)

			if c.VerifiedByModule != 0 || len(c.NotEstablished) != 1 || c.ModuleVerification != "" ||
				!strings.Contains(c.NotEstablished[0].Reason, "the module zip "+tinygoAt+" could not be read") {
				t.Errorf("custody = %+v", c)
			}
			if len(rel.asked) != 0 {
				t.Error("the release was consulted although the module zip, which decides its files, was not read")
			}
			if !strings.Contains(log.String(), "walk.tinygo.custody.module_unavailable") {
				t.Errorf("no warning names the module leg:\n%s", log.String())
			}
		})
	}
}

func TestResolveProject_TinyGoCustody_AGoModOnlyRecordNamesNoZip(t *testing.T) {
	rel := &fakeRelease{release: matched()}
	blobs, fetcher := newFakeBlobStore(), newFakeFetcher()
	bl := tinyGoBuildList()
	bl.TinyGoFiles = []domain3.TinyGoSourceFile{{Path: "machine/machine.go", SHA256: sha("x")}}
	rec := fetchtest.Record(t, fetchtest.Module("github.com/tinygo-org/tinygo", "v0.42.0"),
		fetchtest.PipelineVersion("1.0.0"), fetchtest.GoModOnly(tinygoAt), fetchtest.SchemaVersion("2"))
	fetcher.records[tinygoAt] = mustComposeOne(t, rec)
	r := newResolver(fetcher, blobs).WithBuildListResolver(&fakeBuildListResolver{list: bl}).WithTinyGoReleaseAcquirer(rel)
	c := resolveCustody(t, context.Background(), r, false)
	if len(c.NotEstablished) != 1 || !strings.Contains(c.NotEstablished[0].Reason, "names no module zip") {
		t.Errorf("custody = %+v", c)
	}
}

func TestResolveProject_TinyGoCustody_WithoutAnAcquirerOrSplitNothingIsRecorded(t *testing.T) {
	r, fetcher := custodyResolver(t, nil, map[string]string{"machine/machine.go": "package machine"}, domain2.Verified, nil)
	if c := resolveCustody(t, context.Background(), r, false); c != nil {
		t.Errorf("custody without an acquirer = %+v", c)
	}
	if fetcher.fetched("github.com/tinygo-org/tinygo") {
		t.Error("TinyGo's module was fetched with no custody to establish")
	}

	host, hostFetcher := buildListResolver(t, &fakeBuildListResolver{list: buildListWithEnv()})
	host = host.WithTinyGoReleaseAcquirer(&fakeRelease{})
	if _, err := host.ResolveProject(context.Background(), coord("example.com/project", coordinate.LocalVersion),
		[]byte("module example.com/project\n\ngo 1.21\n"), "/proj", domain3.DefaultDepthPolicy().FetchStage(), nil, false, false); err != nil {
		t.Fatal(err)
	}
	if hostFetcher.fetched("github.com/tinygo-org/tinygo") {
		t.Error("a host walk fetched TinyGo's module")
	}
}

func TestResolveProject_TinyGoCustody_AnUnusableReleaseRecordsNone(t *testing.T) {
	rel := &fakeRelease{release: matched()}
	blobs, fetcher := newFakeBlobStore(), newFakeFetcher()
	bl := tinyGoBuildList()
	bl.Modules = append(bl.Modules, walkports.BuildListModule{Path: domain3.TinyGoModulePath, Version: "v0.41.0"})
	bl.TinyGoVersion = "not a version"
	fetcher.add(t, domain3.TinyGoModulePath, "v0.41.0", "module "+domain3.TinyGoModulePath+"\n", blobs)
	r := newResolver(fetcher, blobs).WithBuildListResolver(&fakeBuildListResolver{list: bl}).WithTinyGoReleaseAcquirer(rel)
	g, err := r.ResolveProject(context.Background(), coord("example.com/project", coordinate.LocalVersion),
		[]byte("module example.com/project\n\ngo 1.21\n"), "/proj", domain3.DefaultDepthPolicy().FetchStage(), nil, false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range g.Nodes {
		if n.TinyGo != nil && n.TinyGo.Custody != nil {
			t.Errorf("a release that is no version was given custody: %+v", n.TinyGo.Custody)
		}
	}
}

func TestResolveProject_TinyGoCustody_ACancelledRunRecordsNone(t *testing.T) {
	for name, cancelAt := range map[string]string{"during the module leg": "module", "during the release leg": "release"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			rel := &cancellingRelease{cancel: cancel}
			blobs, fetcher := newFakeBlobStore(), newFakeFetcher()
			bl := tinyGoBuildList()
			bl.TinyGoFiles = []domain3.TinyGoSourceFile{{Path: "device/rp/rp2040.go", SHA256: sha("g")}}
			rec := fetchtest.Record(t, fetchtest.Module("github.com/tinygo-org/tinygo", "v0.42.0"),
				fetchtest.PipelineVersion("1.0.0"), fetchtest.Content(tinygoAt), fetchtest.SchemaVersion("2"))
			fetcher.records[tinygoAt] = mustComposeOne(t, rec)
			seedStoredZip(t, blobs, rec, map[string]string{"machine/machine.go": "m"})
			var f walkports.ModuleFetcher = fetcher
			if cancelAt == "module" {
				f = tinygoCancellingFetcher{inner: fetcher, cancel: cancel}
			}
			r := newResolver(fetcher, blobs).WithFetcher(f).WithBuildListResolver(&fakeBuildListResolver{list: bl}).WithTinyGoReleaseAcquirer(rel)
			g, err := r.ResolveProject(ctx, coord("example.com/project", coordinate.LocalVersion),
				[]byte("module example.com/project\n\ngo 1.21\n"), "/proj", domain3.DefaultDepthPolicy().FetchStage(), nil, false, false)
			if err != nil {
				t.Fatal(err)
			}
			for _, n := range g.Nodes {
				if n.TinyGo != nil && n.TinyGo.Custody != nil {
					t.Errorf("a cancelled run recorded custody: %+v", n.TinyGo.Custody)
				}
			}
		})
	}
}

type cancellingRelease struct{ cancel context.CancelFunc }

func (c *cancellingRelease) AcquireTinyGoRelease(context.Context, string, string, string, bool) domain3.TinyGoRelease {
	c.cancel()
	return domain3.TinyGoRelease{Outcome: domain3.TinyGoReleaseUnavailable, Reason: "context canceled"}
}

type tinygoCancellingFetcher struct {
	inner  *fakeModuleFetcher
	cancel context.CancelFunc
}

func (c tinygoCancellingFetcher) EnsureFetched(ctx context.Context, m coordinate.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	if m.Path() == domain3.TinyGoModulePath {
		c.cancel()
		return walkports.ModuleFetchResult{}, fmt.Errorf("fetching %s: %w", m, ctx.Err())
	}
	return c.inner.EnsureFetched(ctx, m)
}

func (c tinygoCancellingFetcher) EnsureFetchedReplacing(ctx context.Context, m, original coordinate.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	return c.inner.EnsureFetchedReplacing(ctx, m, original)
}

func seedStoredZip(t *testing.T, blobs *fakeBlobStore, rec domain2.FactRecord, files map[string]string) {
	t.Helper()
	seedZipBlob(t, blobs, rec, tinyGoZip(t, files))
}

func overwriteBlobs(b *fakeBlobStore, data []byte) {
	for k := range b.data {
		b.data[k] = data
	}
}

// corruptBlobs flips a byte of a stored (uncompressed) entry, so the entry is
// found and its checksum then fails on read.
func corruptBlobs(b *fakeBlobStore) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, _ := w.CreateHeader(&zip.FileHeader{Name: tinygoAt + "/src/machine/machine.go", Method: zip.Store}) //nolint:errcheck // a test fixture
	_, _ = f.Write([]byte("package machine"))                                                              //nolint:errcheck // a test fixture
	_ = w.Close()                                                                                          //nolint:errcheck // a test fixture
	data := buf.Bytes()
	i := bytes.Index(data, []byte("package machine"))
	data[i] ^= 0xff
	overwriteBlobs(b, data)
}
