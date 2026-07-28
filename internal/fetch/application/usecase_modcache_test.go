package application_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// modcacheBlob records what --from-modcache mode stores.
//
// It replaces a fake that FAILED the test if Put was ever called. That
// assertion has been deliberately inverted: the mode used to derive
// "modcache:zip:<coord>" addresses from the coordinate and write them into
// records without storing anything, and those addresses were mode-locked — only
// the module-cache adapter resolved them, so a record written here was
// unreadable by an ordinary run and the same artefact measured both ways
// produced two irreconcilable records. The mode now populates its store under
// the artefact identity it measured, exactly like every other path.
type modcacheBlob struct {
	t    *testing.T
	held map[string][]byte
}

func newModcacheBlob(t *testing.T) *modcacheBlob {
	return &modcacheBlob{t: t, held: map[string][]byte{}}
}

func (b *modcacheBlob) Put(_ context.Context, identity ports.BlobIdentity, r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err //nolint:wrapcheck // test fake
	}
	b.held[identity.String()] = data
	return nil
}

func (b *modcacheBlob) Get(_ context.Context, identity ports.BlobIdentity) (io.ReadCloser, error) {
	data, ok := b.held[identity.String()]
	if !ok {
		return nil, errors.New("blob not held: " + identity.String())
	}
	return io.NopCloser(strings.NewReader(string(data))), nil
}

func (b *modcacheBlob) Exists(_ context.Context, identity ports.BlobIdentity) (bool, error) {
	_, ok := b.held[identity.String()]
	return ok, nil
}

func (b *modcacheBlob) GetPath(context.Context, ports.BlobIdentity) (string, error) {
	return "", errors.New("unexpected GetPath")
}

func modcacheCoord(t *testing.T) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate("github.com/example/mod", "v1.2.3")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	return c
}

// downloadWithHashes builds a fakeProxy whose Download reports the given hashes.
func downloadWithHashes(coord coordinate.ModuleCoordinate, zip, gomod domain2.ModuleHash) *fakeProxy {
	return &fakeProxy{
		downloads: map[string]fakeDownload{
			coord.String(): {
				zipData:   "zip-bytes",
				goModData: "module github.com/example/mod\n",
				zipHash:   zip,
				goModHash: gomod,
			},
		},
	}
}

// A --from-modcache measurement records the same content address every other
// mode records, and the bytes land in the store under it. Nothing about the
// record says which mode wrote it beyond the acquisition-mode provenance field,
// which is what makes the two measurements of one artefact reconcilable.
func TestExecuteModcache_RecordsTheSameIdentityAsEveryOtherMode(t *testing.T) {
	coord := modcacheCoord(t)
	zipHash := fetchtest.H1("zip-abc=")
	goModHash := fetchtest.H1("mod-abc=")

	facts := newFakeFacts()
	blobs := newModcacheBlob(t)
	uc := newUseCaseWithSumDB(
		downloadWithHashes(coord, zipHash, goModHash),
		&fakeVCS{}, blobs, facts,
		&fakeSumDB{result: ports.SumDBResult{Available: true, ZipHash: zipHash, GoModHash: goModHash}},
	).WithModcacheMode()

	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.FromCache {
		t.Errorf("FromCache = true, want false on first fetch")
	}
	if got, want := res.Record.VerificationStatus, string(domain2.VerifiedBySumDBOnly); got != want {
		t.Errorf("VerificationStatus = %q, want %q", got, want)
	}
	wantZip := fetchtest.Blob(ports.BlobKindZip, zipHash)
	wantGoMod := fetchtest.Blob(ports.BlobKindGoMod, goModHash)
	if got := res.Record.ContentLocation; got != wantZip.String() {
		t.Errorf("ContentLocation = %q, want the measured zip identity %q", got, wantZip)
	}
	if got := res.Record.GoModLocation; got != wantGoMod.String() {
		t.Errorf("GoModLocation = %q, want the measured go.mod identity %q", got, wantGoMod)
	}
	if strings.Contains(res.Record.ContentLocation, "modcache:") {
		t.Errorf("ContentLocation %q is mode-locked; the address must name the artefact, not the store", res.Record.ContentLocation)
	}
	// The bytes are populated into the store under that identity, so a later
	// ordinary run finds them rather than re-downloading.
	if _, ok := blobs.held[wantZip.String()]; !ok {
		t.Errorf("zip was not stored under %q; --from-modcache must populate its store", wantZip)
	}
	if _, ok, _ := facts.GetFetchRecord(context.Background(), coord, "test-0.1.0"); !ok {
		t.Errorf("fact record was not persisted")
	}
}

func TestExecuteGoModOnlyModcache_RecordsGoModOnly(t *testing.T) {
	coord := modcacheCoord(t)
	goModHash := fetchtest.H1("mod-abc=")

	facts := newFakeFacts()
	uc := newUseCaseWithSumDB(
		downloadWithHashes(coord, fetchtest.H1("zip-unused="), goModHash),
		&fakeVCS{}, newModcacheBlob(t), facts,
		// modcache verification consults only the go.mod hash on this path.
		&fakeSumDB{result: ports.SumDBResult{Available: true, GoModHash: goModHash}},
	).WithModcacheMode()

	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord, GoModOnly: true})
	if err != nil {
		t.Fatalf("Execute go.mod-only (modcache): %v", err)
	}
	if !res.Record.IsGoModOnly() {
		t.Errorf("expected a go.mod-only record, got ContentLocation=%q GoModLocation=%q",
			res.Record.ContentLocation, res.Record.GoModLocation)
	}
	if res.Record.ContentLocation != "" {
		t.Errorf("go.mod-only record must have empty ContentLocation, got %q", res.Record.ContentLocation)
	}
	wantGoMod := fetchtest.Blob(ports.BlobKindGoMod, goModHash)
	if got := res.Record.GoModLocation; got != wantGoMod.String() {
		t.Errorf("GoModLocation = %q, want the measured go.mod identity %q", got, wantGoMod)
	}
	if got, want := res.Record.VerificationStatus, string(domain2.VerifiedBySumDBOnly); got != want {
		t.Errorf("VerificationStatus = %q, want %q", got, want)
	}
	if _, ok, _ := facts.GetFetchRecord(context.Background(), coord, "test-0.1.0"); !ok {
		t.Errorf("fact record was not persisted")
	}
}

func TestExecuteGoModOnlyModcache_GoModHashMismatchHardFails(t *testing.T) {
	coord := modcacheCoord(t)
	goModHash := fetchtest.H1("mod-abc=")
	facts := newFakeFacts()
	uc := newUseCaseWithSumDB(
		downloadWithHashes(coord, fetchtest.H1("zip-unused="), goModHash),
		&fakeVCS{}, newModcacheBlob(t), facts,
		// go.sum records a different go.mod hash → hard tamper failure, no record.
		&fakeSumDB{result: ports.SumDBResult{Available: true, GoModHash: fetchtest.H1("different==")}},
	).WithModcacheMode()

	_, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord, GoModOnly: true})
	if !errors.Is(err, application.ErrGoSumVerification) {
		t.Fatalf("expected ErrGoSumVerification on go.mod hash mismatch, got %v", err)
	}
	if _, ok, _ := facts.GetFetchRecord(context.Background(), coord, "test-0.1.0"); ok {
		t.Errorf("a record must not be persisted when go.sum verification fails")
	}
}

func TestExecuteModcache_ZipHashMismatchHardFails(t *testing.T) {
	coord := modcacheCoord(t)
	computed := fetchtest.H1("computed=")
	recorded := fetchtest.H1("recorded=")

	uc := newUseCaseWithSumDB(
		downloadWithHashes(coord, computed, domain2.ModuleHash{}),
		&fakeVCS{}, newModcacheBlob(t), newFakeFacts(),
		&fakeSumDB{result: ports.SumDBResult{Available: true, ZipHash: recorded}},
	).WithModcacheMode()

	_, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if !errors.Is(err, application.ErrGoSumVerification) {
		t.Fatalf("err = %v, want ErrGoSumVerification", err)
	}
}

func TestExecuteModcache_MissingFromGoSumHardFails(t *testing.T) {
	coord := modcacheCoord(t)
	zipHash := fetchtest.H1("zip=")

	uc := newUseCaseWithSumDB(
		downloadWithHashes(coord, zipHash, domain2.ModuleHash{}),
		&fakeVCS{}, newModcacheBlob(t), newFakeFacts(),
		&fakeSumDB{result: ports.SumDBResult{Available: false, Reason: "no go.sum entry"}},
	).WithModcacheMode()

	_, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if !errors.Is(err, application.ErrGoSumVerification) {
		t.Fatalf("err = %v, want ErrGoSumVerification", err)
	}
}

func TestExecuteModcache_GoModHashMismatchHardFails(t *testing.T) {
	coord := modcacheCoord(t)
	zipHash := fetchtest.H1("zip=")
	computedMod := fetchtest.H1("computed-mod=")
	recordedMod := fetchtest.H1("recorded-mod=")

	uc := newUseCaseWithSumDB(
		downloadWithHashes(coord, zipHash, computedMod),
		&fakeVCS{}, newModcacheBlob(t), newFakeFacts(),
		&fakeSumDB{result: ports.SumDBResult{Available: true, ZipHash: zipHash, GoModHash: recordedMod}},
	).WithModcacheMode()

	_, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if !errors.Is(err, application.ErrGoSumVerification) {
		t.Fatalf("err = %v, want ErrGoSumVerification", err)
	}
}

func TestExecuteModcache_CacheHitSkipsDownload(t *testing.T) {
	coord := modcacheCoord(t)
	zipHash := fetchtest.H1("zip=")

	facts := newFakeFacts()
	blobs := newModcacheBlob(t)
	// A proxy whose Download would fail proves the cached path never downloads.
	uc := newUseCaseWithSumDB(
		&fakeProxy{dlErr: errors.New("download must not run on cache hit")},
		&fakeVCS{}, blobs, facts,
		&fakeSumDB{result: ports.SumDBResult{Available: true, ZipHash: zipHash}},
	).WithModcacheMode()

	// Seed a record for this coordinate + pipeline version, with its zip held
	// under the identity the record names — the cache check re-fetches any record
	// whose artefacts it cannot read, so a record without its bytes would assert
	// the opposite of production.
	seeded := fetchtest.Record(t,
		fetchtest.Coordinate(coord),
		fetchtest.ModuleHash(zipHash),
		// No go.mod hash was computed: production serialises the zero hash as ":".
		fetchtest.GoModHash(domain2.ModuleHash{}),
		fetchtest.Status(domain2.VerifiedBySumDBOnly),
		fetchtest.PipelineVersion("test-0.1.0"),
		fetchtest.Content(fetchtest.Blob(ports.BlobKindZip, zipHash).String()),
	)
	if err := blobs.Put(context.Background(), fetchtest.ZipIdentity(t, seeded), strings.NewReader("zip-bytes")); err != nil {
		t.Fatalf("seeding zip blob: %v", err)
	}
	if err := facts.PutFetchRecord(context.Background(), fetchtest.Sealed(t,
		fetchtest.Coordinate(coord),
		fetchtest.ModuleHash(zipHash),
		fetchtest.GoModHash(domain2.ModuleHash{}),
		fetchtest.Status(domain2.VerifiedBySumDBOnly),
		fetchtest.PipelineVersion("test-0.1.0"),
		fetchtest.Content(fetchtest.Blob(ports.BlobKindZip, zipHash).String()),
	)); err != nil {
		t.Fatalf("seeding record: %v", err)
	}

	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.FromCache {
		t.Errorf("FromCache = false, want true")
	}
}
