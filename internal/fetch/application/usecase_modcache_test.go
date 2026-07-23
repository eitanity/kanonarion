package application_test

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// fakeDeriver produces deterministic, coordinate-derived handles for
// --from-modcache mode, standing in for the module-cache blob store.
type fakeDeriver struct{}

func (fakeDeriver) ZipHandle(c coordinate.ModuleCoordinate) (ports.BlobHandle, error) {
	return ports.BlobHandle("modcache:zip:" + c.String()), nil
}

func (fakeDeriver) GoModHandle(c coordinate.ModuleCoordinate) (ports.BlobHandle, error) {
	return ports.BlobHandle("modcache:mod:" + c.String()), nil
}

// noPutBlob fails the test if Put is ever called: modcache mode must never write
// bytes to the blob store. Get/Exists/GetPath are unused on this path.
type noPutBlob struct{ t *testing.T }

func (b noPutBlob) Put(context.Context, io.Reader) (ports.BlobHandle, error) {
	b.t.Fatalf("blobs.Put must not be called in --from-modcache mode")
	return "", nil
}
func (b noPutBlob) Get(context.Context, ports.BlobHandle) (io.ReadCloser, error) {
	return nil, errors.New("unexpected Get")
}
func (b noPutBlob) Exists(context.Context, ports.BlobHandle) (bool, error) { return false, nil }
func (b noPutBlob) GetPath(context.Context, ports.BlobHandle) (string, error) {
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

func TestExecuteModcache_SuccessRecordsDerivedHandles(t *testing.T) {
	coord := modcacheCoord(t)
	zipHash := domain2.ModuleHash{Algorithm: "h1", Value: "zip-abc="}
	goModHash := domain2.ModuleHash{Algorithm: "h1", Value: "mod-abc="}

	facts := newFakeFacts()
	uc := newUseCaseWithSumDB(
		downloadWithHashes(coord, zipHash, goModHash),
		&fakeVCS{}, noPutBlob{t}, facts,
		&fakeSumDB{result: ports.SumDBResult{Available: true, ZipHash: zipHash, GoModHash: goModHash}},
	).WithModcache(fakeDeriver{})

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
	if got, want := res.Record.ContentLocation, "modcache:zip:"+coord.String(); got != want {
		t.Errorf("ContentLocation = %q, want %q", got, want)
	}
	if got, want := res.Record.GoModLocation, "modcache:mod:"+coord.String(); got != want {
		t.Errorf("GoModLocation = %q, want %q", got, want)
	}
	if _, ok, _ := facts.GetFetchRecord(context.Background(), coord, "test-0.1.0"); !ok {
		t.Errorf("fact record was not persisted")
	}
}

func TestExecuteGoModOnlyModcache_RecordsGoModOnly(t *testing.T) {
	coord := modcacheCoord(t)
	goModHash := domain2.ModuleHash{Algorithm: "h1", Value: "mod-abc="}

	facts := newFakeFacts()
	uc := newUseCaseWithSumDB(
		downloadWithHashes(coord, domain2.ModuleHash{Algorithm: "h1", Value: "zip-unused="}, goModHash),
		&fakeVCS{}, noPutBlob{t}, facts,
		// modcache verification consults only the go.mod hash on this path.
		&fakeSumDB{result: ports.SumDBResult{Available: true, GoModHash: goModHash}},
	).WithModcache(fakeDeriver{})

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
	if got, want := res.Record.GoModLocation, "modcache:mod:"+coord.String(); got != want {
		t.Errorf("GoModLocation = %q, want %q", got, want)
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
	goModHash := domain2.ModuleHash{Algorithm: "h1", Value: "mod-abc="}
	facts := newFakeFacts()
	uc := newUseCaseWithSumDB(
		downloadWithHashes(coord, domain2.ModuleHash{Algorithm: "h1", Value: "zip-unused="}, goModHash),
		&fakeVCS{}, noPutBlob{t}, facts,
		// go.sum records a different go.mod hash → hard tamper failure, no record.
		&fakeSumDB{result: ports.SumDBResult{Available: true, GoModHash: domain2.ModuleHash{Algorithm: "h1", Value: "different=="}}},
	).WithModcache(fakeDeriver{})

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
	computed := domain2.ModuleHash{Algorithm: "h1", Value: "computed="}
	recorded := domain2.ModuleHash{Algorithm: "h1", Value: "recorded="}

	uc := newUseCaseWithSumDB(
		downloadWithHashes(coord, computed, domain2.ModuleHash{}),
		&fakeVCS{}, noPutBlob{t}, newFakeFacts(),
		&fakeSumDB{result: ports.SumDBResult{Available: true, ZipHash: recorded}},
	).WithModcache(fakeDeriver{})

	_, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if !errors.Is(err, application.ErrGoSumVerification) {
		t.Fatalf("err = %v, want ErrGoSumVerification", err)
	}
}

func TestExecuteModcache_MissingFromGoSumHardFails(t *testing.T) {
	coord := modcacheCoord(t)
	zipHash := domain2.ModuleHash{Algorithm: "h1", Value: "zip="}

	uc := newUseCaseWithSumDB(
		downloadWithHashes(coord, zipHash, domain2.ModuleHash{}),
		&fakeVCS{}, noPutBlob{t}, newFakeFacts(),
		&fakeSumDB{result: ports.SumDBResult{Available: false, Reason: "no go.sum entry"}},
	).WithModcache(fakeDeriver{})

	_, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if !errors.Is(err, application.ErrGoSumVerification) {
		t.Fatalf("err = %v, want ErrGoSumVerification", err)
	}
}

func TestExecuteModcache_GoModHashMismatchHardFails(t *testing.T) {
	coord := modcacheCoord(t)
	zipHash := domain2.ModuleHash{Algorithm: "h1", Value: "zip="}
	computedMod := domain2.ModuleHash{Algorithm: "h1", Value: "computed-mod="}
	recordedMod := domain2.ModuleHash{Algorithm: "h1", Value: "recorded-mod="}

	uc := newUseCaseWithSumDB(
		downloadWithHashes(coord, zipHash, computedMod),
		&fakeVCS{}, noPutBlob{t}, newFakeFacts(),
		&fakeSumDB{result: ports.SumDBResult{Available: true, ZipHash: zipHash, GoModHash: recordedMod}},
	).WithModcache(fakeDeriver{})

	_, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if !errors.Is(err, application.ErrGoSumVerification) {
		t.Fatalf("err = %v, want ErrGoSumVerification", err)
	}
}

func TestExecuteModcache_CacheHitSkipsDownload(t *testing.T) {
	coord := modcacheCoord(t)
	zipHash := domain2.ModuleHash{Algorithm: "h1", Value: "zip="}

	facts := newFakeFacts()
	// A proxy whose Download would fail proves the cached path never downloads.
	uc := newUseCaseWithSumDB(
		&fakeProxy{dlErr: errors.New("download must not run on cache hit")},
		&fakeVCS{}, noPutBlob{t}, facts,
		&fakeSumDB{result: ports.SumDBResult{Available: true, ZipHash: zipHash}},
	).WithModcache(fakeDeriver{})

	// Seed a record for this coordinate + pipeline version.
	seeded := domain2.NewFactRecord(domain2.FetchedModule{
		Coordinate:         coord,
		ModuleHash:         zipHash,
		VerificationStatus: domain2.VerifiedBySumDBOnly,
		PipelineVersion:    "test-0.1.0",
		ContentLocation:    "modcache:zip:" + coord.String(),
	})
	if err := facts.PutFetchRecord(context.Background(), seeded); err != nil {
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
