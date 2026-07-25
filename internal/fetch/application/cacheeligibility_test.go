package application_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// scriptedSumDB returns results[i] on call i+1, then the last result forever
// after: the "checksum database fails N times then answers" seam.
type scriptedSumDB struct {
	results []ports.SumDBResult
	calls   int
}

func (s *scriptedSumDB) Lookup(_ context.Context, _ coordinate.ModuleCoordinate) ports.SumDBResult {
	s.calls++
	if s.calls <= len(s.results) {
		return s.results[s.calls-1]
	}
	return s.results[len(s.results)-1]
}

func transientSumDBFailure() ports.SumDBResult {
	err := &domain2.ProxyStatusError{StatusCode: 503, URL: "https://sum.golang.org/lookup/x"}
	return ports.SumDBResult{
		Available:      false,
		Reason:         fmt.Sprintf("sumdb lookup: %v", err),
		Unavailability: ports.SumDBUnavailabilityFailure,
		Err:            err,
	}
}

func policySumDBUnavailable() ports.SumDBResult {
	return ports.SumDBResult{
		Available:      false,
		Reason:         "GOSUMDB=off",
		Unavailability: ports.SumDBUnavailabilityPolicy,
	}
}

// newProxyWithOrigin builds the fake proxy every test here uses: a module with
// resolvable origin metadata, so verification reaches the checksum-database step.
func newProxyWithOrigin() *fakeProxy {
	return &fakeProxy{
		infos: map[string]ports.ModuleInfo{
			testCoord.String(): {
				Version: "v1.8.1",
				Time:    fixedTime,
				Origin: &ports.ModuleOrigin{
					VCS:  "git",
					URL:  "https://github.com/gorilla/mux",
					Ref:  "refs/tags/v1.8.1",
					Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				},
			},
		},
	}
}

// TestFailedSumDBLookupRecordIsReVerifiedNotServedFromCache is the regression
// guard for the cached-downgrade half of the fix. Before it, a single transient
// checksum-database failure produced an UnverifiedNoSumDB record that the cache
// check served on every later run until --force, so one bad network moment became
// a permanent finding about the module.
func TestFailedSumDBLookupRecordIsReVerifiedNotServedFromCache(t *testing.T) {
	fakeHash := domain2.ModuleHash{Algorithm: "h1", Value: "fakehash=="}
	sumdb := &scriptedSumDB{results: []ports.SumDBResult{
		transientSumDBFailure(),
		{Available: true, ZipHash: fakeHash},
	}}
	blobs, facts := newFakeBlob(), newFakeFacts()
	uc := newUseCaseWithSumDB(newProxyWithOrigin(), &fakeVCS{checkoutErr: errors.New("no checkout in test")}, blobs, facts, sumdb)

	// First fetch: the lookup fails, so the record is a downgrade that describes
	// the measurement rather than the module.
	first, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	if first.Record.VerificationStatus != string(domain2.UnverifiedNoSumDB) {
		t.Fatalf("first VerificationStatus = %q, want %q", first.Record.VerificationStatus, domain2.UnverifiedNoSumDB)
	}
	if !first.Record.SumDBLookupFailed {
		t.Error("SumDBLookupFailed not recorded, so the downgrade would be cached as a fact about the module")
	}
	if domain2.RecordIsCacheable(first.Record) {
		t.Error("RecordIsCacheable reported a failed-lookup record as cacheable")
	}

	// Second fetch: the record must be re-verified, not served, and the now-working
	// lookup must lift the status.
	second, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if second.FromCache {
		t.Fatal("second fetch served the downgraded record from cache: one transient failure is permanent again")
	}
	if sumdb.calls != 2 {
		t.Errorf("sumdb consulted %d times, want 2 (the second fetch must re-verify)", sumdb.calls)
	}
	if second.Record.SumDBLookupFailed {
		t.Error("SumDBLookupFailed still set after a successful lookup")
	}
	if got := second.Record.VerificationStatus; got == string(domain2.UnverifiedNoSumDB) {
		t.Errorf("VerificationStatus = %q: the recovered lookup did not lift the downgrade", got)
	}
	if !domain2.RecordIsCacheable(second.Record) {
		t.Error("the re-verified record is still not cacheable, so every future run re-fetches")
	}

	// Third fetch: now that the record rests on a real answer, it is a cache hit
	// again — the guard must not permanently disable caching for the coordinate.
	third, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("third Execute: %v", err)
	}
	if !third.FromCache {
		t.Error("third fetch re-fetched a record whose lookup succeeded")
	}
}

// TestPolicyUnavailableRecordStillHitsTheCache is the other side of the reason
// split: a settled policy answer is the database's real answer, so the record it
// produces must keep behaving exactly as it did before this change.
func TestPolicyUnavailableRecordStillHitsTheCache(t *testing.T) {
	sumdb := &scriptedSumDB{results: []ports.SumDBResult{policySumDBUnavailable()}}
	blobs, facts := newFakeBlob(), newFakeFacts()
	uc := newUseCaseWithSumDB(newProxyWithOrigin(), &fakeVCS{checkoutErr: errors.New("no checkout in test")}, blobs, facts, sumdb)

	first, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	if first.Record.SumDBLookupFailed {
		t.Fatal("a policy answer was recorded as a failed lookup")
	}
	if first.Record.VerificationStatus != string(domain2.UnverifiedNoSumDB) {
		t.Errorf("VerificationStatus = %q, want %q", first.Record.VerificationStatus, domain2.UnverifiedNoSumDB)
	}

	second, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if !second.FromCache {
		t.Error("a policy-unavailable record was re-verified: GOSUMDB=off now costs a re-fetch every run")
	}
	if sumdb.calls != 1 {
		t.Errorf("sumdb consulted %d times, want 1", sumdb.calls)
	}
}

// TestGoSumMaskedFailureIsStillReVerified covers the case the reason split exists
// for. A local go.sum entry elevates an unavailable lookup to VerifiedByGoSum, so
// the record looks verified and nothing in its status hints that the transparency
// log was never reached. It must still be re-verified.
func TestGoSumMaskedFailureIsStillReVerified(t *testing.T) {
	fakeHash := domain2.ModuleHash{Algorithm: "h1", Value: "fakehash=="}
	sumdb := &scriptedSumDB{results: []ports.SumDBResult{transientSumDBFailure()}}
	blobs, facts := newFakeBlob(), newFakeFacts()
	uc := newUseCaseWithSumDB(newProxyWithOrigin(), &fakeVCS{checkoutErr: errors.New("no checkout in test")}, blobs, facts, sumdb).
		WithProjectGoSum(&fakeSumDB{result: ports.SumDBResult{Available: true, ZipHash: fakeHash}})

	first, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	if first.Record.VerificationStatus != string(domain2.VerifiedByGoSum) {
		t.Fatalf("VerificationStatus = %q, want %q", first.Record.VerificationStatus, domain2.VerifiedByGoSum)
	}
	if !first.Record.SumDBLookupFailed {
		t.Fatal("a go.sum-masked lookup failure was recorded as cacheable: the status reads verified and " +
			"nothing records that the checksum database was never reached")
	}

	second, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if second.FromCache {
		t.Error("a go.sum-masked lookup failure was served from cache")
	}
}

// TestGoModOnlyFailedLookupIsReVerified applies the same rule to the go.mod-only
// acquisition path, which has its own cache check and its own verify function.
func TestGoModOnlyFailedLookupIsReVerified(t *testing.T) {
	sumdb := &scriptedSumDB{results: []ports.SumDBResult{transientSumDBFailure()}}
	blobs, facts := newFakeBlob(), newFakeFacts()
	uc := newUseCaseWithSumDB(newProxyWithOrigin(), &fakeVCS{}, blobs, facts, sumdb)

	req := application.FetchRequest{Coordinate: testCoord, GoModOnly: true}
	first, err := uc.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	if !first.Record.SumDBLookupFailed {
		t.Fatal("go.mod-only path did not record the failed lookup")
	}

	second, err := uc.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if second.FromCache {
		t.Error("go.mod-only path served a failed-lookup record from cache")
	}
	if sumdb.calls != 2 {
		t.Errorf("sumdb consulted %d times, want 2", sumdb.calls)
	}
}

// foreignHandleBlob is a blob store that rejects handles written by a different
// acquisition mode, exactly as the local filesystem store rejects the
// "modcache:zip:<coord>" handles a --from-modcache run derives.
type foreignHandleBlob struct {
	*fakeBlob
	foreignPrefix string
}

func (b *foreignHandleBlob) Exists(ctx context.Context, h ports.BlobHandle) (bool, error) {
	if strings.HasPrefix(string(h), b.foreignPrefix) {
		return false, fmt.Errorf("invalid blob handle %q: expected fake:<content>", h)
	}
	return b.fakeBlob.Exists(ctx, h)
}

func (b *foreignHandleBlob) Get(ctx context.Context, h ports.BlobHandle) (io.ReadCloser, error) {
	if strings.HasPrefix(string(h), b.foreignPrefix) {
		return nil, fmt.Errorf("invalid blob handle %q: expected fake:<content>", h)
	}
	return b.fakeBlob.Get(ctx, h)
}

// TestCachedRecordWithUnreadableHandleIsReFetched is the regression guard for the
// cross-mode cache hit. A fact record is keyed by (path, version, pipeline
// version) with no acquisition-mode dimension, so a --from-modcache run
// overwrites a blob-backed record with a "modcache:zip:<coord>" handle only the
// module-cache adapter can resolve. The next normal run used to get a cache hit on
// that handle and hand it to the local blob store, which rejected it — surfacing
// far downstream as every module failing to populate the scan's GOMODCACHE and
// govulncheck silently going to the network.
func TestCachedRecordWithUnreadableHandleIsReFetched(t *testing.T) {
	base := newFakeBlob()
	blobs := &foreignHandleBlob{fakeBlob: base, foreignPrefix: "modcache:"}
	facts := newFakeFacts()

	// Seed the record another mode would have written: a handle this run's blob
	// store cannot resolve.
	seeded := domain2.NewFactRecord(domain2.FetchedModule{
		Coordinate:         testCoord,
		ModuleHash:         domain2.ModuleHash{Algorithm: "h1", Value: "seed=="},
		GoModHash:          domain2.ModuleHash{Algorithm: "h1", Value: "seedmod=="},
		VerificationStatus: domain2.Verified,
		FetchedAt:          fixedTime,
		PipelineVersion:    "test-0.1.0",
		ContentLocation:    "modcache:zip:github.com/gorilla/mux@v1.8.1",
		GoModLocation:      "modcache:gomod:github.com/gorilla/mux@v1.8.1",
	})
	if err := facts.PutFetchRecord(context.Background(), seeded); err != nil {
		t.Fatalf("seed record: %v", err)
	}

	fakeHash := domain2.ModuleHash{Algorithm: "h1", Value: "fakehash=="}
	uc := newUseCaseWithSumDB(newProxyWithOrigin(), &fakeVCS{checkoutErr: errors.New("no checkout in test")},
		blobs, facts, availableSumDB(fakeHash))

	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.FromCache {
		t.Fatal("served a cached record whose blob handle this run's store cannot read")
	}
	present, err := blobs.Exists(context.Background(), ports.BlobHandle(res.Record.ContentLocation))
	if err != nil || !present {
		t.Errorf("re-fetched record's handle %q is not readable by this store (present=%v err=%v)",
			res.Record.ContentLocation, present, err)
	}
}

// TestCachedRecordWithEvictedBlobIsReFetched covers the plainer case the same
// guard handles: a handle in the store's own format whose blob has since been
// removed. Serving it would hand the caller a record pointing at nothing.
func TestCachedRecordWithEvictedBlobIsReFetched(t *testing.T) {
	blobs, facts := newFakeBlob(), newFakeFacts()
	seeded := domain2.NewFactRecord(domain2.FetchedModule{
		Coordinate:         testCoord,
		ModuleHash:         domain2.ModuleHash{Algorithm: "h1", Value: "seed=="},
		GoModHash:          domain2.ModuleHash{Algorithm: "h1", Value: "seedmod=="},
		VerificationStatus: domain2.Verified,
		FetchedAt:          fixedTime,
		PipelineVersion:    "test-0.1.0",
		ContentLocation:    "fake:evicted-zip",
		GoModLocation:      "fake:evicted-gomod",
	})
	if err := facts.PutFetchRecord(context.Background(), seeded); err != nil {
		t.Fatalf("seed record: %v", err)
	}

	fakeHash := domain2.ModuleHash{Algorithm: "h1", Value: "fakehash=="}
	uc := newUseCaseWithSumDB(newProxyWithOrigin(), &fakeVCS{checkoutErr: errors.New("no checkout in test")},
		blobs, facts, availableSumDB(fakeHash))

	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.FromCache {
		t.Error("served a cached record whose blobs are no longer in the store")
	}
}

// TestCachedRecordWithReadableBlobsStillHitsTheCache pins the negative: the
// readability gate must not turn every cache hit into a re-fetch.
func TestCachedRecordWithReadableBlobsStillHitsTheCache(t *testing.T) {
	base := newFakeBlob()
	blobs := &foreignHandleBlob{fakeBlob: base, foreignPrefix: "modcache:"}
	facts := newFakeFacts()

	zip, err := blobs.Put(context.Background(), strings.NewReader("cached-zip"))
	if err != nil {
		t.Fatalf("seed zip blob: %v", err)
	}
	goMod, err := blobs.Put(context.Background(), strings.NewReader("cached-gomod"))
	if err != nil {
		t.Fatalf("seed go.mod blob: %v", err)
	}
	seeded := domain2.NewFactRecord(domain2.FetchedModule{
		Coordinate:         testCoord,
		ModuleHash:         domain2.ModuleHash{Algorithm: "h1", Value: "seed=="},
		GoModHash:          domain2.ModuleHash{Algorithm: "h1", Value: "seedmod=="},
		VerificationStatus: domain2.Verified,
		FetchedAt:          fixedTime,
		PipelineVersion:    "test-0.1.0",
		ContentLocation:    string(zip),
		GoModLocation:      string(goMod),
	})
	if err := facts.PutFetchRecord(context.Background(), seeded); err != nil {
		t.Fatalf("seed record: %v", err)
	}

	uc := newUseCaseWithSumDB(newProxyWithOrigin(), &fakeVCS{}, blobs, facts, disabledSumDB())
	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.FromCache {
		t.Error("re-fetched a cached record whose blobs are both readable")
	}
}
