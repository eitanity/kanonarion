package application_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// newServe wires a ServeModuleUseCase over a sumdb-disabled fetch pipeline and
// the given blob store. Returning the fetch use case lets a test pre-seed it.
func newServe(blobs ports.BlobStore, facts ports.FactStore) *application.ServeModuleUseCase {
	proxy := &fakeProxy{}
	vcs := &fakeVCS{checkoutErr: errors.New("no real checkout in test")}
	fetch := newUseCase(proxy, vcs, blobs, facts)
	return application.NewServeModuleUseCase(fetch, blobs)
}

// existsControlBlob wraps fakeBlob to force Exists outcomes independently of
// what Put stored, so the serve-specific blob-presence branches are reachable.
type existsControlBlob struct {
	*fakeBlob
	existsErr   error
	forceAbsent bool
}

func (b *existsControlBlob) Exists(ctx context.Context, identity ports.BlobIdentity) (bool, error) {
	if b.existsErr != nil {
		return false, b.existsErr
	}
	if b.forceAbsent {
		return false, nil
	}
	return b.fakeBlob.Exists(ctx, identity)
}

func TestServe_FreshFetch(t *testing.T) {
	blobs := newFakeBlob()
	facts := newFakeFacts()
	serve := newServe(blobs, facts)

	res, err := serve.Serve(context.Background(), application.ServeRequest{
		Coordinate:    testCoord,
		SkipVCSVerify: true,
	})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if res.FromCache {
		t.Error("expected FromCache=false on first serve")
	}
	if res.Identity.IsZero() {
		t.Error("expected a non-empty blob handle")
	}
	// The handle must name a blob that actually exists in the store.
	present, err := blobs.Exists(context.Background(), res.Identity)
	if err != nil || !present {
		t.Errorf("returned handle %q not present in store (present=%v err=%v)", res.Identity, present, err)
	}
	if res.Record.Coordinate() != testCoord {
		t.Errorf("Record coordinate = %v, want %v", res.Record.Coordinate(), testCoord)
	}
	// sumdb disabled → status is surfaced, not an error.
	if res.VerificationStatus != domain2.UnverifiedNoSumDB {
		t.Errorf("VerificationStatus = %q, want %q", res.VerificationStatus, domain2.UnverifiedNoSumDB)
	}
}

func TestServe_CacheHitBlobPresent(t *testing.T) {
	blobs := newFakeBlob()
	facts := newFakeFacts()

	// Seed a cached record whose blob is present in the store.
	seedRecord(t, blobs, facts, true, domain2.Verified)

	serve := newServe(blobs, facts)
	res, err := serve.Serve(context.Background(), application.ServeRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if !res.FromCache {
		t.Error("expected FromCache=true on cache hit with present blob")
	}
	if res.Identity.IsZero() {
		t.Error("Identity is zero on a cache hit; Serve must name the artefact it served")
	}
	if res.VerificationStatus != domain2.Verified {
		t.Errorf("VerificationStatus = %q, want %q", res.VerificationStatus, domain2.Verified)
	}
}

func TestServe_CacheHitBlobEvictedRefetches(t *testing.T) {
	blobs := newFakeBlob()
	facts := newFakeFacts()

	// Seed a cached record pointing at a blob that is NOT in the store (evicted).
	seedRecord(t, blobs, facts, false, domain2.Verified)

	serve := newServe(blobs, facts)
	res, err := serve.Serve(context.Background(), application.ServeRequest{
		Coordinate:    testCoord,
		SkipVCSVerify: true,
	})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if res.FromCache {
		t.Error("expected FromCache=false after re-fetching an evicted blob")
	}
	present, err := blobs.Exists(context.Background(), res.Identity)
	if err != nil || !present {
		t.Errorf("re-fetched artefact %q not present (present=%v err=%v)", res.Identity, present, err)
	}
}

func TestServe_RefetchErrorPropagates(t *testing.T) {
	blobs := newFakeBlob()
	facts := newFakeFacts()

	// Cache hit whose blob is evicted, but the forced re-fetch fails at the proxy.
	seedRecord(t, blobs, facts, false, domain2.Verified)
	proxy := &fakeProxy{infoErr: errors.New("proxy down")}
	fetch := newUseCase(proxy, &fakeVCS{}, blobs, facts)
	serve := application.NewServeModuleUseCase(fetch, blobs)

	_, err := serve.Serve(context.Background(), application.ServeRequest{Coordinate: testCoord})
	if err == nil {
		t.Fatal("expected error when re-fetching an evicted blob fails")
	}
}

func TestServe_FetchErrorPropagates(t *testing.T) {
	blobs := newFakeBlob()
	facts := newFakeFacts()
	proxy := &fakeProxy{infoErr: errors.New("proxy down")}
	fetch := newUseCase(proxy, &fakeVCS{}, blobs, facts)
	serve := application.NewServeModuleUseCase(fetch, blobs)

	_, err := serve.Serve(context.Background(), application.ServeRequest{Coordinate: testCoord})
	if err == nil {
		t.Fatal("expected error when the fetch pipeline fails")
	}
}

func TestServe_BlobAbsentAfterFetchErrors(t *testing.T) {
	facts := newFakeFacts()
	blobs := &existsControlBlob{fakeBlob: newFakeBlob(), forceAbsent: true}
	fetch := newUseCase(&fakeProxy{}, &fakeVCS{checkoutErr: errors.New("skip")}, blobs, facts)
	serve := application.NewServeModuleUseCase(fetch, blobs)

	_, err := serve.Serve(context.Background(), application.ServeRequest{
		Coordinate:    testCoord,
		SkipVCSVerify: true,
	})
	if err == nil {
		t.Fatal("expected error when the fetched blob is absent from the store")
	}
}

func TestServe_ExistsErrorPropagates(t *testing.T) {
	facts := newFakeFacts()
	blobs := &existsControlBlob{fakeBlob: newFakeBlob(), existsErr: errors.New("store io error")}
	fetch := newUseCase(&fakeProxy{}, &fakeVCS{checkoutErr: errors.New("skip")}, blobs, facts)
	serve := application.NewServeModuleUseCase(fetch, blobs)

	_, err := serve.Serve(context.Background(), application.ServeRequest{
		Coordinate:    testCoord,
		SkipVCSVerify: true,
	})
	if err == nil {
		t.Fatal("expected error when the blob store Exists check fails")
	}
}

func TestServe_CacheHitExistsErrorPropagates(t *testing.T) {
	facts := newFakeFacts()
	base := newFakeBlob()
	seedRecord(t, base, facts, true, domain2.Verified)
	blobs := &existsControlBlob{fakeBlob: base, existsErr: errors.New("store io error")}
	fetch := newUseCase(&fakeProxy{}, &fakeVCS{}, blobs, facts)
	serve := application.NewServeModuleUseCase(fetch, blobs)

	_, err := serve.Serve(context.Background(), application.ServeRequest{Coordinate: testCoord})
	if err == nil {
		t.Fatal("expected error when the cache-hit blob presence check fails")
	}
}

func TestServe_AuditsVerifiedRead(t *testing.T) {
	blobs := newFakeBlob()
	facts := newFakeFacts()
	seedRecord(t, blobs, facts, true, domain2.Verified)

	sink := newFakeAudit()
	serve := newServe(blobs, facts).WithAudit(sink)
	res, err := serve.Serve(context.Background(), application.ServeRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	// A verified module is served AND recorded as verified.
	if res.Identity.IsZero() {
		t.Error("Identity is zero; Serve must name the artefact it served")
	}
	ev := sink.only(t)
	if ev.Type != audit.EventRecordReadVerified {
		t.Fatalf("event type = %q, want %q", ev.Type, audit.EventRecordReadVerified)
	}
	if ev.Payload["verification_status"] != string(domain2.Verified) {
		t.Errorf("payload status = %v, want %q", ev.Payload["verification_status"], domain2.Verified)
	}
	if ev.Payload["module"] != testCoord.Path() || ev.Payload["version"] != testCoord.Version() {
		t.Errorf("payload coordinate = %v@%v, want %v", ev.Payload["module"], ev.Payload["version"], testCoord)
	}
}

func TestServe_AuditsVerificationFailedButStillServes(t *testing.T) {
	blobs := newFakeBlob()
	facts := newFakeFacts()
	// A blob whose hash did not match its trust anchor: the security-relevant
	// case. Serve does not gate — it records the rejection and still returns.
	seedRecord(t, blobs, facts, true, domain2.UnverifiedHashMismatch)

	sink := newFakeAudit()
	serve := newServe(blobs, facts).WithAudit(sink)
	res, err := serve.Serve(context.Background(), application.ServeRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if res.Identity.IsZero() {
		t.Error("Identity is zero; Serve names the artefact even when verification failed")
	}
	ev := sink.only(t)
	if ev.Type != audit.EventVerificationFailed {
		t.Fatalf("event type = %q, want %q", ev.Type, audit.EventVerificationFailed)
	}
	if ev.Payload["verification_status"] != string(domain2.UnverifiedHashMismatch) {
		t.Errorf("payload status = %v, want %q", ev.Payload["verification_status"], domain2.UnverifiedHashMismatch)
	}
	if r, ok := ev.Payload["reason"].(string); !ok || r == "" {
		t.Errorf("verification_failed payload must carry a non-empty reason, got %v", ev.Payload["reason"])
	}
}

func TestServe_AuditEmitFailurePropagates(t *testing.T) {
	blobs := newFakeBlob()
	facts := newFakeFacts()
	seedRecord(t, blobs, facts, true, domain2.Verified)

	sink := &fakeAudit{err: errors.New("log unwritable")}
	serve := newServe(blobs, facts).WithAudit(sink)
	if _, err := serve.Serve(context.Background(), application.ServeRequest{Coordinate: testCoord}); err == nil {
		t.Fatal("expected serve to fail when the assurance log cannot be written")
	}
}

// seedRecord writes a fact record for testCoord at the test pipeline version
// with the given verification status, and stores its artefacts when zipPresent.
//
// The artefacts are keyed by the identity the record itself carries, because
// that is the only address the pipeline will ask for. zipPresent false is how
// the eviction tests seed a record whose zip is genuinely gone: there is no
// longer a "wrong handle" to pass, since the address is derived from the record
// rather than chosen by the caller.
//
// The go.mod blob is always stored. A record naming a go.mod the store never
// held is not a state the pipeline can produce, and the cache check rejects such
// a record because its artefacts are unreadable — so seeding one would test a
// fiction.
func seedRecord(t *testing.T, blobs ports.BlobStore, facts ports.FactStore, zipPresent bool, status domain2.VerificationStatus) {
	t.Helper()
	rec := fetchtest.Record(t,
		fetchtest.Coordinate(testCoord),
		fetchtest.ModuleHash(fetchtest.H1("seed==")),
		fetchtest.GoModHash(fetchtest.H1("seedmod==")),
		fetchtest.Status(status),
		fetchtest.FetchedAt(fixedTime),
		fetchtest.PipelineVersion("test-0.1.0"),
		fetchtest.Content("seed-zip"),
		fetchtest.GoMod("seed-gomod"),
	)
	if err := blobs.Put(context.Background(), fetchtest.GoModIdentity(t, rec), strings.NewReader("seed-gomod")); err != nil {
		t.Fatalf("seed go.mod blob: %v", err)
	}
	if zipPresent {
		if err := blobs.Put(context.Background(), fetchtest.ZipIdentity(t, rec), strings.NewReader("cached-zip")); err != nil {
			t.Fatalf("seed zip blob: %v", err)
		}
	}
	sealed, serr := domain2.Rehydrate(rec)
	if serr != nil {
		t.Fatalf("sealing seed record: %v", serr)
	}
	if err := facts.PutFetchRecord(context.Background(), sealed); err != nil {
		t.Fatalf("seed record: %v", err)
	}
}
