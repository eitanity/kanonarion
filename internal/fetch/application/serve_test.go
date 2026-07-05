package application_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
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

func (b *existsControlBlob) Exists(ctx context.Context, h ports.BlobHandle) (bool, error) {
	if b.existsErr != nil {
		return false, b.existsErr
	}
	if b.forceAbsent {
		return false, nil
	}
	return b.fakeBlob.Exists(ctx, h)
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
	if res.Handle == "" {
		t.Error("expected a non-empty blob handle")
	}
	// The handle must name a blob that actually exists in the store.
	present, err := blobs.Exists(context.Background(), res.Handle)
	if err != nil || !present {
		t.Errorf("returned handle %q not present in store (present=%v err=%v)", res.Handle, present, err)
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
	handle, err := blobs.Put(context.Background(), strings.NewReader("cached-zip"))
	if err != nil {
		t.Fatalf("seed blob: %v", err)
	}
	seedRecord(t, facts, handle, domain2.Verified)

	serve := newServe(blobs, facts)
	res, err := serve.Serve(context.Background(), application.ServeRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if !res.FromCache {
		t.Error("expected FromCache=true on cache hit with present blob")
	}
	if res.Handle != handle {
		t.Errorf("Handle = %q, want cached %q", res.Handle, handle)
	}
	if res.VerificationStatus != domain2.Verified {
		t.Errorf("VerificationStatus = %q, want %q", res.VerificationStatus, domain2.Verified)
	}
}

func TestServe_CacheHitBlobEvictedRefetches(t *testing.T) {
	blobs := newFakeBlob()
	facts := newFakeFacts()

	// Seed a cached record pointing at a blob that is NOT in the store (evicted).
	seedRecord(t, facts, ports.BlobHandle("fake:evicted"), domain2.Verified)

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
	if res.Handle == ports.BlobHandle("fake:evicted") {
		t.Error("expected a freshly fetched handle, got the evicted one")
	}
	present, err := blobs.Exists(context.Background(), res.Handle)
	if err != nil || !present {
		t.Errorf("re-fetched handle %q not present (present=%v err=%v)", res.Handle, present, err)
	}
}

func TestServe_RefetchErrorPropagates(t *testing.T) {
	blobs := newFakeBlob()
	facts := newFakeFacts()

	// Cache hit whose blob is evicted, but the forced re-fetch fails at the proxy.
	seedRecord(t, facts, ports.BlobHandle("fake:evicted"), domain2.Verified)
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
	seedRecord(t, facts, ports.BlobHandle("fake:cached"), domain2.Verified)
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
	handle, err := blobs.Put(context.Background(), strings.NewReader("cached-zip"))
	if err != nil {
		t.Fatalf("seed blob: %v", err)
	}
	seedRecord(t, facts, handle, domain2.Verified)

	sink := newFakeAudit()
	serve := newServe(blobs, facts).WithAudit(sink)
	res, err := serve.Serve(context.Background(), application.ServeRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	// A verified module is served AND recorded as verified.
	if res.Handle != handle {
		t.Errorf("Handle = %q, want %q", res.Handle, handle)
	}
	ev := sink.only(t)
	if ev.Type != audit.EventRecordReadVerified {
		t.Fatalf("event type = %q, want %q", ev.Type, audit.EventRecordReadVerified)
	}
	if ev.Payload["verification_status"] != string(domain2.Verified) {
		t.Errorf("payload status = %v, want %q", ev.Payload["verification_status"], domain2.Verified)
	}
	if ev.Payload["module"] != testCoord.Path || ev.Payload["version"] != testCoord.Version {
		t.Errorf("payload coordinate = %v@%v, want %v", ev.Payload["module"], ev.Payload["version"], testCoord)
	}
}

func TestServe_AuditsVerificationFailedButStillServes(t *testing.T) {
	blobs := newFakeBlob()
	facts := newFakeFacts()
	handle, err := blobs.Put(context.Background(), strings.NewReader("cached-zip"))
	if err != nil {
		t.Fatalf("seed blob: %v", err)
	}
	// A blob whose hash did not match its trust anchor: the security-relevant
	// case. Serve does not gate — it records the rejection and still returns.
	seedRecord(t, facts, handle, domain2.UnverifiedHashMismatch)

	sink := newFakeAudit()
	serve := newServe(blobs, facts).WithAudit(sink)
	res, err := serve.Serve(context.Background(), application.ServeRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if res.Handle != handle {
		t.Errorf("Handle = %q, want served handle %q", res.Handle, handle)
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
	handle, err := blobs.Put(context.Background(), strings.NewReader("cached-zip"))
	if err != nil {
		t.Fatalf("seed blob: %v", err)
	}
	seedRecord(t, facts, handle, domain2.Verified)

	sink := &fakeAudit{err: errors.New("log unwritable")}
	serve := newServe(blobs, facts).WithAudit(sink)
	if _, err := serve.Serve(context.Background(), application.ServeRequest{Coordinate: testCoord}); err == nil {
		t.Fatal("expected serve to fail when the assurance log cannot be written")
	}
}

// seedRecord writes a fact record for testCoord at the test pipeline version,
// pointing at the given content handle with the given verification status.
func seedRecord(t *testing.T, facts ports.FactStore, handle ports.BlobHandle, status domain2.VerificationStatus) {
	t.Helper()
	rec := domain2.NewFactRecord(domain2.FetchedModule{
		Coordinate:         testCoord,
		ModuleHash:         domain2.ModuleHash{Algorithm: "h1", Value: "seed=="},
		GoModHash:          domain2.ModuleHash{Algorithm: "h1", Value: "seedmod=="},
		VerificationStatus: status,
		FetchedAt:          fixedTime,
		PipelineVersion:    "test-0.1.0",
		ContentLocation:    string(handle),
		GoModLocation:      "fake:seed-gomod",
	})
	if err := facts.PutFetchRecord(context.Background(), rec); err != nil {
		t.Fatalf("seed record: %v", err)
	}
}
