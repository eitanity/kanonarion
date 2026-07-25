package application_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// A --skip-vcs --force run INHERITS the VCS leg an earlier measurement
// established, rather than discarding evidence the store already holds, and the
// inherited leg names the record it came from.
//
// The name is what makes the copy falsifiable. Without it, "inherited" is an
// unfalsifiable claim sitting on a tamper-evident record, and a reader cannot
// tell evidence carried forward from evidence that was never established.
func TestExecute_SkipVCSForceInheritsTheEarlierLegAndNamesItsSource(t *testing.T) {
	facts := newFakeFacts()
	uc := newUseCase(newProxyWithOrigin(), &fakeVCS{}, newFakeBlob(), facts)
	ctx := context.Background()

	// Run 1 performs the VCS check.
	first, err := uc.Execute(ctx, application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	if domain2.LegProvenance(first.Record.VCSCheck) != domain2.LegRechecked {
		t.Fatalf("the first run recorded VCS leg %q, want rechecked", first.Record.VCSCheck)
	}

	// Run 2 skips the check but is forced, so it must carry the earlier result
	// forward rather than record nothing.
	second, err := uc.Execute(ctx, application.FetchRequest{
		Coordinate:    testCoord,
		SkipVCSVerify: true,
		Force:         true,
	})
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if got := domain2.LegProvenance(second.Record.VCSCheck); got != domain2.LegInherited {
		t.Fatalf("a --skip-vcs --force run recorded VCS leg %q, want inherited", got)
	}
	if second.Record.VCSCheckSource != first.Record.ContentHash {
		t.Errorf("inherited leg names source %q, want the record it came from %q; an unnamed inheritance is unfalsifiable",
			second.Record.VCSCheckSource, first.Record.ContentHash)
	}
}

// A measurement records what it did. A fetch that pulled the bytes is
// "acquired"; there is deliberately no "unchanged" kind, because a cache hit
// writes no row at all.
func TestExecute_RecordsTheMeasurementKind(t *testing.T) {
	facts := newFakeFacts()
	uc := newUseCase(newProxyWithOrigin(), &fakeVCS{}, newFakeBlob(), facts)

	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Record.MeasurementKind != string(domain2.MeasurementAcquired) {
		t.Errorf("MeasurementKind = %q, want %q", res.Record.MeasurementKind, domain2.MeasurementAcquired)
	}
}

// A run that performs the VCS check records the leg as rechecked; a --skip-vcs
// run records NO leg at all. Absence is not a negative result: "not checked" and
// "checked and could not confirm" are different claims, and collapsing them
// would make a skipped check look like a failed verification.
func TestExecute_SkippedVCSRecordsNoLegAtAll(t *testing.T) {
	for _, tc := range []struct {
		name     string
		skip     bool
		wantLeg  domain2.LegProvenance
		describe string
	}{
		{"checked", false, domain2.LegRechecked, "a run that performed the check"},
		{"skipped", true, domain2.LegAbsent, "a --skip-vcs run"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := newFakeFacts()
			uc := newUseCase(newProxyWithOrigin(), &fakeVCS{}, newFakeBlob(), facts)

			res, err := uc.Execute(context.Background(), application.FetchRequest{
				Coordinate:    testCoord,
				SkipVCSVerify: tc.skip,
			})
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if got := domain2.LegProvenance(res.Record.VCSCheck); got != tc.wantLeg {
				t.Errorf("%s recorded VCS leg %q, want %q", tc.describe, got, tc.wantLeg)
			}
		})
	}
}

// A cache hit writes NOTHING to the ledger. Writing a row per run — even an
// "unchanged" one — converts a per-artefact ledger into a per-run one, and
// reinstates the growth rate the design exists to avoid: a daily CI walk against
// a stable pipeline version must append approximately zero rows.
func TestExecute_CacheHitAppendsNoRow(t *testing.T) {
	facts := newFakeFacts()
	blobs := newFakeBlob()
	proxy := newProxyWithOrigin()
	uc := newUseCase(proxy, &fakeVCS{}, blobs, facts)

	first, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	if first.FromCache {
		t.Fatal("the first fetch of a cold store reported a cache hit")
	}
	countAfterFirst := first.Record.MeasurementCount

	second, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if !second.FromCache {
		t.Fatal("the second fetch did not take the cache")
	}
	if second.Record.MeasurementCount != countAfterFirst {
		t.Errorf("a cache hit appended a row: measurements went %d -> %d",
			countAfterFirst, second.Record.MeasurementCount)
	}
}

// A forced run APPENDS rather than replacing, so the earlier measurement
// survives and a reader gets the composition of both.
func TestExecute_ForceAppendsWithoutDestroyingTheEarlierMeasurement(t *testing.T) {
	facts := newFakeFacts()
	uc := newUseCase(newProxyWithOrigin(), &fakeVCS{}, newFakeBlob(), facts)

	first, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}

	forced, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord, Force: true})
	if err != nil {
		t.Fatalf("forced Execute: %v", err)
	}
	// The fake store keys on coordinate alone, so it cannot hold two rows; what
	// this asserts is that the forced run did not report the earlier measurement
	// as gone, and that first-seen did not move forward to the forced run.
	if !forced.Record.FirstFetchedAt.Equal(first.Record.FirstFetchedAt) {
		t.Errorf("a forced re-measurement moved first-seen from %v to %v; the artefact was first seen when it was first seen",
			first.Record.FirstFetchedAt, forced.Record.FirstFetchedAt)
	}
}

// A bad run writes NOTHING. A record that fails verification is refused and the
// store is left untouched, so the ledger only ever holds measurements that
// passed — which is what makes a divergence in it always operator-created.
func TestIngest_ABadRunWritesNothing(t *testing.T) {
	store := newFakeFacts()
	uc := application.NewValidateAndIngestUseCase(store)

	tampered := tamperedRecord(t)
	err := uc.Ingest(context.Background(), tampered)
	if !errors.Is(err, application.ErrVerificationFailed) {
		t.Fatalf("Ingest of a tampered record: got %v, want ErrVerificationFailed", err)
	}

	if _, found, ferr := store.GetFetchRecord(context.Background(),
		tampered.Coordinate(), tampered.PipelineVersion); ferr != nil || found {
		t.Errorf("a refused record reached the store: found=%v err=%v", found, ferr)
	}
}

// A NEGATIVE FINDING is not a bad run. UnverifiedNoSumDB and friends are
// measurements that completed and answered negatively; they are persisted, and
// must stay persisted. Conflating them with an integrity failure would make the
// tool silent about exactly the modules it should be loudest about.
func TestExecute_NegativeVerificationFindingIsStillRecorded(t *testing.T) {
	facts := newFakeFacts()
	// sumdb disabled: the module cannot be anchored to the transparency log, which
	// is a completed measurement with a negative answer.
	uc := newUseCase(&fakeProxy{}, &fakeVCS{}, newFakeBlob(), facts)

	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("a negative verification finding failed the fetch: %v", err)
	}
	if domain2.VerificationStatus(res.Record.VerificationStatus).IsVerified() {
		t.Fatalf("expected an unverified status, got %q", res.Record.VerificationStatus)
	}
	if _, found, ferr := facts.GetFetchRecord(context.Background(), testCoord, "test-0.1.0"); ferr != nil || !found {
		t.Errorf("a negative finding was not persisted: found=%v err=%v", found, ferr)
	}
}

// The cold-store single-fetch guarantee (decision 16): a go.mod-only fetch
// followed by a full fetch of the same coordinate performs exactly one zip
// download and never a second go.mod download.
//
// The property currently lives implicitly in two asymmetric cache checks — the
// full path takes a hit only when the existing record is not go.mod-only, while
// the go.mod-only path treats any existing record as a hit. An append-only
// rewrite that collapsed them would lose it SILENTLY: nothing fails, CI just
// gets slower. Hence an explicit test.
func TestExecute_ColdStoreFetchesTheZipExactlyOnce(t *testing.T) {
	facts := newFakeFacts()
	blobs := newFakeBlob()
	proxy := newProxyWithOrigin()
	uc := newUseCase(proxy, &fakeVCS{}, blobs, facts)
	ctx := context.Background()

	// A superseded version is resolved go.mod-only: no zip is downloaded.
	if _, err := uc.Execute(ctx, application.FetchRequest{Coordinate: testCoord, GoModOnly: true}); err != nil {
		t.Fatalf("go.mod-only fetch: %v", err)
	}
	if proxy.zipDownloads != 0 {
		t.Fatalf("a go.mod-only fetch downloaded %d zips, want 0", proxy.zipDownloads)
	}

	// A later stage needs source, so the full path runs over the same coordinate.
	if _, err := uc.Execute(ctx, application.FetchRequest{Coordinate: testCoord}); err != nil {
		t.Fatalf("full fetch: %v", err)
	}
	if proxy.zipDownloads != 1 {
		t.Errorf("zip downloads = %d, want exactly 1 across the go.mod-only fetch and the full fetch",
			proxy.zipDownloads)
	}

	// A further go.mod-only request is answered from what is already held.
	if _, err := uc.Execute(ctx, application.FetchRequest{Coordinate: testCoord, GoModOnly: true}); err != nil {
		t.Fatalf("second go.mod-only fetch: %v", err)
	}
	if proxy.zipDownloads != 1 {
		t.Errorf("zip downloads = %d after a repeat go.mod-only request, want 1", proxy.zipDownloads)
	}
}

// The blob store is addressed by artefact identity, so the record's own hashes
// resolve its bytes and no store-chosen handle is ever persisted. This is what
// makes the defect class from the module-cache poisoning unreachable rather than
// guarded: a coordinate measured by two routes lands on one address.
func TestExecute_RecordsAnIdentityAddressNotAStoreChosenHandle(t *testing.T) {
	facts := newFakeFacts()
	blobs := newFakeBlob()
	uc := newUseCase(newProxyWithOrigin(), &fakeVCS{}, blobs, facts)

	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	identity, ok, err := ports.ZipIdentity(res.Record.FactRecord)
	if err != nil || !ok {
		t.Fatalf("the record carries no derivable zip identity: ok=%v err=%v", ok, err)
	}
	if res.Record.ContentLocation != identity.String() {
		t.Errorf("ContentLocation = %q, want the artefact identity %q", res.Record.ContentLocation, identity)
	}
	if strings.Contains(res.Record.ContentLocation, "modcache:") ||
		strings.HasPrefix(res.Record.ContentLocation, "sha256:") {
		t.Errorf("ContentLocation %q is a store-chosen handle; the address must name the artefact", res.Record.ContentLocation)
	}
	// And the bytes are actually reachable at that address.
	present, err := blobs.Exists(context.Background(), identity)
	if err != nil || !present {
		t.Errorf("the recorded identity does not resolve in the store: present=%v err=%v", present, err)
	}
}
