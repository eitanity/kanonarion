package application_test

import (
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"

	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// metadataOnlyScan runs a scan whose only possible outcome is the metadata-only
// fallback, and returns the record. facts is the ledger to consult; an empty one
// means the store holds nothing about the coordinate.
func metadataOnlyScan(t *testing.T, coord coordinate.ModuleCoordinate, facts *fakeFacts) domain.VulnerabilityRecord {
	t.Helper()
	ctx := t.Context()
	now := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)

	uc := application.NewScanModuleUseCase(
		facts, newFakeBlob(), newFakeVulnStore(), nil, &fakeScanner{},
		&fakeDatabase{snapshot: vulntest.MustNewAt("test", "v1", now), content: "vulndb content"},
		nil, fixedClock{t: now}, "v1", slog.Default(),
	)
	res, err := uc.Scan(ctx, application.ScanModuleParams{Coordinate: coord, WalkID: "walk-1"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.UnscannableReason == "" {
		t.Fatalf("expected the metadata-only fallback for %s", coord)
	}
	return res
}

// assertNoShallowClaim fails if any field of the record mentions shallowness.
//
// The scan cannot see the walk's depth from where it stands, so the word can
// only ever be a guess there — and it was one: a full-depth project walk's local
// root recorded "module not fetched (shallow walk)". Serialising the whole record
// rather than checking the note keeps the guard honest if the claim moves to
// another field.
func assertNoShallowClaim(t *testing.T, rec domain.VulnerabilityRecord) {
	t.Helper()
	blob, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshalling record: %v", err)
	}
	if strings.Contains(strings.ToLower(string(blob)), "shallow") {
		t.Errorf("record claims a shallow walk it never measured:\n%s", blob)
	}
}

// TestMetadataOnlyReason_LocalRootIsNotAShallowWalk is the regression guard for
// the false claim.
//
// A project walk of full depth roots at the local main module, which has no
// published artefact for the store to hold. Degrading it to the fetched surface
// therefore reaches the metadata-only fallback, and that fallback used to assert
// the walk had been shallow — a cause it never measured, about a walk that was
// nothing of the kind. The reason now names what is true of a local coordinate:
// nothing was published, so there was nothing to fetch.
func TestMetadataOnlyReason_LocalRootIsNotAShallowWalk(t *testing.T) {
	local, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatal(err)
	}

	rec := metadataOnlyScan(t, local, newFakeFacts())

	if rec.UnscanReason != domain.UnscanReasonLocalProjectSource {
		t.Errorf("UnscanReason = %q, want %q", rec.UnscanReason, domain.UnscanReasonLocalProjectSource)
	}
	for _, want := range []string{"local project source", "no published artefact exists to fetch", "project directory"} {
		if !strings.Contains(rec.UnscannableReason, want) {
			t.Errorf("reason %q must state %q", rec.UnscannableReason, want)
		}
	}
	assertNoShallowClaim(t, rec)
}

// TestMetadataOnlyReason_AbsentSourceNamesNoCause covers the branch the local
// coordinate was split out of. All the scan measured is that the store holds no
// source, so that is all the reason says: a shallow walk is one way to arrive
// here, a retired fetch generation is another, and picking one is a guess
// printed as a finding.
func TestMetadataOnlyReason_AbsentSourceNamesNoCause(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/neverfetched", "v1.0.0")

	rec := metadataOnlyScan(t, coord, newFakeFacts())

	if rec.UnscanReason != domain.UnscanReasonSourceNotInStore {
		t.Errorf("UnscanReason = %q, want %q", rec.UnscanReason, domain.UnscanReasonSourceNotInStore)
	}
	if rec.UnscannableReason != "metadata-only: module source not in the store" {
		t.Errorf("reason = %q, want it to state the absence and stop there", rec.UnscannableReason)
	}
	assertNoShallowClaim(t, rec)
}

// TestMetadataOnlyReason_StdlibAndGoModOnlyCarryCodes closes the display gap:
// these two shapes are written by the scan itself on every run, so leaving them
// uncoded parked them in the roll-up bucket reserved for producers the display
// does not know — which then printed their reason under a heading announcing
// that no reason had been recorded.
func TestMetadataOnlyReason_StdlibAndGoModOnlyCarryCodes(t *testing.T) {
	t.Run("stdlib", func(t *testing.T) {
		std := coordinatetest.MustNew(domain.StdlibModulePath, "v1.26.5")
		rec := metadataOnlyScan(t, std, newFakeFacts())
		if rec.UnscanReason != domain.UnscanReasonStdlibMetadata {
			t.Errorf("UnscanReason = %q, want %q", rec.UnscanReason, domain.UnscanReasonStdlibMetadata)
		}
	})

	t.Run("go.mod only", func(t *testing.T) {
		ctx := t.Context()
		coord := coordinatetest.MustNew("example.com/gomodonly", "v1.0.0")
		facts := newFakeFacts()
		if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t,
			fetchtest.Coordinate(coord),
			fetchtest.PipelineVersion("v1"),
			fetchtest.GoModOnly("gomod content"),
		)); err != nil {
			t.Fatalf("PutFetchRecord: %v", err)
		}

		rec := metadataOnlyScan(t, coord, facts)
		if rec.UnscanReason != domain.UnscanReasonGoModOnly {
			t.Errorf("UnscanReason = %q, want %q", rec.UnscanReason, domain.UnscanReasonGoModOnly)
		}
	})
}
