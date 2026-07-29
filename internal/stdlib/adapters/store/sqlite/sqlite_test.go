package sqlite_test

import (
	"context"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/stdlib/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/stdlib/domain"
)

func sampleFacts() domain.Facts {
	return sealed(domain.Facts{
		GoVersion:          "go1.26.4",
		Digests:            fetchdomain.ArtifactDigests{SHA256: "s256", SHA384: "s384", SHA512: "s512"},
		PublishedSHA256:    "s256",
		VerificationStatus: domain.VerifiedGoDevChecksum,
		VerificationDetail: "matched go.dev/dl; commit abc",
		LicenseSPDX:        "BSD-3-Clause",
		SourceURL:          "https://go.dev/dl/go1.26.4.src.tar.gz",
		VCSURL:             domain.VCSRepoURL,
		VCSRef:             "go1.26.4",
		VCSCommit:          "abc123",
		ContentLocation:    "sha256:deadbeef",
		AcquiredAt:         time.Unix(1_700_000_000, 0).UTC(),
		AcquisitionRoute:   domain.RouteGoDev,
	})
}

// sealed stamps a measurement's content hash, which the store now requires to
// agree with the measurement it seals.
func sealed(f domain.Facts) domain.Facts {
	out, err := domain.FactsHasher{}.SetContentHash(f)
	if err != nil {
		panic("SetContentHash: " + err.Error())
	}
	return out
}

func TestPutGetRoundTrip(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	want := sampleFacts()
	if err := store.Put(ctx, want); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, ok, err := store.Get(ctx, "go1.26.4")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if got != want {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestGetMiss(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, ok, err := store.Get(context.Background(), "go9.9.9")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if ok {
		t.Error("expected cache miss")
	}
}

// TestPutAppendsRatherThanReplaces replaces a test that asserted the opposite,
// and the replacement is the point of the conversion.
//
// The old TestPutReplaces pinned the overwrite: a second Put for one Go version
// replaced the first, and it was the only place that behaviour was asserted. That
// overwrite is the defect — a run that could not reach go.dev/dl replaced the run
// that could, and the evidence that a stronger anchor had ever been established
// was gone rather than merely unserved.
func TestPutAppendsRatherThanReplaces(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()

	verified := sampleFacts()
	// A later run that could not consult the published checksum. Same bytes, same
	// route; only the anchor differs, and it is the NEWER measurement.
	unavailable := sampleFacts()
	unavailable.VerificationStatus = domain.UnverifiedGoDevUnavailable
	unavailable.PublishedSHA256 = ""
	unavailable.VerificationDetail = "go.dev/dl published checksum unavailable"
	unavailable.AcquiredAt = verified.AcquiredAt.Add(time.Hour)
	unavailable = sealed(unavailable)

	for _, f := range []domain.Facts{verified, unavailable} {
		if perr := store.Put(ctx, f); perr != nil {
			t.Fatalf("put: %v", perr)
		}
	}

	gens, err := store.ListFactsFor(ctx, "go1.26.4")
	if err != nil {
		t.Fatalf("ListFactsFor: %v", err)
	}
	if len(gens) != 2 {
		t.Fatalf("ledger holds %d measurements, want 2 — the second acquisition overwrote the first", len(gens))
	}

	got, ok, err := store.Get(ctx, "go1.26.4")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if got.VerificationStatus != domain.VerifiedGoDevChecksum {
		t.Fatalf("composed read served %q — a run that never consulted the checksum displaced one that matched it",
			got.VerificationStatus)
	}
}

// TestPutSameMeasurementTwiceIsANoOp: one measurement written twice is still one
// measurement, and must not fail a run that had already succeeded.
func TestPutSameMeasurementTwiceIsANoOp(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	f := sampleFacts()
	for i := range 2 {
		if perr := store.Put(ctx, f); perr != nil {
			t.Fatalf("put %d: %v", i, perr)
		}
	}
	gens, err := store.ListFactsFor(ctx, "go1.26.4")
	if err != nil {
		t.Fatalf("ListFactsFor: %v", err)
	}
	if len(gens) != 1 {
		t.Fatalf("ledger holds %d measurements, want 1", len(gens))
	}
}
