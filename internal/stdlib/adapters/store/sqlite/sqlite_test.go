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
	return domain.Facts{
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
	}
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

func TestPutReplaces(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	f := sampleFacts()
	if err := store.Put(ctx, f); err != nil {
		t.Fatal(err)
	}
	f.VerificationStatus = domain.GoDevChecksumMismatch
	f.VCSCommit = "newsha"
	if err := store.Put(ctx, f); err != nil {
		t.Fatal(err)
	}
	got, _, err := store.Get(ctx, "go1.26.4")
	if err != nil {
		t.Fatal(err)
	}
	if got.VerificationStatus != domain.GoDevChecksumMismatch || got.VCSCommit != "newsha" {
		t.Errorf("replace failed: %+v", got)
	}
}
