package domain_test

import (
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/canonicalshape"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/stdlib/domain"
)

// TestCanonicalShape_IsPinned fails when the bytes this domain seals over
// change. See package canonicalshape for what to do when it fires.
func TestCanonicalShape_IsPinned(t *testing.T) {
	t.Parallel()

	var h domain.FactsHasher
	sealed, err := h.SetContentHash(domain.Facts{
		GoVersion:          "go1.26.5",
		Digests:            fetchdomain.ArtifactDigests{SHA256: "sha256-value", SHA384: "sha384-value", SHA512: "sha512-value"},
		PublishedSHA256:    "sha256-value",
		VerificationStatus: domain.VerifiedGoDevChecksum,
		VerificationDetail: "SHA-256 matched go.dev/dl published checksum for go1.26.5.src.tar.gz",
		LicenseSPDX:        "BSD-3-Clause",
		SourceURL:          "https://go.dev/dl/go1.26.5.src.tar.gz",
		VCSURL:             domain.VCSRepoURL,
		VCSRef:             "go1.26.5",
		VCSCommit:          "c19862e5f8415b4f24b189d065ed739517c548ba",
		ContentLocation:    "zip:sha256:abc",
		AcquiredAt:         time.Date(2026, 7, 28, 17, 7, 30, 0, time.UTC),
		AcquisitionRoute:   domain.RouteGoDev,
	})
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	got, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	canonicalshape.AssertGolden(t, "testdata/canonical_shape.json", got)
}
