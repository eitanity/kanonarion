package domain_test

import (
	"reflect"
	"testing"
	"time"

	domain "github.com/eitanity/kanonarion/internal/stdlib/domain"
	"github.com/eitanity/kanonarion/internal/wireshape"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// determinismSeals is how many times this guard re-seals one value. Map
// iteration order differs between range statements, so a canonical form that
// leaked one would disagree with itself within a handful of attempts.
const determinismSeals = 50

// TestFacts_ContentHashIsIndependentOfInputOrder is the determinism guard for
// the standard library's custody measurement.
//
// The measurement is flat: every field the seal covers is a scalar, so there is
// no arrangement for the seal to depend on and nothing to shuffle. That is a
// property of the shape rather than a promise, so it is enumerated by
// reflection — adding a collection fails here, which is where the decision of
// how to order it has to be made.
func TestFacts_ContentHashIsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()

	for _, path := range wireshape.Collections(t, reflect.TypeOf(domain.Facts{})) {
		t.Errorf("Facts now carries the collection %q, whose order reaches its seal: "+
			"give it a total order in a named comparator and shuffle it here", path)
	}

	var h domain.FactsHasher
	var want string
	for i := range determinismSeals {
		sealed, err := h.SetContentHash(makeDeterminismFacts())
		if err != nil {
			t.Fatalf("seal %d: SetContentHash: %v", i, err)
		}
		if i == 0 {
			want = sealed.ContentHash
			continue
		}
		if sealed.ContentHash != want {
			t.Fatalf("seal %d: content hash %s, seal 0 gave %s: the seal is not a function of the measurement alone",
				i, sealed.ContentHash, want)
		}
	}
}

func makeDeterminismFacts() domain.Facts {
	return domain.Facts{
		GoVersion:          "go1.26.6",
		Digests:            fetchdomain.ArtifactDigests{SHA256: "aa", SHA384: "bb", SHA512: "cc"},
		PublishedSHA256:    "aa",
		VerificationDetail: "checksum from go.dev/dl",
		LicenseSPDX:        "BSD-3-Clause",
		SourceURL:          "https://go.dev/dl/go1.26.6.src.tar.gz",
		VCSURL:             "https://go.googlesource.com/go",
		VCSRef:             "go1.26.6",
		AcquiredAt:         time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
	}
}
