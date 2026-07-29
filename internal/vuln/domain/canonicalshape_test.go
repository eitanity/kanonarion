package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/canonicalshape"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestCanonicalShape_IsPinned fails when the bytes this domain seals over
// change. See package canonicalshape for what to do when it fires.
func TestCanonicalShape_IsPinned(t *testing.T) {
	t.Parallel()

	var h domain.VulnerabilityRecordHasher
	sealed, err := h.SetContentHash(sampleRecord(t))
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	got, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	canonicalshape.AssertGolden(t, "testdata/canonical_shape.json", got)
}
