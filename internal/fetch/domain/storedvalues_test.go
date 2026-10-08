package domain_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// The stored-values check answers whether a row's values, fetched_at spelled as
// stored, hash to its seal: true for a spelling this build would not write,
// false for an altered value or an unsealed row.
func TestCanonicalHasher_StoredValuesHashToSeal(t *testing.T) {
	var h domain.CanonicalHasher
	at := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	r := fetchtest.Record(t, fetchtest.FetchedAt(at))
	if !h.StoredValuesHashToSeal(r, at.Format(time.RFC3339)) {
		t.Error("this build's own spelling does not reproduce its seal")
	}

	respelt := strings.TrimSuffix(at.Format(time.RFC3339), "Z") + ".5Z"
	unsealed := r
	unsealed.ContentHash = ""
	raw, err := h.Marshal(unsealed)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(strings.Replace(string(raw), at.Format(time.RFC3339), respelt, 1)))
	other := r
	other.ContentHash = "sha256:" + hex.EncodeToString(sum[:])
	other.FetchedAt = at.Add(500 * time.Millisecond)
	if !h.StoredValuesHashToSeal(other, respelt) {
		t.Error("a seal taken over another spelling of fetched_at is not recognised")
	}
	if h.VerifyContentHash(other) == nil {
		t.Error("fixture is reproducible by this build; it would prove nothing")
	}

	altered := other
	altered.VerificationDetail = "rewritten"
	if h.StoredValuesHashToSeal(altered, respelt) {
		t.Error("an altered value hashes to the seal")
	}
	if h.StoredValuesHashToSeal(unsealed, at.Format(time.RFC3339)) {
		t.Error("an unsealed row claims to hash to a seal")
	}
}
