package domain_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/stdlib/domain"
)

// The stored-values check answers whether a row's values, acquired_at spelled
// as stored, hash to its seal: true for a spelling this build would not write,
// false for an altered value or an unsealed row.
func TestFactsHasher_StoredValuesHashToSeal(t *testing.T) {
	var h domain.FactsHasher
	at := time.Unix(1_700_000_000, 0).UTC()
	f, err := h.SetContentHash(domain.Facts{GoVersion: "go1.26.4", AcquiredAt: at, LicenseSPDX: "BSD-3-Clause"})
	if err != nil {
		t.Fatal(err)
	}
	if !h.StoredValuesHashToSeal(f, at.Format(time.RFC3339)) {
		t.Error("this build's own spelling does not reproduce its seal")
	}

	respelt := at.Format("2006-01-02T15:04:05") + ".5Z"
	unsealed := f
	unsealed.ContentHash = ""
	raw, err := h.Marshal(unsealed)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(strings.Replace(string(raw), at.Format(time.RFC3339), respelt, 1)))
	other := f
	other.ContentHash = "sha256:" + hex.EncodeToString(sum[:])
	if !h.StoredValuesHashToSeal(other, respelt) {
		t.Error("a seal taken over another spelling of acquired_at is not recognised")
	}
	if h.VerifyContentHash(other) == nil {
		t.Error("fixture is reproducible by this build; it would prove nothing")
	}

	altered := other
	altered.LicenseSPDX = "MIT"
	if h.StoredValuesHashToSeal(altered, respelt) {
		t.Error("an altered value hashes to the seal")
	}
	if h.StoredValuesHashToSeal(unsealed, at.Format(time.RFC3339)) {
		t.Error("an unsealed row claims to hash to a seal")
	}
}
