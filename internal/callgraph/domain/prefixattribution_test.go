package domain_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// TestPrefixAttributedPackages_IsHashTransparentWhenEmpty pins the terms this
// field landed on. Every record sealed before it existed carries none, and must
// re-marshal to exactly the bytes it was sealed over — otherwise the field costs
// a purge or a pipeline-version bump to state something no stored record claims.
func TestPrefixAttributedPackages_IsHashTransparentWhenEmpty(t *testing.T) {
	t.Parallel()
	var h domain.CallGraphRecordHasher

	withoutField := makeTestRecord()
	withEmpty := makeTestRecord()
	withEmpty.PrefixAttributedPackages = []string{}

	a, err := h.Marshal(withoutField)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	b, err := h.Marshal(withEmpty)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("an empty prefix attribution changed the sealed bytes:\n%s\n%s", a, b)
	}
}

// TestPrefixAttributedPackages_IsSealedAndReadBack: when the fallback WAS used,
// the claim is inside the hash and survives the round trip. A label a reader
// could strip without invalidating the record is not a label.
func TestPrefixAttributedPackages_IsSealedAndReadBack(t *testing.T) {
	t.Parallel()
	var h domain.CallGraphRecordHasher

	plain, err := h.SetContentHash(makeTestRecord())
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	labelled := makeTestRecord()
	labelled.PrefixAttributedPackages = []string{"example.com/mod/second", "example.com/mod/first"}
	labelled, err = h.SetContentHash(labelled)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if labelled.ContentHash == plain.ContentHash {
		t.Error("a record that reconstructed its membership hashes the same as one that measured it")
	}

	raw, err := h.Marshal(labelled)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := h.Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	want := []string{"example.com/mod/first", "example.com/mod/second"}
	if !slices.Equal(back.PrefixAttributedPackages, want) {
		t.Errorf("read back %v, want %v (sorted on the wire)", back.PrefixAttributedPackages, want)
	}
	if err := h.VerifyContentHash(back); err != nil {
		t.Errorf("VerifyContentHash after round trip: %v", err)
	}
}
