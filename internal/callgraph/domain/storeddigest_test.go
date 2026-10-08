package domain_test

import (
	"bytes"
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// storedShell is what a store keeps for r: the record marshalled with no edges,
// with its content_hash blanked in place.
func storedShell(t *testing.T, r domain2.CallGraphRecord) []byte {
	t.Helper()
	var h domain2.CallGraphRecordHasher
	stored := r
	stored.Edges = nil
	raw, err := h.Marshal(stored)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return bytes.Replace(raw, []byte(`"content_hash":"`+r.ContentHash+`"`), []byte(`"content_hash":""`), 1)
}

// The digest over the stored shell and the edges kept beside it is the seal,
// whatever order the edges come back in.
func TestStoredDigest_IsTheSeal(t *testing.T) {
	var h domain2.CallGraphRecordHasher
	r := makeTestRecord()
	r.Edges = append(r.Edges, domain2.CallEdge{
		FromID: "example.com/mod.Z", ToID: "example.com/mod.A",
		CallSite: domain2.SourcePosition{File: "z.go", Line: 3}, Confidence: domain2.ConfidenceDirect,
	})
	r.EdgeCount = len(r.Edges)
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if len(sealed.Edges) < 2 {
		t.Fatal("fixture needs two edges to show order does not matter")
	}
	reversed := append([]domain2.CallEdge(nil), sealed.Edges...)
	reversed[0], reversed[len(reversed)-1] = reversed[len(reversed)-1], reversed[0]

	got, err := h.StoredDigest(storedShell(t, sealed), reversed)
	if err != nil {
		t.Fatalf("StoredDigest: %v", err)
	}
	if got != sealed.ContentHash {
		t.Errorf("StoredDigest = %s, want the seal %s", got, sealed.ContentHash)
	}

	// One edge changed is not the sealed record.
	altered := append([]domain2.CallEdge(nil), sealed.Edges...)
	altered[0].CallSite.Line++
	if other, err := h.StoredDigest(storedShell(t, sealed), altered); err != nil || other == sealed.ContentHash {
		t.Errorf("StoredDigest over an altered edge = (%s, %v), want a different digest", other, err)
	}
}

// Bytes with no edge span, or with two, are refused rather than guessed at.
func TestStoredDigest_RefusesAnAmbiguousSpan(t *testing.T) {
	var h domain2.CallGraphRecordHasher
	for name, shell := range map[string][]byte{
		"none": []byte(`{"content_hash":""}`),
		"two":  []byte(`{"content_hash":"","edges":[],"x":{"edges":[]}}`),
	} {
		if _, err := h.StoredDigest(shell, nil); err == nil {
			t.Errorf("%s: StoredDigest accepted %s", name, shell)
		}
	}
}
