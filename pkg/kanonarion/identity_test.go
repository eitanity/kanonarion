package kanonarion_test

import (
	"reflect"
	"testing"

	"github.com/eitanity/kanonarion/pkg/kanonarion"
)

// TestContentIdentity_EndToEnd exercises the published surface: derive
// canonical digests, commit them to a Merkle root, and verify an inclusion
// proof — the canonical-digest and Merkle operations requires the façade
// to expose.
func TestContentIdentity_EndToEnd(t *testing.T) {
	t.Parallel()

	id := kanonarion.NewContentIdentity()

	members := []kanonarion.SubjectDigest{
		id.CanonicalDigest([]byte("alpha")),
		id.CanonicalDigest([]byte("bravo")),
		id.CanonicalDigest([]byte("charlie")),
	}

	root, err := id.MerkleRoot(members)
	if err != nil {
		t.Fatalf("MerkleRoot: %v", err)
	}

	proof, err := id.InclusionProof(members, 1)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}
	if !id.VerifyInclusion(members[1], proof, root) {
		t.Error("VerifyInclusion failed for a genuine member")
	}
	if id.VerifyInclusion(id.CanonicalDigest([]byte("outsider")), proof, root) {
		t.Error("VerifyInclusion accepted a non-member")
	}
}

// TestNoHasherReachable is the §3 acceptance guard: no exported
// identifier on the façade names a *Hasher type. Type aliases re-export the
// underlying type's name, so a leaked *Hasher would surface here.
func TestNoHasherReachable(t *testing.T) {
	t.Parallel()

	for _, v := range []any{
		kanonarion.NewContentIdentity(),
		kanonarion.SubjectDigest{},
		kanonarion.InclusionProof{},
	} {
		if name := reflect.TypeOf(v).String(); contains(name, "Hasher") {
			t.Errorf("façade type %q names a Hasher; the *Hasher types must stay internal", name)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
