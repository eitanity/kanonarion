package application_test

import (
	"fmt"
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

func digestOf(uc *application.ContentIdentityUseCase, s string) ports.SubjectDigest {
	return uc.CanonicalDigest([]byte(s))
}

func memberSet(uc *application.ContentIdentityUseCase, n int) []ports.SubjectDigest {
	out := make([]ports.SubjectDigest, n)
	for i := range out {
		out[i] = digestOf(uc, fmt.Sprintf("member-%d", i))
	}
	return out
}

func TestCanonicalDigest_MatchesCoreDigest(t *testing.T) {
	t.Parallel()
	uc := application.NewContentIdentityUseCase()
	got := uc.CanonicalDigest([]byte("hello"))

	// Must equal core's existing canonical digest, so signing and identity
	// never drift apart.
	want := domain2.ContentDigest([]byte("hello"))
	if joined := got.Algorithm + ":" + got.Hex; joined != want {
		t.Errorf("CanonicalDigest = %q, want %q", joined, want)
	}
	if got.Algorithm != "sha256" {
		t.Errorf("algorithm = %q, want sha256", got.Algorithm)
	}
}

func TestMerkleRoot_EmptySet(t *testing.T) {
	t.Parallel()
	uc := application.NewContentIdentityUseCase()
	if _, err := uc.MerkleRoot(nil); err == nil {
		t.Fatal("MerkleRoot(nil) error = nil, want non-nil for empty set")
	}
}

func TestMerkleRoot_Deterministic(t *testing.T) {
	t.Parallel()
	uc := application.NewContentIdentityUseCase()
	set := memberSet(uc, 5)
	a, err := uc.MerkleRoot(set)
	if err != nil {
		t.Fatalf("MerkleRoot: %v", err)
	}
	b, _ := uc.MerkleRoot(set)
	if a != b {
		t.Errorf("MerkleRoot non-deterministic: %v vs %v", a, b)
	}
	if a.Algorithm != "sha256" || len(a.Hex) != 64 {
		t.Errorf("root digest malformed: %+v", a)
	}
}

func TestMerkleRoot_OrderSensitive(t *testing.T) {
	t.Parallel()
	uc := application.NewContentIdentityUseCase()
	set := memberSet(uc, 3)
	a, _ := uc.MerkleRoot(set)
	b, _ := uc.MerkleRoot([]ports.SubjectDigest{set[2], set[1], set[0]})
	if a == b {
		t.Error("reordering members produced the same root")
	}
}

func TestInclusionProof_RoundTrip(t *testing.T) {
	t.Parallel()
	uc := application.NewContentIdentityUseCase()
	for n := 1; n <= 9; n++ {
		set := memberSet(uc, n)
		root, err := uc.MerkleRoot(set)
		if err != nil {
			t.Fatalf("MerkleRoot(%d): %v", n, err)
		}
		for i := 0; i < n; i++ {
			proof, err := uc.InclusionProof(set, i)
			if err != nil {
				t.Fatalf("InclusionProof(%d,%d): %v", n, i, err)
			}
			if proof.Index != i || proof.Size != n {
				t.Errorf("proof position = (%d,%d), want (%d,%d)", proof.Index, proof.Size, i, n)
			}
			if !uc.VerifyInclusion(set[i], proof, root) {
				t.Errorf("proof for member %d of %d failed to verify", i, n)
			}
		}
	}
}

func TestInclusionProof_Errors(t *testing.T) {
	t.Parallel()
	uc := application.NewContentIdentityUseCase()
	set := memberSet(uc, 4)
	if _, err := uc.InclusionProof(nil, 0); err == nil {
		t.Error("InclusionProof over empty set error = nil, want non-nil")
	}
	if _, err := uc.InclusionProof(set, 4); err == nil {
		t.Error("InclusionProof out-of-range index error = nil, want non-nil")
	}
}

func TestVerifyInclusion_Rejects(t *testing.T) {
	t.Parallel()
	uc := application.NewContentIdentityUseCase()
	set := memberSet(uc, 6)
	root, _ := uc.MerkleRoot(set)
	proof, _ := uc.InclusionProof(set, 2)

	t.Run("wrong member", func(t *testing.T) {
		t.Parallel()
		if uc.VerifyInclusion(digestOf(uc, "not-a-member"), proof, root) {
			t.Error("verified proof against a non-member digest")
		}
	})
	t.Run("wrong root", func(t *testing.T) {
		t.Parallel()
		other, _ := uc.MerkleRoot(memberSet(uc, 3))
		if uc.VerifyInclusion(set[2], proof, other) {
			t.Error("verified proof against an unrelated root")
		}
	})
	t.Run("replayed at wrong index", func(t *testing.T) {
		t.Parallel()
		moved := application.InclusionProof{Index: 3, Size: proof.Size, Siblings: proof.Siblings}
		if uc.VerifyInclusion(set[2], moved, root) {
			t.Error("verified proof replayed at a different index")
		}
	})
}

// TestMalformedDigests covers the validation boundary: bad algorithm, bad hex,
// and wrong length must be rejected rather than silently entering a tree.
func TestMalformedDigests(t *testing.T) {
	t.Parallel()
	uc := application.NewContentIdentityUseCase()
	good := digestOf(uc, "ok")

	bad := []ports.SubjectDigest{
		{Algorithm: "sha512", Hex: good.Hex},
		{Algorithm: "sha256", Hex: "nothex!!"},
		{Algorithm: "sha256", Hex: "abcd"}, // too short
	}
	for _, m := range bad {
		if _, err := uc.MerkleRoot([]ports.SubjectDigest{m}); err == nil {
			t.Errorf("MerkleRoot accepted malformed digest %+v", m)
		}
		if _, err := uc.InclusionProof([]ports.SubjectDigest{m}, 0); err == nil {
			t.Errorf("InclusionProof accepted malformed digest %+v", m)
		}
	}

	// VerifyInclusion must return false (not panic) on malformed inputs.
	set := memberSet(uc, 2)
	root, _ := uc.MerkleRoot(set)
	proof, _ := uc.InclusionProof(set, 0)
	if uc.VerifyInclusion(bad[0], proof, root) {
		t.Error("VerifyInclusion accepted malformed member digest")
	}
	if uc.VerifyInclusion(set[0], proof, bad[1]) {
		t.Error("VerifyInclusion accepted malformed root digest")
	}
	badProof := application.InclusionProof{Index: proof.Index, Size: proof.Size, Siblings: []ports.SubjectDigest{bad[2]}}
	if uc.VerifyInclusion(set[0], badProof, root) {
		t.Error("VerifyInclusion accepted a malformed sibling digest")
	}
}
