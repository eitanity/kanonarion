package domain

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// leaf returns a distinct deterministic entry for index i.
func leaf(i int) []byte { return fmt.Appendf(nil, "leaf-%d", i) }

func leaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = leaf(i)
	}
	return out
}

func TestMerkleRoot_EmptySet(t *testing.T) {
	t.Parallel()
	if _, err := MerkleRoot(nil); !errors.Is(err, ErrEmptyMerkleSet) {
		t.Fatalf("MerkleRoot(nil) error = %v, want ErrEmptyMerkleSet", err)
	}
}

func TestMerkleRoot_SingleLeafIsLeafHash(t *testing.T) {
	t.Parallel()
	root, err := MerkleRoot([][]byte{leaf(0)})
	if err != nil {
		t.Fatalf("MerkleRoot: %v", err)
	}
	if want := merkleLeafHash(leaf(0)); !bytes.Equal(root, want) {
		t.Errorf("single-leaf root = %x, want leaf hash %x", root, want)
	}
}

// TestMerkleRoot_StructuralVectors pins the RFC 6962 recursion shape for small
// trees against hand-derived node/leaf compositions, independent of the
// recursive implementation.
func TestMerkleRoot_StructuralVectors(t *testing.T) {
	t.Parallel()
	l0, l1, l2, l3 := merkleLeafHash(leaf(0)), merkleLeafHash(leaf(1)), merkleLeafHash(leaf(2)), merkleLeafHash(leaf(3))

	tests := []struct {
		name string
		n    int
		want []byte
	}{
		{"two", 2, merkleNodeHash(l0, l1)},
		// k = largest power of two below 3 = 2: node(node(l0,l1), l2).
		{"three", 3, merkleNodeHash(merkleNodeHash(l0, l1), l2)},
		// k = 2: node(node(l0,l1), node(l2,l3)).
		{"four", 4, merkleNodeHash(merkleNodeHash(l0, l1), merkleNodeHash(l2, l3))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := MerkleRoot(leaves(tt.n))
			if err != nil {
				t.Fatalf("MerkleRoot: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("root(%d) = %x, want %x", tt.n, got, tt.want)
			}
		})
	}
}

func TestMerkleRoot_OrderSensitive(t *testing.T) {
	t.Parallel()
	a, _ := MerkleRoot([][]byte{leaf(0), leaf(1)})
	b, _ := MerkleRoot([][]byte{leaf(1), leaf(0)})
	if bytes.Equal(a, b) {
		t.Error("root is order-insensitive; reordered leaves produced the same root")
	}
}

// TestInclusionProof_RoundTrip exhaustively builds and verifies a proof for
// every leaf across a range of tree sizes, including non-power-of-two sizes
// that exercise the unbalanced RFC 6962 recursion.
func TestInclusionProof_RoundTrip(t *testing.T) {
	t.Parallel()
	for n := 1; n <= 17; n++ {
		set := leaves(n)
		root, err := MerkleRoot(set)
		if err != nil {
			t.Fatalf("MerkleRoot(%d): %v", n, err)
		}
		for i := 0; i < n; i++ {
			proof, err := BuildMerkleProof(set, i)
			if err != nil {
				t.Fatalf("BuildMerkleProof(%d,%d): %v", n, i, err)
			}
			if proof.Index != i || proof.Size != n {
				t.Errorf("proof position = (%d,%d), want (%d,%d)", proof.Index, proof.Size, i, n)
			}
			if !VerifyMerkleProof(set[i], proof, root) {
				t.Errorf("proof for leaf %d of %d failed to verify", i, n)
			}
		}
	}
}

func TestVerifyMerkleProof_Rejects(t *testing.T) {
	t.Parallel()
	set := leaves(7)
	root, _ := MerkleRoot(set)
	proof, _ := BuildMerkleProof(set, 3)

	t.Run("wrong entry", func(t *testing.T) {
		t.Parallel()
		if VerifyMerkleProof([]byte("not-the-leaf"), proof, root) {
			t.Error("verified a proof against the wrong leaf entry")
		}
	})
	t.Run("wrong root", func(t *testing.T) {
		t.Parallel()
		bad := append([]byte(nil), root...)
		bad[0] ^= 0xff
		if VerifyMerkleProof(set[3], proof, bad) {
			t.Error("verified a proof against a tampered root")
		}
	})
	t.Run("tampered sibling", func(t *testing.T) {
		t.Parallel()
		tampered := MerkleProof{Index: proof.Index, Size: proof.Size, Siblings: make([][]byte, len(proof.Siblings))}
		for i, s := range proof.Siblings {
			tampered.Siblings[i] = append([]byte(nil), s...)
		}
		tampered.Siblings[0][0] ^= 0xff
		if VerifyMerkleProof(set[3], tampered, root) {
			t.Error("verified a proof with a tampered sibling hash")
		}
	})
	t.Run("wrong position replay", func(t *testing.T) {
		t.Parallel()
		moved := MerkleProof{Index: 4, Size: proof.Size, Siblings: proof.Siblings}
		if VerifyMerkleProof(set[3], moved, root) {
			t.Error("verified a proof replayed at a different index")
		}
	})
	t.Run("index out of range", func(t *testing.T) {
		t.Parallel()
		if VerifyMerkleProof(set[3], MerkleProof{Index: 7, Size: 7, Siblings: proof.Siblings}, root) {
			t.Error("verified a proof whose index equals the tree size")
		}
	})
	t.Run("too many siblings", func(t *testing.T) {
		t.Parallel()
		extra := MerkleProof{Index: proof.Index, Size: proof.Size, Siblings: append(append([][]byte(nil), proof.Siblings...), root)}
		if VerifyMerkleProof(set[3], extra, root) {
			t.Error("verified a proof carrying more siblings than the tree height")
		}
	})
}

func TestBuildMerkleProof_Errors(t *testing.T) {
	t.Parallel()
	if _, err := BuildMerkleProof(nil, 0); !errors.Is(err, ErrEmptyMerkleSet) {
		t.Errorf("empty set error = %v, want ErrEmptyMerkleSet", err)
	}
	set := leaves(4)
	for _, idx := range []int{-1, 4, 99} {
		if _, err := BuildMerkleProof(set, idx); err == nil {
			t.Errorf("BuildMerkleProof(index=%d) error = nil, want out-of-range", idx)
		}
	}
}

func TestSingleLeafProof_IsEmpty(t *testing.T) {
	t.Parallel()
	set := leaves(1)
	root, _ := MerkleRoot(set)
	proof, err := BuildMerkleProof(set, 0)
	if err != nil {
		t.Fatalf("BuildMerkleProof: %v", err)
	}
	if len(proof.Siblings) != 0 {
		t.Errorf("single-leaf proof has %d siblings, want 0", len(proof.Siblings))
	}
	if !VerifyMerkleProof(set[0], proof, root) {
		t.Error("single-leaf proof failed to verify")
	}
}
