package domain

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Merkle tree construction over an ordered set of leaf entries, following the
// RFC 6962 (Certificate Transparency) hashing rules. Domain separation — a
// 0x00 prefix on leaves and 0x01 on interior nodes — makes the leaf and node
// hash spaces disjoint, so a leaf hash can never be re-presented as an interior
// node (the second-preimage defence). The leaf entries are core's canonical
// digests; the tree gives an integrity-audit structure whose root commits to
// the whole selected set and whose inclusion proof pins one member without
// revealing the others.
//
// This is internal hashing detail: only the use case that wraps
// it is published, never these functions or a *Hasher type.
const (
	merkleLeafPrefix = 0x00
	merkleNodePrefix = 0x01
)

// ErrEmptyMerkleSet is returned when a Merkle root or proof is requested over a
// set with no leaves. An empty set has no canonical root, so callers must
// distinguish it rather than receive a zero hash that looks meaningful.
var ErrEmptyMerkleSet = errors.New("merkle set is empty")

// MerkleProof is an RFC 6962 inclusion (audit) proof: the sibling hashes that,
// combined bottom-up with a leaf, reconstruct the tree root. Index and Size pin
// the leaf's position so verification can replay the exact left/right ordering
// that produced the root; a proof for one (Index, Size) cannot be replayed
// against a different position.
type MerkleProof struct {
	// Index is the zero-based position of the proven leaf in the ordered set.
	Index int
	// Size is the total number of leaves in the tree the proof was built over.
	Size int
	// Siblings are the audit-path hashes, ordered from the leaf level upward.
	Siblings [][]byte
}

// merkleLeafHash hashes a leaf entry with the 0x00 domain-separation prefix.
func merkleLeafHash(entry []byte) []byte {
	h := sha256.New()
	h.Write([]byte{merkleLeafPrefix})
	h.Write(entry)
	return h.Sum(nil)
}

// merkleNodeHash hashes the concatenation of two child hashes with the 0x01
// domain-separation prefix.
func merkleNodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{merkleNodePrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// largestPowerOfTwoBelow returns the largest power of two strictly less than n,
// for n >= 2. It is the split point k of the RFC 6962 recursion.
func largestPowerOfTwoBelow(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// MerkleRoot returns the RFC 6962 Merkle tree hash over the ordered leaf
// entries. Each entry is a canonical digest of a selected record/blob. Order is
// significant: the same entries in a different order yield a different root.
// Returns ErrEmptyMerkleSet when leaves is empty.
func MerkleRoot(leaves [][]byte) ([]byte, error) {
	if len(leaves) == 0 {
		return nil, ErrEmptyMerkleSet
	}
	return merkleTreeHash(leaves), nil
}

// merkleTreeHash is the RFC 6962 MTH over a non-empty slice of leaf entries.
func merkleTreeHash(leaves [][]byte) []byte {
	if len(leaves) == 1 {
		return merkleLeafHash(leaves[0])
	}
	k := largestPowerOfTwoBelow(len(leaves))
	return merkleNodeHash(merkleTreeHash(leaves[:k]), merkleTreeHash(leaves[k:]))
}

// BuildMerkleProof returns the inclusion proof for the leaf at index over the
// ordered leaf entries. Returns ErrEmptyMerkleSet when leaves is empty, or an
// out-of-range error when index does not address a leaf.
func BuildMerkleProof(leaves [][]byte, index int) (MerkleProof, error) {
	if len(leaves) == 0 {
		return MerkleProof{}, ErrEmptyMerkleSet
	}
	if index < 0 || index >= len(leaves) {
		return MerkleProof{}, fmt.Errorf("merkle proof index %d out of range for %d leaves", index, len(leaves))
	}
	return MerkleProof{
		Index:    index,
		Size:     len(leaves),
		Siblings: auditPath(index, leaves),
	}, nil
}

// auditPath is the RFC 6962 PATH(m, D) function: the audit path for the leaf at
// position m within the ordered leaves D, ordered from the leaf level upward.
func auditPath(m int, leaves [][]byte) [][]byte {
	if len(leaves) == 1 {
		return nil
	}
	k := largestPowerOfTwoBelow(len(leaves))
	if m < k {
		return append(auditPath(m, leaves[:k]), merkleTreeHash(leaves[k:]))
	}
	return append(auditPath(m-k, leaves[k:]), merkleTreeHash(leaves[:k]))
}

// VerifyMerkleProof reports whether proof links the leaf entry to root. It
// replays the RFC 6962 verification: the proof's Index and Size drive the
// left/right ordering at each level, so a proof is only valid for the exact
// position it was built for. Returns false on any structural mismatch (bad
// index, wrong number of siblings, non-matching root).
func VerifyMerkleProof(entry []byte, proof MerkleProof, root []byte) bool {
	if proof.Index < 0 || proof.Index >= proof.Size {
		return false
	}
	fn, sn := proof.Index, proof.Size-1
	r := merkleLeafHash(entry)
	for _, sib := range proof.Siblings {
		if sn == 0 {
			// More siblings than the tree of this size can have.
			return false
		}
		if fn%2 == 1 || fn == sn {
			r = merkleNodeHash(sib, r)
			for fn%2 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = merkleNodeHash(r, sib)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(r, root)
}
