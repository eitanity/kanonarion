package application

import (
	"encoding/hex"
	"fmt"
	"strings"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// canonicalAlgorithm is the one digest algorithm the content-identity surface
// produces and accepts. It matches the algorithm core's canonical digests
// (ContentDigest, the FactRecord ContentHash) already use, so identities never
// straddle two hash functions.
const canonicalAlgorithm = "sha256"

// canonicalDigestBytes is the byte length of a canonical sha256 digest.
const canonicalDigestBytes = 32

// ContentIdentityUseCase is the single source of canonical identity shared by
// signing, bundling, and integrity audit. It exposes the
// canonical digest of a record/blob and the Merkle root + inclusion proof over
// a selected set of such digests. It deliberately does not expose the internal
// *Hasher types: callers receive identities, never the hashing
// machinery, so a signature or bundle can never drift from core's digest.
//
// The use case is pure and stateless; construct one with
// NewContentIdentityUseCase and call its methods directly.
type ContentIdentityUseCase struct{}

// NewContentIdentityUseCase constructs the content-identity use case.
func NewContentIdentityUseCase() *ContentIdentityUseCase {
	return &ContentIdentityUseCase{}
}

// InclusionProof is the published shape of a Merkle inclusion proof: the
// audit-path digests that, combined bottom-up with a leaf, reconstruct the
// root. Index and Size pin the proven leaf's position in the ordered set so a
// proof cannot be replayed at a different position. The sibling hashes are
// expressed as SubjectDigests, the same canonical-identity type used
// everywhere else on this surface.
type InclusionProof struct {
	// Index is the zero-based position of the proven member in the ordered set.
	Index int
	// Size is the number of members in the set the proof was built over.
	Size int
	// Siblings are the audit-path digests, ordered from the leaf level upward.
	Siblings []ports.SubjectDigest
}

// CanonicalDigest returns the canonical SubjectDigest of raw record/blob bytes.
// Raw bytes have exactly one digest, so this introduces no canonicalisation
// choice and matches the content-address the blob store and the fetch signing
// call sites derive — the digest a Signer attests over.
func (uc *ContentIdentityUseCase) CanonicalDigest(data []byte) ports.SubjectDigest {
	algorithm, hexDigest, _ := strings.Cut(domain2.ContentDigest(data), ":")
	return ports.SubjectDigest{Algorithm: algorithm, Hex: hexDigest}
}

// MerkleRoot returns the canonical digest committing to the ordered set of
// member digests. Order is significant. It errors when the set is empty (an
// empty set has no canonical root) or when any member is not a well-formed
// canonical digest.
func (uc *ContentIdentityUseCase) MerkleRoot(members []ports.SubjectDigest) (ports.SubjectDigest, error) {
	leaves, err := decodeMembers(members)
	if err != nil {
		return ports.SubjectDigest{}, err
	}
	root, err := domain2.MerkleRoot(leaves)
	if err != nil {
		return ports.SubjectDigest{}, fmt.Errorf("computing merkle root: %w", err)
	}
	return digestFromBytes(root), nil
}

// InclusionProof returns the proof that the member at index belongs to the
// ordered set committed by MerkleRoot. It errors when the set is empty, index
// is out of range, or any member is malformed.
func (uc *ContentIdentityUseCase) InclusionProof(members []ports.SubjectDigest, index int) (InclusionProof, error) {
	leaves, err := decodeMembers(members)
	if err != nil {
		return InclusionProof{}, err
	}
	proof, err := domain2.BuildMerkleProof(leaves, index)
	if err != nil {
		return InclusionProof{}, fmt.Errorf("building inclusion proof: %w", err)
	}
	siblings := make([]ports.SubjectDigest, len(proof.Siblings))
	for i, s := range proof.Siblings {
		siblings[i] = digestFromBytes(s)
	}
	return InclusionProof{Index: proof.Index, Size: proof.Size, Siblings: siblings}, nil
}

// VerifyInclusion reports whether proof links the member digest to root. It
// returns false on any malformed digest or structural mismatch, so a caller can
// treat false as "not proven" without inspecting an error.
func (uc *ContentIdentityUseCase) VerifyInclusion(member ports.SubjectDigest, proof InclusionProof, root ports.SubjectDigest) bool {
	entry, err := decodeDigest(member)
	if err != nil {
		return false
	}
	rootBytes, err := decodeDigest(root)
	if err != nil {
		return false
	}
	siblings := make([][]byte, len(proof.Siblings))
	for i, s := range proof.Siblings {
		b, err := decodeDigest(s)
		if err != nil {
			return false
		}
		siblings[i] = b
	}
	return domain2.VerifyMerkleProof(entry, domain2.MerkleProof{
		Index:    proof.Index,
		Size:     proof.Size,
		Siblings: siblings,
	}, rootBytes)
}

// decodeMembers validates and hex-decodes a set of canonical digests into raw
// leaf bytes, preserving order.
func decodeMembers(members []ports.SubjectDigest) ([][]byte, error) {
	leaves := make([][]byte, len(members))
	for i, m := range members {
		b, err := decodeDigest(m)
		if err != nil {
			return nil, fmt.Errorf("member %d: %w", i, err)
		}
		leaves[i] = b
	}
	return leaves, nil
}

// decodeDigest validates a SubjectDigest and returns its raw bytes. It enforces
// the single canonical algorithm and the fixed digest length so a malformed
// identity cannot silently enter a tree.
func decodeDigest(d ports.SubjectDigest) ([]byte, error) {
	if d.Algorithm != canonicalAlgorithm {
		return nil, fmt.Errorf("unsupported digest algorithm %q, want %q", d.Algorithm, canonicalAlgorithm)
	}
	b, err := hex.DecodeString(d.Hex)
	if err != nil {
		return nil, fmt.Errorf("decoding digest hex: %w", err)
	}
	if len(b) != canonicalDigestBytes {
		return nil, fmt.Errorf("digest length %d bytes, want %d", len(b), canonicalDigestBytes)
	}
	return b, nil
}

// digestFromBytes wraps raw digest bytes as a canonical SubjectDigest.
func digestFromBytes(b []byte) ports.SubjectDigest {
	return ports.SubjectDigest{Algorithm: canonicalAlgorithm, Hex: hex.EncodeToString(b)}
}
