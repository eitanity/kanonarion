package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// SubjectKind names what a signature attests over. Sign-on-process produces one
// of these at each pipeline call site: the received blob, or the produced fact
// record.
type SubjectKind string

const (
	// SubjectBlob marks an attestation over a received module blob (the zip
	// bytes), signed at fetch-receive after verification.
	SubjectBlob SubjectKind = "blob"
	// SubjectFact marks an attestation over a produced FactRecord, signed at
	// the moment the fact is produced (over its canonical ContentHash).
	SubjectFact SubjectKind = "fact"
)

// AttestationRecord is an additive provenance record: a signature over a
// subject digest taken from core's canonical identity, persisted alongside the
// fact it attests without altering it. Multiple attestations may exist per
// artifact; an unconfigured (no-op) signer produces none.
//
// It records the canonical digest that was signed (algorithm + hex) rather than
// re-deriving one, so the signature can never drift from core's digest.
type AttestationRecord struct {
	Coordinate       coordinate.ModuleCoordinate
	PipelineVersion  string
	SubjectKind      SubjectKind
	SubjectAlgorithm string
	SubjectDigest    string // hex-encoded digest value
	Bundle           []byte // opaque signed attestation/bundle
	SignedAt         time.Time
}

// ContentDigest returns the canonical content digest of raw bytes in
// "sha256:<hex>" form. Raw bytes have exactly one digest, so this introduces no
// canonicalisation choice and cannot drift — it matches the content-address the
// blob store derives. Used to produce the subject digest for a received blob.
func ContentDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// AttestationRecordLess is the canonical ordering for AttestationRecord slices:
// the subject first, because that is what a reader scans an attestation list
// by, then the coordinate and the signature it carries.
//
// One subject can be attested more than once — a second signer, or the same
// signer after a key rotation — so the subject is not an identity, and a
// comparator stopping there hands the pair's order to the sort.
func AttestationRecordLess(a, b AttestationRecord) bool {
	if a.SubjectKind != b.SubjectKind {
		return a.SubjectKind < b.SubjectKind
	}
	if a.SubjectDigest != b.SubjectDigest {
		return a.SubjectDigest < b.SubjectDigest
	}
	if a.SubjectAlgorithm != b.SubjectAlgorithm {
		return a.SubjectAlgorithm < b.SubjectAlgorithm
	}
	if a.Coordinate.Path() != b.Coordinate.Path() {
		return a.Coordinate.Path() < b.Coordinate.Path()
	}
	if a.Coordinate.Version() != b.Coordinate.Version() {
		return a.Coordinate.Version() < b.Coordinate.Version()
	}
	if a.PipelineVersion != b.PipelineVersion {
		return a.PipelineVersion < b.PipelineVersion
	}
	if !a.SignedAt.Equal(b.SignedAt) {
		return a.SignedAt.Before(b.SignedAt)
	}
	return bytes.Compare(a.Bundle, b.Bundle) < 0
}

// SortAttestations orders attestation records by AttestationRecordLess, a total
// order, so any serialisation over a set is a function of the set alone.
func SortAttestations(records []AttestationRecord) {
	sort.Slice(records, func(i, j int) bool { return AttestationRecordLess(records[i], records[j]) })
}
