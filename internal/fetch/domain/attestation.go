package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"
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
	Coordinate       ModuleCoordinate
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

// SortAttestations orders attestation records deterministically by subject kind
// then subject digest, so any serialisation over a set is stable.
func SortAttestations(records []AttestationRecord) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].SubjectKind != records[j].SubjectKind {
			return records[i].SubjectKind < records[j].SubjectKind
		}
		return records[i].SubjectDigest < records[j].SubjectDigest
	})
}
