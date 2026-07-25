package domain

import (
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// SealedRecord is a FactRecord that has been shown to carry its own content
// hash. It is the only shape the fact store accepts for writing.
//
// The point is to close the window in which an unsealed record exists. Before
// SealedRecord the write path built a FactRecord, then hashed it, then persisted
// it, and every step in between held a record whose ContentHash did not describe
// its contents — a record that would have been written faithfully and verified
// happily ever after. Seal computes the hash at construction, so there is no
// such intermediate value to mislay, and Rehydrate refuses to reconstruct one
// whose stored hash disagrees with its stored fields.
//
// The wrapped record is unexported: Seal and Rehydrate are the only ways to
// obtain a SealedRecord, so possessing one is itself the evidence that the
// invariant holds. Record hands back a copy for reading; mutating that copy
// cannot invalidate the seal, because the copy is no longer sealed.
//
// The public pkg/kanonarion.FactRecord alias is deliberately untouched by this.
// It is a dumb read shape frozen by the v0 contract; enforcement belongs on the
// write side, which is where SealedRecord sits.
type SealedRecord struct {
	record FactRecord
}

// Seal builds the fact record for a fetched module and computes its content
// hash in one step, returning a record that is sealed from the moment it exists.
func Seal(m FetchedModule) (SealedRecord, error) {
	hashed, err := (CanonicalHasher{}).SetContentHash(NewFactRecord(m))
	if err != nil {
		return SealedRecord{}, fmt.Errorf("sealing fact record for %s: %w", m.Coordinate, err)
	}
	return SealedRecord{record: hashed}, nil
}

// Rehydrate reconstructs a SealedRecord from persisted fields, verifying every
// integrity invariant first and failing closed.
//
// It fails rather than reporting absence. A record whose stored hash disagrees
// with its stored fields is a detected tamper, and reporting a detected tamper
// as "no record here" turns the loudest signal the store can produce into a
// silent cache miss followed by a re-fetch that overwrites the evidence.
func Rehydrate(r FactRecord) (SealedRecord, error) {
	if err := VerifyFactRecord(r); err != nil {
		return SealedRecord{}, fmt.Errorf("rehydrating fact record for %s: %w", r.Coordinate(), err)
	}
	return SealedRecord{record: r}, nil
}

// Record returns a copy of the sealed fact record for reading.
func (s SealedRecord) Record() FactRecord { return s.record }

// ContentHash returns the sealed record's self-hash.
func (s SealedRecord) ContentHash() string { return s.record.ContentHash }

// Coordinate returns the module coordinate the sealed record describes.
func (s SealedRecord) Coordinate() coordinate.ModuleCoordinate { return s.record.Coordinate() }

// ArtefactIdentity returns the identity of the artefact the sealed record
// describes. The record's hashes have already been shown to be covered by its
// content hash, so a parse failure here is a malformed hash rather than a
// tampered one.
func (s SealedRecord) ArtefactIdentity() (ArtefactIdentity, error) {
	return ArtefactIdentityOf(s.record)
}

// IsZero reports whether this is the zero SealedRecord, which seals nothing.
func (s SealedRecord) IsZero() bool { return s.record.ContentHash == "" }
