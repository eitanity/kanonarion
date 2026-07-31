package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrZeroSnapshot is the refusal every store owes the zero database snapshot.
// It is defined here, beside the value object, on the terms
// coordinate.ErrZeroCoordinate and fetchdomain.ErrZeroIdentity already set: one
// error in the domain so every implementation refuses alike and a caller can
// test the refusal without knowing which store answered.
//
// The zero snapshot names neither an advisory database nor a generation of one,
// so it can key nothing on a write and answers nothing on a read. It is worse
// here than for the coordinate: vulnerability_records is an append-only ledger
// whose composition group is keyed on (coordinate, pipeline version, snapshot),
// so a record admitted under the zero snapshot joins a group holding every other
// record that also named none, and a read composes them as though they described
// one measurement against one advisory database.
var ErrZeroSnapshot = errors.New("database snapshot is zero: it names no advisory database at no generation and must never reach storage")

// snapshotFieldSep separates the four parts String writes and
// ParseDatabaseSnapshot reads back. Source and version may not contain it —
// NewDatabaseSnapshot refuses one that does — so the split is unambiguous.
const snapshotFieldSep = "@"

// DatabaseSnapshot identifies a pinned snapshot of the vulnerability database.
//
// Source and Version name the advisory database and its own generation;
// RetrievedAt records when kanonarion fetched it. Those three answer "how
// current was the data behind this verdict". ContentHash answers the question
// they cannot: whether the bytes a verdict was reached against are the bytes
// still held.
//
// The advisory database is the evidence every finding is derived from, and it
// was the one input to a verdict that was not content-addressed — a snapshot
// was identified by a version string alone, and the version string is metadata
// the blob itself asserts. Two stores both holding "2026-07-24T18:35:55Z" could
// not be shown to hold the same advisories.
//
// Its fields are unexported: a snapshot is built by NewDatabaseSnapshot or read
// back from its persisted form by ParseDatabaseSnapshot, and neither can be
// short-circuited by a struct literal. This is not a read shape — it is passed
// INTO the store as a key, and it is half of what tells two scans of one module
// apart, so a half-built one keys rows on a pin that identifies nothing. Read it
// back through Source, Version, RetrievedAt, ContentHash or String.
type DatabaseSnapshot struct {
	// source names the advisory database.
	source string

	// version is that database's own generation of itself.
	version string

	// retrievedAt is when kanonarion fetched this generation, canonical UTC.
	retrievedAt time.Time

	// contentHash is HashSnapshotContent over the snapshot blob, in
	// "sha256:<hex>" form. Empty on snapshots recorded before the hash existed;
	// such a snapshot is unverifiable, never verified-and-clean.
	contentHash string

	// advisoryCount is how many advisories the extracted database was measured
	// to hold, established at extraction by whoever handed the directory to a
	// scanner. Zero means no count was ever established — it is never a measured
	// reading, because WithAdvisoryCount refuses a non-positive one and a scan
	// against an empty database is refused rather than sealed.
	advisoryCount int
}

// NewDatabaseSnapshot returns the snapshot naming source at version, retrieved
// at retrievedAt and — when it has been sealed — addressed by contentHash.
//
// Source and version are both required: a snapshot that names neither its
// database nor its pin identifies nothing, and admitting one keys every record
// that recorded no snapshot into a single composition group. Neither may contain
// the field separator, so String always round-trips through
// ParseDatabaseSnapshot.
//
// contentHash is optional. A snapshot fetched before the hash existed carries
// none and is unverifiable rather than invalid; a snapshot that carries one must
// spell it the way HashSnapshotContent does, because a hash no reader can
// recompute is not evidence of anything.
//
// retrievedAt is normalised to UTC, which also strips the monotonic reading a
// time.Now() carries, so two snapshots of the same pin cannot differ by a clock
// reading that describes this process rather than the fetch.
func NewDatabaseSnapshot(source, version string, retrievedAt time.Time, contentHash string) (DatabaseSnapshot, error) {
	if source == "" || version == "" {
		return DatabaseSnapshot{}, fmt.Errorf("building database snapshot %q@%q: %w", source, version, ErrZeroSnapshot)
	}
	if strings.Contains(source, snapshotFieldSep) || strings.Contains(version, snapshotFieldSep) {
		return DatabaseSnapshot{}, fmt.Errorf("building database snapshot %q@%q: neither part may contain %q", source, version, snapshotFieldSep)
	}
	if err := validateSnapshotContentHash(contentHash); err != nil {
		return DatabaseSnapshot{}, fmt.Errorf("building database snapshot %s@%s: %w", source, version, err)
	}
	return DatabaseSnapshot{
		source:      source,
		version:     version,
		retrievedAt: retrievedAt.UTC(),
		contentHash: contentHash,
	}, nil
}

// validateSnapshotContentHash accepts the empty hash — a snapshot older than the
// field is unsealed, not malformed — and otherwise demands the exact spelling
// HashSnapshotContent produces.
func validateSnapshotContentHash(contentHash string) error {
	if contentHash == "" {
		return nil
	}
	digits, ok := strings.CutPrefix(contentHash, snapshotHashPrefix)
	if !ok {
		return fmt.Errorf("content hash %q: want the %q prefix HashSnapshotContent writes", contentHash, snapshotHashPrefix)
	}
	if len(digits) != sha256.Size*2 {
		return fmt.Errorf("content hash %q: want %d hex digits after %q, got %d", contentHash, sha256.Size*2, snapshotHashPrefix, len(digits))
	}
	if _, err := hex.DecodeString(digits); err != nil {
		return fmt.Errorf("content hash %q is not hex: %w", contentHash, err)
	}
	return nil
}

// Source names the advisory database this snapshot was taken from.
func (s DatabaseSnapshot) Source() string { return s.source }

// Version is the advisory database's own generation of itself.
func (s DatabaseSnapshot) Version() string { return s.version }

// RetrievedAt is when kanonarion fetched this generation, in UTC.
func (s DatabaseSnapshot) RetrievedAt() time.Time { return s.retrievedAt }

// ContentHash is HashSnapshotContent over the snapshot blob, empty on a snapshot
// recorded before the hash existed.
func (s DatabaseSnapshot) ContentHash() string { return s.contentHash }

// AdvisoryCount is how many advisories this snapshot was measured to hold, and
// zero when no measurement was ever established.
//
// Zero is unambiguous rather than merely absent. A positive count is the only
// one WithAdvisoryCount admits, and a scan against a database measured at zero
// is refused rather than sealed, so no record can carry a measured zero. A zero
// therefore says "this record predates the measurement", never "this verdict was
// reached against nothing" — the two readings must not collide, because a
// pre-count record is unproven while a zero-advisory one would be false.
//
// It is deliberately not part of the snapshot's identity: it is a reading of the
// same bytes ContentHash already pins, so two snapshots that agree on the hash
// cannot disagree on the count. It is therefore absent from String, from
// ParseDatabaseSnapshot and from Equal, and no store keys a row on it.
func (s DatabaseSnapshot) AdvisoryCount() int { return s.advisoryCount }

// WithAdvisoryCount returns the snapshot carrying the advisory count measured
// from its extracted database.
//
// It is the one way a count reaches a snapshot, and it takes only a positive
// one. Zero is refused rather than stored: a stored zero is what every record
// written before this field existed already carries, so admitting a measured
// zero would make an empty database indistinguishable from an unmeasured one —
// the same collision, one layer down, that this whole measurement exists to
// close. A database measured at zero is refused as a scan input instead, where
// the count can be named in the failure rather than buried in a record.
//
// The zero snapshot is refused for the reason WithContentHash refuses it:
// stating a measurement about a value that names no database at all describes
// nothing.
func (s DatabaseSnapshot) WithAdvisoryCount(count int) (DatabaseSnapshot, error) {
	if s.IsZero() {
		return DatabaseSnapshot{}, fmt.Errorf("counting the advisories of a database snapshot: %w", ErrZeroSnapshot)
	}
	if count <= 0 {
		return DatabaseSnapshot{}, fmt.Errorf("counting the advisories of database snapshot %s: a count must be positive, got %d", s, count)
	}
	s.advisoryCount = count
	return s, nil
}

// IsZero reports whether the snapshot names no pinned generation of any advisory
// database — either part missing leaves it naming nothing, because a database
// with no generation and a generation of no database are equally unusable as a
// key. A store handed one refuses it with ErrZeroSnapshot.
//
// An empty ContentHash does NOT make a snapshot zero. Rows written before the
// hash existed legitimately carry none, and treating those as zero would make
// every un-migrated store unreadable rather than merely unproven.
func (s DatabaseSnapshot) IsZero() bool { return s.source == "" || s.version == "" }

// WithContentHash returns the snapshot sealed against contentHash.
//
// It is the one way a hash reaches a snapshot after construction, and it exists
// because the store is the authority on what it holds: PutDatabaseSnapshot
// computes the hash from the bytes being written rather than trusting the
// caller's word for them. The zero snapshot is refused rather than sealed —
// sealing a value that names nothing produces a verifiable claim about no
// database at all.
func (s DatabaseSnapshot) WithContentHash(contentHash string) (DatabaseSnapshot, error) {
	if s.IsZero() {
		return DatabaseSnapshot{}, fmt.Errorf("sealing database snapshot: %w", ErrZeroSnapshot)
	}
	if err := validateSnapshotContentHash(contentHash); err != nil {
		return DatabaseSnapshot{}, fmt.Errorf("sealing database snapshot %s: %w", s, err)
	}
	s.contentHash = contentHash
	return s, nil
}

// Equal reports whether two snapshots name the same generation of the same
// database, fetched at the same instant and sealed against the same bytes.
// RetrievedAt is compared with time.Time.Equal rather than ==, so two readings
// of one instant in different locations compare equal.
//
// AdvisoryCount is not compared: it is a reading of the bytes ContentHash
// already pins, so it can only restate what the hash decided, and comparing it
// would make a snapshot unequal to itself before it was counted.
func (s DatabaseSnapshot) Equal(other DatabaseSnapshot) bool {
	return s.source == other.source &&
		s.version == other.version &&
		s.retrievedAt.Equal(other.retrievedAt) &&
		s.contentHash == other.contentHash
}

// String renders the snapshot for keying and for logs, as all four parts joined
// by the field separator: "source@version@retrieved-at@content-hash". The zero
// snapshot's own spelling is the empty string.
//
// It carries every part rather than the readable source@version pair alone
// because ParseDatabaseSnapshot reads back exactly what String emits, on the
// terms ParseArtefactIdentity set: a rendering that drops the retrieval time and
// the seal is not the value, and a parser that invented them would hand back a
// snapshot claiming bytes nobody measured.
func (s DatabaseSnapshot) String() string {
	if s.IsZero() {
		return ""
	}
	return strings.Join([]string{
		s.source,
		s.version,
		s.retrievedAt.UTC().Format(time.RFC3339Nano),
		s.contentHash,
	}, snapshotFieldSep)
}

// ParseDatabaseSnapshot reads the form String emits back into a snapshot.
//
// It fails closed on everything else. A part count other than four, an
// unreadable retrieval time, a content hash the parser cannot recompute the
// shape of, and the empty string all produce an error rather than a zero
// snapshot, because a value that cannot be read is not evidence of a scan that
// named no database: mistaking the first for the second is how a corrupt column
// becomes a silently absent one. The zero snapshot's own spelling is the empty
// string, and reading one back is refused with ErrZeroSnapshot, the same error a
// store refuses it with on the way in.
func ParseDatabaseSnapshot(str string) (DatabaseSnapshot, error) {
	if str == "" {
		return DatabaseSnapshot{}, fmt.Errorf("parsing database snapshot %q: %w", str, ErrZeroSnapshot)
	}
	parts := strings.Split(str, snapshotFieldSep)
	if len(parts) != 4 {
		return DatabaseSnapshot{}, fmt.Errorf("invalid database snapshot %q: expected source%sversion%sretrieved-at%scontent-hash", str, snapshotFieldSep, snapshotFieldSep, snapshotFieldSep)
	}
	retrievedAt, err := time.Parse(time.RFC3339Nano, parts[2])
	if err != nil {
		return DatabaseSnapshot{}, fmt.Errorf("invalid database snapshot %q: reading the retrieval time: %w", str, err)
	}
	snapshot, err := NewDatabaseSnapshot(parts[0], parts[1], retrievedAt, parts[3])
	if err != nil {
		return DatabaseSnapshot{}, fmt.Errorf("invalid database snapshot %q: %w", str, err)
	}
	return snapshot, nil
}

// snapshotJSON is the persisted shape of a DatabaseSnapshot: the exact object
// the type serialised to while its fields were exported, field order and tags
// included.
//
// It exists because unexporting the fields would otherwise silently narrow every
// stored record to "database_snapshot":{}. The snapshot is a named field on
// VulnerabilityRecord and on WalkScanRun, and both are sealed by hashing their
// own JSON encoding, so a change to these bytes would invalidate the hash of
// every record already in every store. Keeping the object form is what makes
// this conversion hash-transparent.
//
// AdvisoryCount arrived later and carries omitzero for that reason: an unmeasured
// snapshot emits exactly the four fields it always did, so every record already
// sealed still marshals to the bytes its content hash was taken over. Only a
// snapshot that was actually counted adds a fifth key, and only records written
// after the measurement existed can carry one.
type snapshotJSON struct {
	Source        string    `json:"source"`
	Version       string    `json:"version"`
	RetrievedAt   time.Time `json:"retrieved_at"`
	ContentHash   string    `json:"content_hash"`
	AdvisoryCount int       `json:"advisory_count,omitzero"`
}

// MarshalJSON implements json.Marshaler, emitting the object form byte for byte
// as the exported fields did.
func (s DatabaseSnapshot) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(snapshotJSON{
		Source:        s.source,
		Version:       s.version,
		RetrievedAt:   s.retrievedAt,
		ContentHash:   s.contentHash,
		AdvisoryCount: s.advisoryCount,
	})
	if err != nil {
		return nil, fmt.Errorf("marshalling database snapshot %s: %w", s, err)
	}
	return b, nil
}

// UnmarshalJSON implements json.Unmarshaler.
//
// It deliberately does not validate and does not normalise. A record already in
// a store must round-trip to the bytes that were written — its content hash is
// computed over its own JSON encoding, so re-marshalling a normalised value
// would fail the verification of a record nothing had tampered with. Records
// predating the snapshot's invariants therefore read back as they are, including
// the zero snapshot, and the store's write leg is what keeps new ones out.
func (s *DatabaseSnapshot) UnmarshalJSON(data []byte) error {
	var obj snapshotJSON
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("unmarshalling database snapshot: %w", err)
	}
	s.source, s.version = obj.Source, obj.Version
	s.retrievedAt, s.contentHash = obj.RetrievedAt, obj.ContentHash
	s.advisoryCount = obj.AdvisoryCount
	return nil
}

// snapshotHashPrefix labels the digest algorithm inside DatabaseSnapshot's
// ContentHash, as contentHashPrefix does on the record's own seal. It was once
// the only labelled hash on a vulnerability record, because no snapshot hash had
// been written when the field was added and it was free to take the project's
// normal prefixed form while the record's own seal was frozen bare by the rows
// already stored. Those rows have since been re-notated and the contradiction is
// gone; the two constants stay separate because they label different digests
// over different bytes.
const snapshotHashPrefix = "sha256:"

// HashSnapshotContent renders the content hash of a vulnerability database
// snapshot blob: SHA-256 over the bytes verbatim, prefixed with the algorithm.
//
// It hashes the stored bytes rather than any parsed view of them, so the check
// covers exactly what a later scan will feed to govulncheck.
func HashSnapshotContent(blob []byte) string {
	sum := sha256.Sum256(blob)
	return snapshotHashPrefix + hex.EncodeToString(sum[:])
}
