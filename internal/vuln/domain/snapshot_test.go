package domain_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// TestNewDatabaseSnapshot_RefusesAnUnnamedPin pins the invariant the type
// exists for: a snapshot that names neither its database nor its generation
// identifies nothing, and every record keyed on one composes into a single
// bucket.
func TestNewDatabaseSnapshot_RefusesAnUnnamedPin(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, source, version string }{
		{"neither part", "", ""},
		{"no source", "", "v2026-07-24"},
		{"no version", "vuln.go.dev", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := domain.NewDatabaseSnapshot(tc.source, tc.version, time.Now(), "")
			if !errors.Is(err, domain.ErrZeroSnapshot) {
				t.Fatalf("NewDatabaseSnapshot(%q, %q) error = %v, want %v", tc.source, tc.version, err, domain.ErrZeroSnapshot)
			}
		})
	}
}

// TestNewDatabaseSnapshot_RefusesAHashNoReaderCanRecompute covers the seal. A
// content hash spelled some other way is not evidence about any bytes: the read
// leg recomputes HashSnapshotContent and compares, so a hash it can never equal
// would make the snapshot permanently unverifiable while claiming to be sealed.
func TestNewDatabaseSnapshot_RefusesAHashNoReaderCanRecompute(t *testing.T) {
	t.Parallel()

	good := domain.HashSnapshotContent([]byte("advisories"))
	for _, tc := range []struct{ name, hash string }{
		{"no algorithm prefix", good[len("sha256:"):]},
		{"wrong length", "sha256:abc123"},
		{"not hex", "sha256:" + "zz" + good[len("sha256:")+2:]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := domain.NewDatabaseSnapshot("vuln.go.dev", "v1", time.Time{}, tc.hash); err == nil {
				t.Fatalf("NewDatabaseSnapshot(hash %q) = nil error, want a refusal", tc.hash)
			}
		})
	}
	if _, err := domain.NewDatabaseSnapshot("vuln.go.dev", "v1", time.Time{}, good); err != nil {
		t.Fatalf("NewDatabaseSnapshot(well-formed hash) = %v, want nil", err)
	}
}

// TestNewDatabaseSnapshot_AcceptsAnUnsealedSnapshot is the asymmetry this
// conversion turns on: an empty content hash is legitimate, because rows written
// before the hash existed carry one and an un-migrated store still holds them.
// Refusing it here would make every such store unreadable rather than merely
// unproven.
func TestNewDatabaseSnapshot_AcceptsAnUnsealedSnapshot(t *testing.T) {
	t.Parallel()

	s, err := domain.NewDatabaseSnapshot("vuln.go.dev", "v1", time.Time{}, "")
	if err != nil {
		t.Fatalf("NewDatabaseSnapshot(no hash) = %v, want nil", err)
	}
	if s.IsZero() {
		t.Fatal("an unsealed snapshot reports IsZero; the empty hash is absence of a seal, not absence of a pin")
	}
	if s.ContentHash() != "" {
		t.Fatalf("ContentHash() = %q, want the empty string", s.ContentHash())
	}
}

// TestDatabaseSnapshot_RetrievedAtIsCanonicalUTC pins the normalisation: two
// snapshots of one pin must not differ by a clock reading that describes this
// process rather than the fetch.
func TestDatabaseSnapshot_RetrievedAtIsCanonicalUTC(t *testing.T) {
	t.Parallel()

	zone := time.FixedZone("UTC+7", 7*60*60)
	instant := time.Date(2026, 7, 24, 18, 35, 55, 0, zone)

	s := vulntest.MustNewAt("vuln.go.dev", "v1", instant)
	if got := s.RetrievedAt().Location(); got != time.UTC {
		t.Errorf("RetrievedAt().Location() = %v, want UTC", got)
	}
	if !s.RetrievedAt().Equal(instant) {
		t.Errorf("RetrievedAt() = %v, want the same instant as %v", s.RetrievedAt(), instant)
	}
	if !s.Equal(vulntest.MustNewAt("vuln.go.dev", "v1", instant.UTC())) {
		t.Error("the same instant read in two locations produced unequal snapshots")
	}
}

// TestParseDatabaseSnapshot_RoundTripsString pins that Parse reads exactly what
// String emits, all four parts included — the terms ParseArtefactIdentity set.
func TestParseDatabaseSnapshot_RoundTripsString(t *testing.T) {
	t.Parallel()

	for _, want := range []domain.DatabaseSnapshot{
		vulntest.MustNew("vuln.go.dev", "v2026-07-24"),
		vulntest.MustNewAt("vuln.go.dev", "2026-07-24T18:35:55Z", time.Date(2026, 7, 24, 18, 40, 0, 0, time.UTC)),
		vulntest.MustSealOver("vuln.go.dev", "v1", time.Date(2026, 7, 24, 18, 40, 0, 123, time.UTC), []byte("advisories")),
	} {
		got, err := domain.ParseDatabaseSnapshot(want.String())
		if err != nil {
			t.Fatalf("ParseDatabaseSnapshot(%q): %v", want.String(), err)
		}
		if !got.Equal(want) {
			t.Errorf("ParseDatabaseSnapshot(%q) = %v, want %v", want.String(), got, want)
		}
	}
}

// TestParseDatabaseSnapshot_FailsClosed pins that a value which cannot be read
// is an error rather than a zero snapshot: mistaking the first for the second is
// how a corrupt column becomes a silently absent one. The empty string — the
// zero snapshot's own spelling — is refused with the sentinel a store refuses it
// with on the way in.
func TestParseDatabaseSnapshot_FailsClosed(t *testing.T) {
	t.Parallel()

	if _, err := domain.ParseDatabaseSnapshot(""); !errors.Is(err, domain.ErrZeroSnapshot) {
		t.Errorf("ParseDatabaseSnapshot(%q) error = %v, want %v", "", err, domain.ErrZeroSnapshot)
	}
	for _, input := range []string{
		"vuln.go.dev",
		"vuln.go.dev@v1",
		"vuln.go.dev@v1@2026-07-24T18:40:00Z",
		"vuln.go.dev@v1@not-a-time@",
		"vuln.go.dev@v1@2026-07-24T18:40:00Z@sha256:short",
		"@v1@2026-07-24T18:40:00Z@",
	} {
		if _, err := domain.ParseDatabaseSnapshot(input); err == nil {
			t.Errorf("ParseDatabaseSnapshot(%q) = nil error, want a refusal", input)
		}
	}
}

// TestNewDatabaseSnapshot_RefusesASeparatorInEitherPart pins what keeps String
// round-trippable: a source or version containing the separator would split into
// the wrong number of parts and read back as a different snapshot, or not at all.
func TestNewDatabaseSnapshot_RefusesASeparatorInEitherPart(t *testing.T) {
	t.Parallel()

	if _, err := domain.NewDatabaseSnapshot("vuln.go.dev@mirror", "v1", time.Time{}, ""); err == nil {
		t.Error("NewDatabaseSnapshot(source with a separator) = nil error, want a refusal")
	}
	if _, err := domain.NewDatabaseSnapshot("vuln.go.dev", "v1@2", time.Time{}, ""); err == nil {
		t.Error("NewDatabaseSnapshot(version with a separator) = nil error, want a refusal")
	}
}

// TestDatabaseSnapshot_WithContentHash pins the store's sealing path: the store
// is the authority on the bytes it holds, so it seals the caller's snapshot
// against what it actually wrote. Sealing a value that names nothing is refused
// — it would produce a verifiable claim about no database at all.
func TestDatabaseSnapshot_WithContentHash(t *testing.T) {
	t.Parallel()

	want := domain.HashSnapshotContent([]byte("advisories"))
	sealed, err := vulntest.MustNew("vuln.go.dev", "v1").WithContentHash(want)
	if err != nil {
		t.Fatalf("WithContentHash: %v", err)
	}
	if sealed.ContentHash() != want {
		t.Errorf("ContentHash() = %q, want %q", sealed.ContentHash(), want)
	}
	if _, err := (domain.DatabaseSnapshot{}).WithContentHash(want); !errors.Is(err, domain.ErrZeroSnapshot) {
		t.Errorf("DatabaseSnapshot{}.WithContentHash() error = %v, want %v", err, domain.ErrZeroSnapshot)
	}
}

// TestDatabaseSnapshot_IsZero pins that both parts are required to name
// something, and that the seal has no say in it.
func TestDatabaseSnapshot_IsZero(t *testing.T) {
	t.Parallel()

	if !(domain.DatabaseSnapshot{}).IsZero() {
		t.Error("the zero snapshot does not report IsZero")
	}
	if vulntest.MustNew("vuln.go.dev", "v1").IsZero() {
		t.Error("a named snapshot reports IsZero")
	}
}

// snapshotWireForm is the exact object DatabaseSnapshot serialised to while its
// fields were exported. It is written out here rather than derived, because
// deriving it from the type under test would pin nothing.
const snapshotWireForm = `{"source":"vuln.go.dev","version":"2026-07-24T18:35:55Z","retrieved_at":"2026-07-24T18:40:00Z","content_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}`

// TestDatabaseSnapshot_WireFormIsUnchanged is the regression guard on the whole
// conversion.
//
// The snapshot is a named field on VulnerabilityRecord and on WalkScanRun, both
// of which are sealed by hashing their own JSON encoding. Unexporting the fields
// without a marshaller would have narrowed every one of those encodings to
// "database_snapshot":{} — silently, at write time, and fatally at read time for
// every record already stored. This pins the object form, key order included.
func TestDatabaseSnapshot_WireFormIsUnchanged(t *testing.T) {
	t.Parallel()

	s := vulntest.MustSeal(
		"vuln.go.dev",
		"2026-07-24T18:35:55Z",
		time.Date(2026, 7, 24, 18, 40, 0, 0, time.UTC),
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
	)
	got, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(got) != snapshotWireForm {
		t.Fatalf("the persisted shape changed:\n got %s\nwant %s", got, snapshotWireForm)
	}
}

// TestDatabaseSnapshot_UnmarshalRoundTripsStoredBytesVerbatim pins the read leg
// of the same rule, and the reason UnmarshalJSON neither validates nor
// normalises: a record's content hash is computed over its own JSON encoding, so
// re-marshalling a value the reader had normalised would fail the verification
// of a record nothing had tampered with.
//
// The inputs are the shapes a store actually holds and this type's rules would
// otherwise reject: a snapshot with no seal, one with a non-UTC retrieval time
// (time.Now() carried the local offset into every record written before this
// conversion), and the zero snapshot itself.
func TestDatabaseSnapshot_UnmarshalRoundTripsStoredBytesVerbatim(t *testing.T) {
	t.Parallel()

	for _, stored := range []string{
		snapshotWireForm,
		`{"source":"vuln.go.dev","version":"v1","retrieved_at":"2026-07-24T18:40:00Z","content_hash":""}`,
		`{"source":"vuln.go.dev","version":"v1","retrieved_at":"2026-07-24T19:40:00+01:00","content_hash":""}`,
		`{"source":"","version":"","retrieved_at":"0001-01-01T00:00:00Z","content_hash":""}`,
	} {
		var s domain.DatabaseSnapshot
		if err := json.Unmarshal([]byte(stored), &s); err != nil {
			t.Fatalf("Unmarshal(%s): %v", stored, err)
		}
		got, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if string(got) != stored {
			t.Errorf("a stored snapshot did not round-trip:\n got %s\nwant %s", got, stored)
		}
	}
}
