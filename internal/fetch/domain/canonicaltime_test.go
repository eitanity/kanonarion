package domain_test

import (
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

var timeCoord = coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}

// A record measured at a whole second hashes exactly as it always did.
//
// This is what lets sub-second measurement land without rehashing anything.
// Every record written before it existed came from a pipeline that truncated to
// seconds, so every one of them takes the whole-second branch and its stored
// content hash still recomputes. The maintainer's store holds 6629 such records;
// a canonical encoding that widened unconditionally would invalidate all of them
// at once.
func TestCanonicalTime_WholeSecondRecordHashesUnchanged(t *testing.T) {
	// The exact bytes a pre-sub-second pipeline produced, hashed by hand.
	at := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	rec := fetchtest.Record(t,
		fetchtest.Coordinate(timeCoord),
		fetchtest.ModuleHash(fetchtest.H1("zip==")),
		fetchtest.FetchedAt(at),
	)
	if err := domain.VerifyFactRecord(rec); err != nil {
		t.Fatalf("a whole-second record does not verify: %v", err)
	}

	// Its canonical bytes must still carry the second-precision encoding.
	b, err := (domain.CanonicalHasher{}).Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `"fetched_at":"2026-01-01T12:00:00Z"`; !contains(string(b), want) {
		t.Errorf("canonical bytes do not carry %s; every existing record would fail its integrity check", want)
	}
}

// A sub-second measurement carries its nanoseconds into the hash, so two
// measurements within one second are distinguishable — which is the forensic
// question a second-precision timestamp cannot answer.
func TestCanonicalTime_SubSecondMeasurementIsHashedAtFullPrecision(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	first := fetchtest.Record(t,
		fetchtest.Coordinate(timeCoord),
		fetchtest.ModuleHash(fetchtest.H1("zip==")),
		fetchtest.FetchedAt(base.Add(1)),
	)
	second := fetchtest.Record(t,
		fetchtest.Coordinate(timeCoord),
		fetchtest.ModuleHash(fetchtest.H1("zip==")),
		fetchtest.FetchedAt(base.Add(2)),
	)

	if first.ContentHash == second.ContentHash {
		t.Error("two measurements one nanosecond apart share a content hash; they are indistinguishable in the ledger")
	}
	for _, r := range []domain.FactRecord{first, second} {
		if err := domain.VerifyFactRecord(r); err != nil {
			t.Errorf("a sub-second record does not verify: %v", err)
		}
	}

	b, err := (domain.CanonicalHasher{}).Marshal(first)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `"fetched_at":"2026-01-01T12:00:00.000000001Z"`; !contains(string(b), want) {
		t.Errorf("canonical bytes do not carry %s; the sub-second measurement was truncated", want)
	}
}

// The encoding is FIXED WIDTH, so it is usable as a sort key. time.RFC3339Nano
// strips trailing zeros, which would put a whole-second value AFTER a fractional
// one in the same second and reverse the ledger's own sequence.
func TestCanonicalTime_SubSecondEncodingIsFixedWidthAndSortsChronologically(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	var prev string
	for _, d := range []time.Duration{
		1 * time.Nanosecond,
		123456789 * time.Nanosecond,
		500 * time.Millisecond,
		999999999 * time.Nanosecond,
	} {
		got := base.Add(d).UTC().Format(domain.CanonicalTimeFormat)
		if len(got) != len("2026-01-01T12:00:00.000000000Z") {
			t.Errorf("encoding %q is %d chars, want fixed width; a variable-width fraction cannot sort", got, len(got))
		}
		if got <= prev {
			t.Errorf("%q does not sort after %q; lexicographic order must match chronological order", got, prev)
		}
		prev = got
	}
}

// Verification recomputes the same encoding it was written with, because the
// precision follows the VALUE rather than a schema version. There is therefore
// no second decoder to choose between and no way to read a record through the
// wrong one.
func TestCanonicalTime_VerificationIsSelfDescribing(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		at   time.Time
	}{
		{"whole second", base},
		{"one nanosecond", base.Add(1)},
		{"half a second", base.Add(500 * time.Millisecond)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := fetchtest.Record(t,
				fetchtest.Coordinate(timeCoord),
				fetchtest.ModuleHash(fetchtest.H1("zip==")),
				fetchtest.FetchedAt(tc.at),
			)
			if err := domain.VerifyFactRecord(rec); err != nil {
				t.Errorf("record does not verify: %v", err)
			}
			// And a round trip through the canonical form preserves the instant.
			b, err := (domain.CanonicalHasher{}).Marshal(rec)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			back, err := (domain.CanonicalHasher{}).Unmarshal(b)
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if !back.FetchedAt.Equal(tc.at) {
				t.Errorf("round trip changed the instant: %v -> %v", tc.at, back.FetchedAt)
			}
		})
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
