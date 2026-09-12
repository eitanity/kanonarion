package recordstamp_test

import (
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/recordstamp"
)

// The fraction is FIXED WIDTH. time.RFC3339Nano strips trailing zeros, so it
// writes one instant at whichever width its digits end at — which is what makes
// a stored stamp unsortable as text and unmatchable against a log line.
func TestFormat_FractionIsFixedWidth(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		ns   time.Duration
		want string
	}{
		{"trailing zeros are kept", 500 * time.Millisecond, "2026-01-01T12:00:00.500000000Z"},
		{"one nanosecond", 1, "2026-01-01T12:00:00.000000001Z"},
		{"a whole millisecond", 123 * time.Millisecond, "2026-01-01T12:00:00.123000000Z"},
		{"nine significant digits", 123456789, "2026-01-01T12:00:00.123456789Z"},
		{"the last nanosecond", 999999999, "2026-01-01T12:00:00.999999999Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recordstamp.Format(base.Add(tc.ns))
			if got != tc.want {
				t.Errorf("Format = %q, want %q", got, tc.want)
			}
			if trimmed := base.Add(tc.ns).UTC().Format(time.RFC3339Nano); trimmed == got && len(trimmed) != len(tc.want) {
				t.Errorf("Format matched RFC3339Nano %q; the trimming is what this encoding exists to avoid", trimmed)
			}
		})
	}
}

// A whole second encodes as it always did, which is what makes the widening
// free: every record written before sub-second measurement carries one, and its
// stored hash covers these exact bytes.
func TestFormat_WholeSecondKeepsTheLegacyEncoding(t *testing.T) {
	at := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	if got, want := recordstamp.Format(at), "2026-01-01T12:00:00Z"; got != want {
		t.Errorf("Format = %q, want %q; every record written before the widening would fail its integrity check", got, want)
	}
}

// A local time is written in UTC, so a log line and a record are directly
// comparable without converting a timezone.
func TestFormat_IsAlwaysUTC(t *testing.T) {
	zone := time.FixedZone("ACST", 9*3600+1800)
	at := time.Date(2026, 1, 1, 21, 30, 0, 467000000, zone)
	if got, want := recordstamp.Format(at), "2026-01-01T12:00:00.467000000Z"; got != want {
		t.Errorf("Format = %q, want %q", got, want)
	}
}

// Fixed width is what makes the encoding usable as a sort key: lexicographic
// order over these strings is chronological order.
func TestFormat_SortsChronologicallyWithinOneSecond(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	var prev string
	for _, d := range []time.Duration{
		1,
		123456789,
		500 * time.Millisecond,
		999999999,
	} {
		got := recordstamp.Format(base.Add(d))
		if got <= prev {
			t.Errorf("%q does not sort after %q; lexicographic order must match chronological order", got, prev)
		}
		prev = got
	}
}

// One parser reads both generations, so a widened ledger needs no second
// decoder and no way to read a row through the wrong one.
func TestParse_ReadsBothGenerations(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Time
	}{
		{"2026-01-01T12:00:00Z", time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)},
		{"2026-01-01T12:00:00.500000000Z", time.Date(2026, 1, 1, 12, 0, 0, 500000000, time.UTC)},
		{"2026-01-01T12:00:00.5Z", time.Date(2026, 1, 1, 12, 0, 0, 500000000, time.UTC)},
		{"2026-01-01T21:30:00.467+09:30", time.Date(2026, 1, 1, 12, 0, 0, 467000000, time.UTC)},
	} {
		got, err := recordstamp.Parse(tc.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", tc.in, err)
			continue
		}
		if !got.Equal(tc.want) {
			t.Errorf("Parse(%q) = %v, want %v", tc.in, got, tc.want)
		}
		if got.Location() != time.UTC {
			t.Errorf("Parse(%q) returned %v, not UTC", tc.in, got.Location())
		}
	}
}

func TestParse_RefusesAStampItCannotRead(t *testing.T) {
	if _, err := recordstamp.Parse("last tuesday"); err == nil {
		t.Fatal("Parse accepted a value that is not a timestamp")
	}
}

// The round trip is the property verification depends on: the encoding a record
// was written with is the one recomputing its hash produces.
func TestFormatParseRoundTrip(t *testing.T) {
	for _, at := range []time.Time{
		time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 12, 0, 0, 1, time.UTC),
		time.Date(2026, 1, 1, 12, 0, 0, 500000000, time.UTC),
		time.Date(2026, 1, 1, 12, 0, 0, 999999999, time.UTC),
	} {
		back, err := recordstamp.Parse(recordstamp.Format(at))
		if err != nil {
			t.Fatalf("Parse(Format(%v)): %v", at, err)
		}
		if !back.Equal(at) {
			t.Errorf("round trip changed the instant: %v -> %v", at, back)
		}
		if recordstamp.Format(back) != recordstamp.Format(at) {
			t.Errorf("round trip changed the encoding: %q -> %q", recordstamp.Format(at), recordstamp.Format(back))
		}
	}
}
