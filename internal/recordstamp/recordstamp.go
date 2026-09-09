// Package recordstamp holds the one shape a record's timestamp takes, so that a
// log line and a stored record can be laid beside each other.
//
// Correlation is the whole point of the shape. Given a line from the assurance
// log and a record from a ledger, a reader lines them up directly — no timezone
// to convert and no precision to reconcile — which is what a forensic question
// asks of a timestamp and what four different encodings across the store could
// not answer.
//
// The encoding is UTC, with a FIXED-WIDTH nine-digit fraction. Fixed width
// matters because the ledgers persist these as TEXT and SQLite orders TEXT
// lexicographically: time.RFC3339Nano strips trailing zeros, so ".5" and
// ".500000000" are the same instant written two widths, and a variable-width
// fraction sorts by width rather than by time.
package recordstamp

import (
	"fmt"
	"time"
)

// Layout is the canonical encoding: RFC3339 in UTC with nine fractional digits.
const Layout = "2006-01-02T15:04:05.000000000Z07:00"

// Format encodes t for a ledger column, a sealed record, or a log line.
//
// A whole-second value encodes as plain RFC3339 instead, which is what makes
// the widening free. Every record written before sub-second measurement existed
// carries a whole second, and its stored content hash covers the bytes its own
// generation emitted; encoding at the precision the VALUE carries means those
// records recompute their hash unchanged, so widening needs no pipeline version
// bump, no migration and no purge. A measurement that actually carries
// nanoseconds encodes all nine of them.
//
// The precision follows the value rather than a schema version or a flag on the
// record. That is what makes verification self-describing: recomputing a
// record's hash asks only what the record says, so there is no second decoder
// to pick between and no way to read a record through the wrong one.
func Format(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond() == 0 {
		return t.Format(time.RFC3339)
	}
	return t.Format(Layout)
}

// Parse reads a stamp at either precision back into a time. RFC3339's layout
// accepts a fraction it does not mention, so one parser reads both generations.
func Parse(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}
