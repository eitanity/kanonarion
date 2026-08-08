package cli

import (
	"encoding/json"
	"fmt"
	"io"
)

// listTruncation is what a listing knows about its own row cap: the limit it
// applied, the records it applied it to, and whether the store held at least one
// more than it printed.
//
// A listing that stops at its default and says nothing reads as the complete
// population. Counting its rows — by a person or by an agent sizing a class from
// its JSON — then produces a confident, wrong number with nothing in the output
// to contradict it. The remedy is the same one the zero-result notice takes: the
// listing states its own scope rather than leaving the row count to speak for
// it.
//
// The statement deliberately does NOT carry a total. Knowing how many were
// withheld costs a second read the listing does not otherwise pay; knowing that
// some were withheld costs one extra row. limit+1 answers "is there more?", and
// that is the whole question a reader needs before they trust the rows in front
// of them.
type listTruncation struct {
	// limit is the cap that was applied. Zero means none was, and nothing is
	// stated on either path: an unlimited listing has no scope to declare.
	limit int
	// subject names the listing's rows in the plural — "license records", "scan
	// runs" — so the line reads in the reader's terms rather than the port's.
	subject string
	// truncated is true when the store held at least one record beyond the
	// limit. It is measured, never assumed: a listing holding exactly its limit
	// and nothing more must not claim to have withheld anything.
	truncated bool
}

// applied reports whether this listing capped anything at all.
func (t listTruncation) applied() bool { return t.limit > 0 }

// truncationFetchLimit converts a caller's limit into the number of rows the
// port is asked for: one more than will be printed, so the extra row's presence
// answers whether the limit bit.
//
// Zero passes through unchanged — an unlimited request must stay unlimited, and
// asking for "1 more than unlimited" is not a thing a filter can express.
func truncationFetchLimit(limit int) int {
	if limit <= 0 {
		return 0
	}
	return limit + 1
}

// truncateList trims an over-fetched slice back to the caller's limit and
// reports whether anything was dropped.
//
// It is written to be safe against a port that ignored the limit entirely and
// returned everything: the check is on the returned length, not on the extra row
// being exactly one.
func truncateList[T any](rows []T, limit int) ([]T, bool) {
	if limit <= 0 || len(rows) <= limit {
		return rows, false
	}
	return rows[:limit], true
}

// writeListTruncationNotice states a truncated listing's cap on the text path.
//
// It writes nothing when no limit was applied, and nothing when the limit was
// applied but did not bite. Silence therefore means "these are all of them",
// which is exactly what the reader was already assuming — the defect was that it
// meant that even when it was false.
func writeListTruncationNotice(stdout io.Writer, t listTruncation) error {
	if !t.applied() || !t.truncated {
		return nil
	}
	if _, err := fmt.Fprintf(stdout, "showing first %d %s — more exist (--limit 0 for all)\n",
		t.limit, t.subject); err != nil {
		return fmt.Errorf("writing truncation notice: %w", err)
	}
	return nil
}

// listTruncationJSON is the machine-readable form of the same statement.
type listTruncationJSON struct {
	Truncated bool   `json:"truncated"`
	Limit     int    `json:"limit"`
	Subject   string `json:"subject"`
	Remedy    string `json:"remedy"`
}

// writeListTruncationJSON states the cap for a machine reader.
//
// It goes to stderr and stdout keeps emitting the bare array unchanged, for the
// same reason the zero-result notice does: the data channel's type must not
// depend on how many rows came back, or every existing consumer has to branch on
// it. The listing payloads here are top-level arrays, so there is no envelope to
// add a field to — wrapping one would break every consumer, which is the
// opposite of what a new field was meant to avoid.
//
// Unlike the text line this is emitted whenever a limit was applied, with
// truncated true or false. A consumer cannot read a line that is not there, so
// the absence of a marker would leave it unable to distinguish "not truncated"
// from "this build does not say". A human reading the text path can.
func writeListTruncationJSON(stderr io.Writer, t listTruncation) error {
	if !t.applied() {
		return nil
	}
	enc := json.NewEncoder(stderr)
	if err := enc.Encode(listTruncationJSON{
		Truncated: t.truncated,
		Limit:     t.limit,
		Subject:   t.subject,
		Remedy:    "--limit 0",
	}); err != nil {
		return fmt.Errorf("encoding truncation notice: %w", err)
	}
	return nil
}

// writeListTruncation states the cap on whichever path the invocation selected.
// Every listing that applies a limit calls exactly this, so the six commands the
// defect was measured on and the two the sweep found cannot drift apart.
func writeListTruncation(stdout, stderr io.Writer, asJSON bool, t listTruncation) error {
	if asJSON {
		return writeListTruncationJSON(stderr, t)
	}
	return writeListTruncationNotice(stdout, t)
}
