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
	// limit is the cap that was applied. Zero means none was: the text path then
	// states nothing, having no scope to declare, while the document still says
	// so — a consumer reads the same fields at every limit.
	limit int
	// subject names the listing's rows in the plural — "license records", "scan
	// runs" — so the line reads in the reader's terms rather than the port's.
	subject string
	// truncated is true when the store held at least one record beyond the
	// limit. It is measured, never assumed: a listing holding exactly its limit
	// and nothing more must not claim to have withheld anything.
	truncated bool
	// offset is how many records the caller skipped to reach this page. It is
	// carried so the statement can name the NEXT page and not only the whole
	// population: a reader told "more exist" and offered --limit 0 alone must
	// choose between this page and all of it, which is exactly the choice paging
	// exists to remove.
	offset int
}

// applied reports whether this listing capped anything at all.
func (t listTruncation) applied() bool { return t.limit > 0 }

// nextOffset is the offset that starts the page after this one. It is only ever
// read on a truncated listing, where a further page is known to exist.
func (t listTruncation) nextOffset() int { return t.offset + t.limit }

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

// skipList applies a caller's offset to rows a port could not page itself.
//
// It exists for the two listings whose page is not the port's page: one that
// post-filters the port's rows in the CLI, and one whose port hands back its
// whole population by design. Everywhere else the offset goes to the filter, so
// the store does the skipping and the CLI never holds rows it will not print.
//
// An offset at or past the end yields no rows rather than an error: paging past
// the population is a page that is empty, and the zero-result notice says so.
func skipList[T any](rows []T, offset int) []T {
	if offset <= 0 {
		return rows
	}
	if offset >= len(rows) {
		return nil
	}
	return rows[offset:]
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
	shown := fmt.Sprintf("showing first %d %s", t.limit, t.subject)
	if t.offset > 0 {
		// A page that did not start at the beginning must not describe itself as
		// the first anything: the rows are the ones the caller asked to skip to,
		// and naming the range is what lets them be placed in the population.
		shown = fmt.Sprintf("showing %s %d-%d", t.subject, t.offset+1, t.offset+t.limit)
	}
	if _, err := fmt.Fprintf(stdout, "%s — more exist (--limit 0 for all, --offset %d for the next page)\n",
		shown, t.nextOffset()); err != nil {
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
	// Offset is the page this listing returned, and NextOffset the one after it.
	// NextOffset is stated whenever a limit applied, not only when it bit: a
	// consumer paging a listing reads the same field every time rather than
	// branching on whether the previous page happened to be full.
	Offset     int `json:"offset"`
	NextOffset int `json:"next_offset"`
}

// statement renders the cap as the machine-readable fields the listing document
// carries. It is stated whether or not the limit bit: a consumer cannot read a
// field that is not there, so an absent marker would leave it unable to tell
// "not truncated" from "this build does not say".
func (t listTruncation) statement() listTruncationJSON {
	return listTruncationJSON{
		Truncated:  t.truncated,
		Limit:      t.limit,
		Subject:    t.subject,
		Remedy:     "--limit 0",
		Offset:     t.offset,
		NextOffset: t.nextOffset(),
	}
}

// listDocumentJSON is what a listing emits on stdout under --json: the records
// and what the listing knows about the request that produced them, in one
// object.
//
// The records used to be the whole of stdout and these facts went to stderr. A
// consumer reading the data channel then could not tell a complete list from one
// that stopped at its default — it read a partial list that looked whole, which
// is a wrong answer and not a thin one. A bare array has nowhere to put a fact
// about the request, so the array became a field of a document that has.
type listDocumentJSON struct {
	// Records is the listing's rows, in the shape and order the text path prints
	// them. It is an array at every row count, including none.
	Records any `json:"records"`
	// The paging state, promoted so a consumer reads document.truncated rather
	// than a nested object, and named exactly as it was on stderr.
	listTruncationJSON
	// ZeroResult is present only on a page that returned nothing, where it says
	// which of the three zeroes this is — empty store, filter miss, or a page
	// past the end — and what invocation changes the answer.
	ZeroResult *listZeroJSON `json:"zero_result,omitempty"`
}

// writeListDocument emits a listing's whole answer on stdout.
//
// A nil slice would encode as null, so the records are normalised to an empty
// array first: the type of the field must not depend on how many rows came back,
// or every consumer has to branch on it.
func writeListDocument[T any](stdout io.Writer, records []T, t listTruncation, zero *listZeroScope) error {
	if records == nil {
		records = []T{}
	}
	doc := listDocumentJSON{Records: records, listTruncationJSON: t.statement()}
	if zero != nil {
		statement := listZeroStatementJSON(*zero)
		doc.ZeroResult = &statement
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return nil
}
