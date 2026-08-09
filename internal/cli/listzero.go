package cli

import (
	"encoding/json"
	"fmt"
	"io"
)

// listZeroScope is everything a listing knows about a zero result: the filter it
// applied, what that value was compared against, how many records there were to
// compare it with, and the invocations that would change the answer.
//
// A bare "no records found" collapses three different facts into one line — the
// store holds nothing, the filter matched nothing, or paging skipped past the
// end — and they have different remedies. The reader cannot tell which they are
// looking at, and the cheapest way to find out is to guess and re-run. This is
// the same statement the --node filter notice makes on callgraph-show, in the
// shape a record listing needs: summaries rather than nodes, and a filter that
// may be a positional rather than a flag.
type listZeroScope struct {
	// subject names one record in the listing's corpus, singular: "call graph
	// record", "scan run". Every sentence below is built around it.
	subject string
	// subjectPlural is the plural of subject, for the listings whose corpus is
	// named rather than counted — "directive scans for example.com/proj" cannot
	// be pluralised by appending "(s)" to the project path. Empty means the
	// default "<subject>(s)", which is what every listing whose subject is a
	// bare noun uses.
	subjectPlural string
	// filterName names the filter in the reader's terms — "module path", "walk
	// id" — and filterValue is what they gave. Empty filterValue means the
	// listing was unfiltered, and the zero is about the store, not the filter.
	filterName  string
	filterValue string
	// field names the column the value was compared against and matchKind names
	// how, so a reader who passed a prefix of a module path learns why an
	// exact-match filter refused it rather than concluding the record is absent.
	field     string
	matchKind string
	// considered is how many records the filter was compared against: the size
	// of the listing's corpus with the filter lifted. It is what separates
	// "nothing here" from "nothing matched".
	considered int
	// example is one value from that corpus, in the shape the filter compares
	// against. Empty when the corpus is empty — there is nothing to illustrate,
	// and inventing one would teach a spelling the store cannot confirm.
	example string
	// produce and listAll are invocations this CLI's own parser accepts: one
	// that would create a record, one that would list the corpus unfiltered.
	produce string
	listAll string
	// pagedPast is set when --offset, not the filter, emptied the page; it
	// carries the clause naming the paging that did it.
	pagedPast string
	// keepProduce carries both remedies on a miss over a non-empty corpus,
	// instead of only the one that lists it. It is for the selectors whose flat
	// negative already told the caller how to produce the record they asked for:
	// dropping that to make room for the corpus statement would trade one half
	// of the answer for the other, and a caller whose module has simply never
	// been walked needs the produce invocation whether or not other modules have.
	keepProduce bool
}

// storeEmpty reports the case whose remedy is "produce a record", as opposed to
// "check the filter".
func (s listZeroScope) storeEmpty() bool { return s.considered == 0 }

// plural renders the subject in the plural the counting sentences need.
func (s listZeroScope) plural() string {
	if s.subjectPlural != "" {
		return s.subjectPlural
	}
	return s.subject + "(s)"
}

// writeListZeroNotice states a zero-result listing's own scope on the text path.
//
// It is only ever reached with an empty result, so the extra store read that
// fills `considered` is paid exactly when the alternative is a line the reader
// cannot act on, and never on a listing that returned rows.
func writeListZeroNotice(stdout io.Writer, s listZeroScope) error {
	line, remedyLabel, remedy := listZeroStatement(s)
	if _, err := fmt.Fprintf(stdout, "%s\n  %s: %s\n", line, remedyLabel, remedy); err != nil {
		return fmt.Errorf("writing zero-result notice: %w", err)
	}
	return nil
}

// listZeroLine is the same statement on one line, for the surfaces whose zero
// is an error rather than an empty page: a single-record selector that matched
// nothing returns a non-zero exit, and the message it carries is the only place
// it can say what it searched. Sharing the wording with the listings is the
// point — a reader who has seen one has seen both.
func listZeroLine(s listZeroScope) string {
	line, remedyLabel, remedy := listZeroStatement(s)
	out := fmt.Sprintf("%s; %s: %s", line, remedyLabel, remedy)
	// The store-empty statement already offers the produce invocation, so adding
	// it again would print the same remedy twice.
	if s.keepProduce && !s.storeEmpty() {
		out += fmt.Sprintf("; to produce one: %s", s.produce)
	}
	return out
}

// listZeroStatement renders the prose halves of the notice: what was looked at,
// and the invocation that changes the answer.
func listZeroStatement(s listZeroScope) (line, remedyLabel, remedy string) {
	switch {
	case s.pagedPast != "":
		line = fmt.Sprintf("no %s on this page — the store holds %d %s, and %s",
			s.subject, s.considered, s.plural(), s.pagedPast)
		remedyLabel, remedy = "to list from the start", s.listAll
	case s.storeEmpty() && s.filterValue == "":
		line = fmt.Sprintf("the store holds no %s at all", s.subject)
		remedyLabel, remedy = "to produce one", s.produce
	case s.storeEmpty():
		line = fmt.Sprintf("the store holds no %s at all, so %s %q is not what made this empty",
			s.subject, s.filterName, s.filterValue)
		remedyLabel, remedy = "to produce one", s.produce
	case s.filterValue != "":
		line = fmt.Sprintf("no %s matched %s %q — the value is compared %s against the %s of all %d %s in the store",
			s.subject, s.filterName, s.filterValue, s.matchKind, s.field, s.considered, s.plural())
		if s.example != "" {
			line += fmt.Sprintf(" (e.g. %s)", s.example)
		}
		remedyLabel, remedy = fmt.Sprintf("to list every %s", s.subject), s.listAll
	default:
		// An unfiltered listing that returned nothing over a non-empty corpus.
		// Nothing in this command explains it, so the line says exactly that
		// rather than borrowing one of the explanations above.
		line = fmt.Sprintf("no %s was returned, though the store holds %d %s",
			s.subject, s.considered, s.plural())
		remedyLabel, remedy = fmt.Sprintf("to list every %s", s.subject), s.listAll
	}
	return line, remedyLabel, remedy
}

// listZeroFilterJSON carries the filter half of the statement.
type listZeroFilterJSON struct {
	Name            string `json:"name"`
	Value           string `json:"value"`
	ComparedAgainst string `json:"compared_against"`
	Match           string `json:"match"`
}

// listZeroJSON is the machine-readable form of the same statement.
type listZeroJSON struct {
	Subject           string              `json:"subject"`
	Filter            *listZeroFilterJSON `json:"filter,omitempty"`
	RecordsConsidered int                 `json:"records_considered"`
	StoreEmpty        bool                `json:"store_empty"`
	PagedPast         bool                `json:"paged_past"`
	Remedy            []string            `json:"remedy"`
}

// writeListZeroNoticeJSON states the same scope for a machine reader.
//
// It goes to stderr, and stdout keeps emitting the empty array unchanged: the
// data channel's type must not depend on how many rows came back, or every
// consumer has to branch on it. A caller who wants the distinction reads the
// object on stderr; one who does not is entirely unaffected.
func writeListZeroNoticeJSON(stderr io.Writer, s listZeroScope) error {
	out := listZeroJSON{
		Subject:           s.subject,
		RecordsConsidered: s.considered,
		StoreEmpty:        s.storeEmpty(),
		PagedPast:         s.pagedPast != "",
		Remedy:            []string{s.listAll},
	}
	if s.storeEmpty() {
		out.Remedy = []string{s.produce}
	} else if s.keepProduce {
		out.Remedy = []string{s.listAll, s.produce}
	}
	if s.filterValue != "" {
		out.Filter = &listZeroFilterJSON{
			Name:            s.filterName,
			Value:           s.filterValue,
			ComparedAgainst: s.field,
			Match:           s.matchKind,
		}
	}
	enc := json.NewEncoder(stderr)
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("encoding zero-result notice: %w", err)
	}
	return nil
}

// matchExact and matchSubstring phrase how a filter compares. Every listing
// filter that reaches SQL is equality on one indexed column, not a substring or
// prefix test; a reader who passed "github.com/spf13" and got nothing back needs
// to know that before they conclude the record is missing.
const (
	matchExact     = "for exact equality"
	matchSubstring = "as a case-insensitive substring"
	// matchLowerBound phrases a range filter: --since keeps every record at or
	// after an instant rather than one that equals it, and a reader told their
	// value was compared "for exact equality" would go and check a timestamp
	// that was never required to match.
	matchLowerBound = "as a lower bound"
)
