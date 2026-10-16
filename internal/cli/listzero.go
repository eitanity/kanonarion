package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/eitanity/kanonarion/internal/versionorder"
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
	// filterValues names each value separately when one statement covers
	// several missed selectors, so two ids never read as one id with a comma.
	filterValues []string
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
	// superseded is what the census found at generations this build does not
	// serve. considered counts only the served generation, so without it a store
	// holding nothing but superseded records reads as an empty one.
	superseded listZeroSuperseded
}

// listZeroSuperseded is the half of a generation-aware listing's census that
// the served-generation filter would have hidden.
type listZeroSuperseded struct {
	gen listGeneration
	// held is the generation of every superseded record held, one entry per
	// record; matched is the subset the listing's filter keeps.
	held, matched []string
}

// splitGenerations is the census every generation-aware listing takes: one read
// with the generation filter lifted, split into the served rows the notice
// counts and the superseded ones it states. matches is the listing's own filter,
// nil when it has none. Under --all-generations every row is served.
func splitGenerations[T any](gen listGeneration, rows []T, generation func(T) string, matches func(T) bool) ([]T, listZeroSuperseded) {
	sup := listZeroSuperseded{gen: gen}
	if gen.all {
		return rows, sup
	}
	served := make([]T, 0, len(rows))
	for _, r := range rows {
		v := generation(r)
		if !gen.superseded(v) {
			served = append(served, r)
			continue
		}
		sup.held = append(sup.held, v)
		if matches == nil || matches(r) {
			sup.matched = append(sup.matched, v)
		}
	}
	return served, sup
}

// storeEmpty reports the case whose remedy is "produce a record", as opposed to
// "check the filter". A store holding only superseded records is not empty.
func (s listZeroScope) storeEmpty() bool { return s.considered == 0 && len(s.superseded.held) == 0 }

// supersededAsked is the superseded records the figure is about: those the
// filter matches when there is one, every superseded record otherwise.
func (s listZeroScope) supersededAsked() []string {
	if s.filterValue != "" {
		return s.superseded.matched
	}
	return s.superseded.held
}

// listAllGenerations is the invocation that lists the superseded records.
func (s listZeroScope) listAllGenerations() string { return s.listAll + " --all-generations" }

// quotedFilter renders the filter and its value: `run id "a"`, or
// `run ids "a" or "b"` when several values missed.
func (s listZeroScope) quotedFilter() string {
	if len(s.filterValues) < 2 {
		return fmt.Sprintf("%s %q", s.filterName, s.filterValue)
	}
	quoted := make([]string, len(s.filterValues))
	for i, v := range s.filterValues {
		quoted[i] = strconv.Quote(v)
	}
	return s.filterName + "s " + strings.Join(quoted, " or ")
}

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
	// Rows the listing's reads set aside are held, so the listing is not a zero;
	// Run names them on stderr.
	if storeSetAside.pending() {
		return nil
	}
	line, remedies := listZeroStatement(s)
	text := line + "\n"
	for _, r := range remedies {
		text += fmt.Sprintf("  %s: %s\n", r.label, r.invocation)
	}
	if _, err := io.WriteString(stdout, text); err != nil {
		return fmt.Errorf("writing zero-result notice: %w", err)
	}
	return nil
}

// writeListZeroWithGeneration is a generation-aware listing's text zero: the
// notice, then the generation line every page of the listing ends with, so an
// empty page also points at --all-generations.
func writeListZeroWithGeneration(stdout io.Writer, s listZeroScope, gen listGeneration) error {
	if err := writeListZeroNotice(stdout, s); err != nil {
		return err
	}
	return gen.writeNotice(stdout, 0, 0)
}

// listZeroRemedy is one labelled invocation the notice offers.
type listZeroRemedy struct{ label, invocation string }

// listZeroLine is the same statement on one line, for the surfaces whose zero
// is an error rather than an empty page: a single-record selector that matched
// nothing returns a non-zero exit, and the message it carries is the only place
// it can say what it searched. Sharing the wording with the listings is the
// point — a reader who has seen one has seen both.
func listZeroLine(s listZeroScope) string {
	line, remedies := listZeroStatement(s)
	out := line
	for _, r := range remedies {
		out += fmt.Sprintf("; %s: %s", r.label, r.invocation)
	}
	// The store-empty statement already offers the produce invocation, so adding
	// it again would print the same remedy twice.
	if s.keepProduce && !s.storeEmpty() {
		out += fmt.Sprintf("; to produce one: %s", s.produce)
	}
	return out
}

// listZeroStatement renders the prose halves of the notice: what was looked at,
// and the invocations that change the answer.
func listZeroStatement(s listZeroScope) (string, []listZeroRemedy) {
	one := func(line, label, invocation string) (string, []listZeroRemedy) {
		return line, []listZeroRemedy{{label, invocation}}
	}
	switch {
	case s.pagedPast != "":
		return one(fmt.Sprintf("no %s on this page — the store holds %d %s, and %s",
			s.subject, s.considered, s.plural(), s.pagedPast),
			"to list from the start", s.listAll)
	case s.considered == 0 && len(s.superseded.held) > 0:
		return supersededZeroStatement(s)
	case s.storeEmpty() && s.filterValue == "":
		return one(fmt.Sprintf("the store holds no %s at all", s.subject), "to produce one", s.produce)
	case s.storeEmpty():
		verb := "is"
		if len(s.filterValues) > 1 {
			verb = "are"
		}
		return one(fmt.Sprintf("the store holds no %s at all, so %s %s not what made this empty",
			s.subject, s.quotedFilter(), verb), "to produce one", s.produce)
	case s.filterValue != "":
		line := fmt.Sprintf("no %s matched %s — the value is compared %s against the %s of all %d %s in the store",
			s.subject, s.quotedFilter(), s.matchKind, s.field, s.considered, s.plural())
		if s.example != "" {
			line += fmt.Sprintf(" (e.g. %s)", s.example)
		}
		remedies := []listZeroRemedy{{fmt.Sprintf("to list every %s", s.subject), s.listAll}}
		if m := s.superseded.matched; len(m) > 0 {
			g := s.superseded.gen
			line += fmt.Sprintf("; %d %s matching it %s held only at a superseded %s (%s)",
				len(m), s.plural(), pluralVerb(len(m)), g.supersededNoun, strings.Join(distinctGenerations(m), ", "))
			remedies = append(remedies, listZeroRemedy{"to list them", s.listAllGenerations()})
		}
		return line, remedies
	default:
		// An unfiltered listing that returned nothing over a non-empty corpus.
		// Nothing in this command explains it, so the line says exactly that
		// rather than borrowing one of the explanations above.
		return one(fmt.Sprintf("no %s was returned, though the store holds %d %s",
			s.subject, s.considered, s.plural()),
			fmt.Sprintf("to list every %s", s.subject), s.listAll)
	}
}

// supersededZeroStatement is the zero of a store whose records, or whose
// records the filter matches, are all at a generation this build does not
// serve: the store is not empty, and the remedy is to list or re-derive them.
func supersededZeroStatement(s listZeroScope) (string, []listZeroRemedy) {
	g := s.superseded.gen
	servedAt := fmt.Sprintf("%s %s, the %s this build serves", g.at, g.served, g.servedNoun)
	var line string
	switch held, matched := s.superseded.held, s.superseded.matched; {
	case s.filterValue == "":
		line = fmt.Sprintf("none of the %d %s the store holds is at %s (held at %s)",
			len(held), s.plural(), servedAt, strings.Join(distinctGenerations(held), ", "))
	case len(matched) > 0:
		line = fmt.Sprintf("none of the %d %s matching %s that the store holds is at %s (held at %s)",
			len(matched), s.plural(), s.quotedFilter(), servedAt, strings.Join(distinctGenerations(matched), ", "))
	default:
		line = fmt.Sprintf("no %s matched %s in any generation, and none of the %d %s the store holds is at %s (held at %s)",
			s.subject, s.quotedFilter(), len(held), s.plural(), servedAt, strings.Join(distinctGenerations(held), ", "))
	}
	return line, []listZeroRemedy{
		{"to list them", s.listAllGenerations()},
		{"to " + strings.ToLower(g.redo[:1]) + g.redo[1:], g.produce},
	}
}

// pluralVerb agrees "is"/"are" with a count.
func pluralVerb(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

// distinctGenerations returns each generation once, oldest first, ordered as
// versions (lexical order puts 0.10.0 before 0.9.0). A detection generation's
// "+recipes.N" suffix is compared as text after its version.
func distinctGenerations(versions []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range versions {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, _, _ := strings.Cut(out[i], "+")
		b, _, _ := strings.Cut(out[j], "+")
		if c := versionorder.ComparePipelineVersions(a, b); c != 0 {
			return c < 0
		}
		return out[i] < out[j]
	})
	return out
}

// listZeroFilterJSON carries the filter half of the statement.
type listZeroFilterJSON struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	// Values lists each missed value when the statement covers several.
	Values          []string `json:"values,omitempty"`
	ComparedAgainst string   `json:"compared_against"`
	Match           string   `json:"match"`
}

// listZeroJSON is the machine-readable form of the same statement.
type listZeroJSON struct {
	Subject           string              `json:"subject"`
	Filter            *listZeroFilterJSON `json:"filter,omitempty"`
	RecordsConsidered int                 `json:"records_considered"`
	StoreEmpty        bool                `json:"store_empty"`
	PagedPast         bool                `json:"paged_past"`
	// Superseded counts the records held only at a generation this build does
	// not serve (those the filter matches, when there is one), and
	// SupersededGenerations names those generations. Both are always emitted,
	// null on a surface whose census takes no generation.
	Superseded            *int      `json:"superseded"`
	SupersededGenerations *[]string `json:"superseded_generations"`
	Remedy                []string  `json:"remedy"`
}

// listZeroStatementJSON renders the same scope for a machine reader. A listing
// carries it inside its document, where the empty records array is; the
// selectors below, whose zero is a not-found error and not a page, write it on
// its own.
func listZeroStatementJSON(s listZeroScope) listZeroJSON {
	out := listZeroJSON{
		Subject:           s.subject,
		RecordsConsidered: s.considered,
		StoreEmpty:        s.storeEmpty(),
		PagedPast:         s.pagedPast != "",
		Remedy:            []string{s.listAll},
	}
	if s.superseded.gen.served != "" {
		sup := s.supersededAsked()
		n := len(sup)
		out.Superseded = &n
		gens := distinctGenerations(sup)
		out.SupersededGenerations = &gens
	}
	switch {
	case s.storeEmpty():
		out.Remedy = []string{s.produce}
	case s.pagedPast == "" && s.considered == 0 && len(s.superseded.held) > 0:
		out.Remedy = []string{s.listAllGenerations(), s.superseded.gen.produce}
	case s.pagedPast == "" && s.filterValue != "" && len(s.superseded.matched) > 0:
		out.Remedy = []string{s.listAll, s.listAllGenerations()}
	case s.keepProduce:
		out.Remedy = []string{s.listAll, s.produce}
	}
	if s.filterValue != "" {
		out.Filter = &listZeroFilterJSON{
			Name:            s.filterName,
			Value:           s.filterValue,
			Values:          s.filterValues,
			ComparedAgainst: s.field,
			Match:           s.matchKind,
		}
	}
	return out
}

// writeListZeroNoticeJSON states the scope for a machine reader on stderr.
//
// It is for the surfaces whose zero is not a page of records: a selector that
// named one record and missed exits non-zero with nothing on stdout, so the
// statement has no document to travel in. A listing does NOT use this — its
// statement is a field of the document on stdout, because a consumer reading the
// data channel must be able to tell an empty answer from an unasked question.
func writeListZeroNoticeJSON(stderr io.Writer, s listZeroScope) error {
	enc := json.NewEncoder(stderr)
	if err := enc.Encode(listZeroStatementJSON(s)); err != nil {
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
