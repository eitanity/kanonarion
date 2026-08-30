package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	factsqlite "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	"github.com/eitanity/kanonarion/internal/audit"
)

// storeLedgerFlags are the query shapes the assurance log is asked in. They are
// kept in a struct and dispatched whole so every field is answerable for on the
// one path that reads them.
type storeLedgerFlags struct {
	since     string
	until     string
	module    string
	eventType string
	limit     int
	offset    int
}

// ledgerNotEmitted names the persisted record kinds that append NOTHING to the
// assurance log, stated on every reading of it.
//
// It exists because the ledger's most dangerous property is that it reads as
// complete. Silence in an append-only evidence stream looks like proof that
// nothing happened, and for these writes it is not: they happen, they are
// persisted, and the log says nothing. A reader who is not told this will draw
// the stronger conclusion, under exactly the pressure — an incident, a regulator
// — where the stronger conclusion is the expensive one.
//
// It is a measured list, not a guess: each line below was checked against the
// write site and against the vocabulary in internal/audit. It is maintained in
// the same commit as any change to what emits, on the rule the migrations
// document already states for the event table.
var ledgerNotEmitted = []string{
	"individual vulnerability record generations — a walk scan COUNTS them (vuln_scan_completed) and names each finding (vuln_finding_observed), but no event names a per-module verdict, and a Clean generation is only an increment; a single-module scan names no generation either, and appends only the advisory snapshot it acquired, if it acquired one. Enumerating generations is a store query, not a ledger query",
	"attestations — additive provenance, recorded beside a fact record and not mirrored into the log",
	"latest-version (staleness) ledger entries — resolved and written with no audit sink wired at all",
	"blob content writes — the artefact bytes themselves; fact_record_written names the blob identity, the write of the bytes appends nothing",
	"directive, GODEBUG and FIPS scans that found nothing — those events are emitted per finding, so a clean scan writes a record and appends no event",
}

// ledgerQuestions states which question each half of the log answers. The two
// are routinely confused and the confusion is silent: a derivation event dates
// when evidence was ESTABLISHED, and until a served event existed there was
// nothing at all that dated when it was last ASKED FOR.
var ledgerQuestions = []string{
	"when did we first learn X — the derivation events (fact_record_written, vuln_finding_observed, license_extracted, walk_completed, …); each dates a measurement",
	"when did we last check X — the served events (vuln_scan_served, sbom_served); each dates an asking that was answered from the store without re-measuring",
}

func newStoreLedgerCmd(stdout io.Writer) *cobra.Command {
	var f storeLedgerFlags
	cmd := &cobra.Command{
		Use: "ledger",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "List the store's append-only assurance-log events",
		Long: `List the events in the store's append-only assurance log (audit.jsonl).

Events are listed in chronological order. The ledger's own coverage window —
its first and last event — is always stated, so an empty result over a window
the log never spanned is distinguishable from a window in which nothing
happened. Lines that cannot be read are counted and named by line number; they
are never dropped and never abort the read. A reading that matched nothing says
which filter emptied it.

--module takes a module path (example.com/mod) or a coordinate
(example.com/mod@v1.2.3). A coordinate additionally requires the version, for
the events whose payload carries one; an event that names the module and no
version still matches.

--event-type accepts one of:
` + ledgerEventTypeHelp(),
		Example: `  kanonarion store ledger --since 2026-07-23T00:00:00Z --until 2026-07-24T00:00:00Z
  kanonarion store ledger --event-type vuln_finding_observed --module github.com/golang-jwt/jwt/v4 --limit 1
  kanonarion store ledger --event-type vuln_scan_served --json`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runStoreLedger(storeRoot, f, jsonOut, stdout)
		},
	}
	cmd.Flags().StringVar(&f.since, "since", "", "list only events at or after this time (RFC3339)")
	cmd.Flags().StringVar(&f.until, "until", "", "list only events at or before this time (RFC3339)")
	cmd.Flags().StringVar(&f.module, "module", "", "list only events naming this module path, or <path>@<version> to require the version too")
	cmd.Flags().StringVar(&f.eventType, "event-type", "", "list only events of this type (--help names the accepted values)")
	cmd.Flags().IntVar(&f.limit, "limit", 0, "maximum number of events to list (0 = unlimited)")
	cmd.Flags().IntVar(&f.offset, "offset", 0, "skip this many matched events")
	return cmd
}

// ledgerCoverage is the log's own window, reported on every query.
type ledgerCoverage struct {
	FirstEvent string `json:"first_event,omitempty"`
	LastEvent  string `json:"last_event,omitempty"`
	Events     int    `json:"events"`
	LinesRead  int    `json:"lines_read"`
}

// ledgerUnreadable is one line the reader could not read, with the readable
// timestamps that bracket it. A torn line carries no time of its own, so the
// bracket is the only thing that places it — and placing it is what lets a
// window say whether its own count is complete.
type ledgerUnreadable struct {
	Line   int    `json:"line"`
	Reason string `json:"reason"`
	After  string `json:"after,omitempty"`
	Before string `json:"before,omitempty"`
}

// ledgerEventResult is one listed event.
type ledgerEventResult struct {
	Line      int            `json:"line"`
	Timestamp string         `json:"timestamp"`
	EventType string         `json:"event_type"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// ledgerResult is the whole answer: what was asked, what the log covers, what
// could not be read, what matched, and what the log does not witness at all.
type ledgerResult struct {
	LedgerPath      string             `json:"ledger_path"`
	Coverage        ledgerCoverage     `json:"coverage"`
	UnreadableCount int                `json:"unreadable_count"`
	Unreadable      []ledgerUnreadable `json:"unreadable,omitempty"`
	// UnreadableInWindow is how many of those lines could fall inside the window
	// queried. When it is non-zero the matched count is a lower bound for that
	// window, which is a caveat the answer owes rather than one a reader should
	// have to derive.
	UnreadableInWindow int  `json:"unreadable_in_window"`
	Matched            int  `json:"matched"`
	Truncated          bool `json:"truncated"`
	// Skipped is how many matched events the offset stepped over. Stated
	// because Matched counts the whole window and Events carries one page of
	// it, and the difference is otherwise unattributable to either bound.
	Skipped int                 `json:"skipped"`
	Events  []ledgerEventResult `json:"events"`
	// ZeroReasons is stated only on a reading that matched nothing: which of the
	// filters emptied it, and what its value was compared against. A confident
	// zero that names no cause is the one answer this command must not give.
	ZeroReasons  []string `json:"zero_reasons,omitempty"`
	NotWitnessed []string `json:"not_witnessed"`
	Questions    []string `json:"questions_answered"`
}

func runStoreLedger(root string, f storeLedgerFlags, asJSON bool, stdout io.Writer) error {
	since, err := parseLedgerTime("--since", f.since)
	if err != nil {
		return err
	}
	until, err := parseLedgerTime("--until", f.until)
	if err != nil {
		return err
	}
	if !since.IsZero() && !until.IsZero() && until.Before(since) {
		return &exitError{code: ExitConfig, msg: fmt.Sprintf("--until %s is before --since %s", f.until, f.since)}
	}
	if f.limit < 0 {
		return &exitError{code: ExitConfig, msg: fmt.Sprintf("--limit must not be negative, got %d", f.limit)}
	}
	if f.offset < 0 {
		return &exitError{code: ExitConfig, msg: fmt.Sprintf("--offset must not be negative, got %d", f.offset)}
	}

	mod, err := parseLedgerModule(f.module)
	if err != nil {
		return err
	}

	path := factsqlite.AuditLogPath(root)
	led, err := factsqlite.ReadLedger(path)
	if err != nil {
		return fmt.Errorf("reading the assurance log: %w", err)
	}
	// Validated against the log in hand as well as against the vocabulary, so a
	// type this build no longer declares is still queryable in a log written by
	// one that did.
	if err := validateLedgerEventType(f.eventType, led); err != nil {
		return err
	}

	first, last := led.Coverage()
	result := ledgerResult{
		LedgerPath: path,
		Coverage: ledgerCoverage{
			FirstEvent: formatLedgerTime(first),
			LastEvent:  formatLedgerTime(last),
			Events:     len(led.Entries),
			LinesRead:  led.LinesRead,
		},
		UnreadableCount:    len(led.Faults),
		UnreadableInWindow: len(led.FaultsWithin(since, until)),
		NotWitnessed:       ledgerNotEmitted,
		Questions:          ledgerQuestions,
		Events:             []ledgerEventResult{},
	}
	for _, flt := range led.Faults {
		result.Unreadable = append(result.Unreadable, ledgerUnreadable{
			Line:   flt.Line,
			Reason: flt.Reason,
			After:  formatLedgerTime(flt.After),
			Before: formatLedgerTime(flt.Before),
		})
	}

	for _, e := range led.Entries {
		if !ledgerEntryMatches(e, since, until, mod, f.eventType) {
			continue
		}
		result.Matched++
		// The offset walks the matched events, not the ledger's lines: a page is
		// taken from the answer the filter produced, so paging and filtering
		// compose rather than one silently re-scoping the other.
		if result.Skipped < f.offset {
			result.Skipped++
			continue
		}
		if f.limit > 0 && len(result.Events) >= f.limit {
			result.Truncated = true
			continue
		}
		result.Events = append(result.Events, ledgerEventResult{
			Line:      e.Line,
			Timestamp: formatLedgerTime(e.Timestamp),
			EventType: string(e.Type),
			Fields:    e.Fields,
		})
	}

	if result.Matched == 0 {
		result.ZeroReasons = ledgerZeroReasons(led, mod, f.eventType, since, until)
	}

	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(result); encErr != nil {
			return fmt.Errorf("encoding ledger: %w", encErr)
		}
		return nil
	}
	return writeLedgerText(stdout, result)
}

// ledgerEntryMatches applies the query. An empty filter never restricts.
func ledgerEntryMatches(e factsqlite.LedgerEntry, since, until time.Time, mod ledgerModuleFilter, eventType string) bool {
	if !since.IsZero() && e.Timestamp.Before(since) {
		return false
	}
	if !until.IsZero() && e.Timestamp.After(until) {
		return false
	}
	if eventType != "" && string(e.Type) != eventType {
		return false
	}
	if mod.active() && !ledgerEntryNamesModule(e, mod) {
		return false
	}
	return true
}

// ledgerModuleFilter is a --module argument in the two forms it is asked in: a
// bare module path, and a coordinate that also carries a version.
//
// Both are accepted because the ledger's headline question — when did we first
// learn about this module@version — is asked in coordinates, while every payload
// key the filter compares against holds a bare path. Comparing the whole
// coordinate to a path is not a mis-parse, it is a comparison that can never be
// equal, and it answered "no events" for modules the log holds hundreds of
// events for.
type ledgerModuleFilter struct {
	path    string
	version string
}

// active reports whether the filter restricts anything.
func (m ledgerModuleFilter) active() bool { return m.path != "" }

// String renders the filter the way it was typed, for the statements that quote
// it back.
func (m ledgerModuleFilter) String() string {
	if m.version == "" {
		return m.path
	}
	return m.path + "@" + m.version
}

// parseLedgerModule splits a --module argument into the path and the version it
// may carry. A value that is neither — an empty path, or an "@" with nothing
// after it — is refused rather than filtered on, on the model --since and
// --until already set for a filter value the command cannot use.
func parseLedgerModule(value string) (ledgerModuleFilter, error) {
	if value == "" {
		return ledgerModuleFilter{}, nil
	}
	path, version, hasVersion := strings.Cut(value, "@")
	if path == "" || (hasVersion && version == "") {
		return ledgerModuleFilter{}, &exitError{code: ExitConfig, msg: fmt.Sprintf(
			"parsing --module %q: want a module path (example.com/mod) or a coordinate (example.com/mod@v1.2.3)", value)}
	}
	return ledgerModuleFilter{path: path, version: version}, nil
}

// ledgerModuleKeys are the payload keys under which an event names a module
// path. Three exist because three envelope generations do: the historical
// fact-record line uses module_path, the per-module events use module, and the
// project-scoped events (directives, GODEBUG, FIPS, vendor) name the project
// they scanned. A filter that knew only one of them would silently answer "no
// events" for whole families of the log.
var ledgerModuleKeys = []string{"module", "module_path", "project"}

// ledgerVersionKeys are the payload keys under which an event names the version
// of the module it named: module_version on the flat fact-record line, version
// on the generic per-module envelopes.
//
// They are read only to REFINE a path match, never to make one. An event that
// names the module and carries no version at all — a vendor-tree scan, a
// directive observation — is still an event about that module, and dropping it
// because the caller happened to type a coordinate would re-create, one level
// down, the silence the coordinate form was accepted to end.
var ledgerVersionKeys = []string{"module_version", "version"}

func ledgerEntryNamesModule(e factsqlite.LedgerEntry, mod ledgerModuleFilter) bool {
	named := false
	for _, k := range ledgerModuleKeys {
		if s, ok := e.Fields[k].(string); ok && s == mod.path {
			named = true
			break
		}
	}
	if !named || mod.version == "" {
		return named
	}
	for _, k := range ledgerVersionKeys {
		if s, ok := e.Fields[k].(string); ok && s != "" {
			return s == mod.version
		}
	}
	return true
}

// ledgerEventTypeNames is the accepted --event-type set, read from the audit
// vocabulary rather than restated here: every emitter passes Event.Validate,
// which admits exactly these, so the set a reader is offered cannot fall behind
// the set a writer can produce.
func ledgerEventTypeNames() []string {
	known := audit.KnownEventTypes()
	names := make([]string, 0, len(known))
	for _, t := range known {
		names = append(names, string(t))
	}
	return names
}

// ledgerEventTypeHelp renders that set for --help, two per line.
func ledgerEventTypeHelp() string {
	names := ledgerEventTypeNames()
	var b strings.Builder
	for i, n := range names {
		if i%2 == 0 {
			b.WriteString("  ")
		}
		b.WriteString(n)
		switch {
		case i == len(names)-1:
			b.WriteString("\n")
		case i%2 == 1:
			b.WriteString(",\n")
		default:
			b.WriteString(", ")
		}
	}
	return b.String()
}

// validateLedgerEventType refuses a value no event in this log can carry, and
// names the set that can.
//
// Without it an unrecognised name is indistinguishable from a recognised one
// with no events: both return the same well-qualified zero, and the zero is the
// convincing kind — it states its coverage window and volunteers what the log
// does not witness. --since and --until already refuse a value they cannot use;
// this is the same refusal for the same reason.
//
// The log in hand is consulted as well as the vocabulary. A type this build no
// longer declares can still stand in a log written by one that did, and
// refusing it would strand the history it names — the opposite of what an
// append-only ledger is for.
func validateLedgerEventType(value string, led factsqlite.Ledger) error {
	if value == "" || audit.EventType(value).Known() {
		return nil
	}
	for _, e := range led.Entries {
		if string(e.Type) == value {
			return nil
		}
	}
	return &exitError{code: ExitConfig, msg: fmt.Sprintf(
		"--event-type %q is not an event type this build emits or this ledger holds; accepted values: %s",
		value, strings.Join(ledgerEventTypeNames(), ", "))}
}

// ledgerZeroReasons names what emptied a reading that matched nothing.
//
// Each active filter is re-applied on its own, so the answer can say which one
// did it rather than leaving the caller to bisect their own flags. When every
// filter matches events by itself, that is said too: the reading is empty
// because no single event satisfies them together, which is a different fact
// with a different remedy.
func ledgerZeroReasons(led factsqlite.Ledger, mod ledgerModuleFilter, eventType string, since, until time.Time) []string {
	if len(led.Entries) == 0 {
		// The coverage line already states that the ledger holds no readable
		// event; repeating it per filter would explain a zero that has one cause.
		return nil
	}
	first, last := led.Coverage()
	windowed := !since.IsZero() || !until.IsZero()

	// Per-filter counts over the whole log: how many events each filter would
	// have matched had it been the only one.
	var windowAlone, moduleAlone, pathAlone, typeAlone int
	for _, e := range led.Entries {
		if ledgerEntryMatches(e, since, until, ledgerModuleFilter{}, "") {
			windowAlone++
		}
		if ledgerEntryNamesModule(e, mod) {
			moduleAlone++
		}
		if ledgerEntryNamesModule(e, ledgerModuleFilter{path: mod.path}) {
			pathAlone++
		}
		if string(e.Type) == eventType {
			typeAlone++
		}
	}

	var reasons []string
	if windowed && windowAlone == 0 {
		if disjoint := ledgerWindowOutsideCoverage(since, until, first, last); disjoint != "" {
			reasons = append(reasons, disjoint)
		} else {
			reasons = append(reasons, fmt.Sprintf(
				"no event falls in the window asked for, though the ledger's coverage (%s .. %s) spans it",
				formatLedgerTime(first), formatLedgerTime(last)))
		}
	}
	if mod.active() && moduleAlone == 0 {
		switch {
		case mod.version != "" && pathAlone > 0:
			reasons = append(reasons, fmt.Sprintf(
				"--module %q: %d event(s) name the path %s, none of them at version %s — the version is compared against the %s payload keys, for the events that carry one",
				mod.String(), pathAlone, mod.path, mod.version, strings.Join(ledgerVersionKeys, " and ")))
		default:
			reasons = append(reasons, fmt.Sprintf(
				"--module %q: no event names the path %s — the path is compared for exact equality against the %s payload keys of all %d event(s) the ledger holds",
				mod.String(), mod.path, strings.Join(ledgerModuleKeys, ", "), len(led.Entries)))
		}
	}
	if eventType != "" && typeAlone == 0 {
		reasons = append(reasons, fmt.Sprintf(
			"--event-type %q: the ledger holds no event of that type at all", eventType))
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "each filter matches events on its own; no single event satisfies all of them together")
	}
	return reasons
}

// ledgerWindowOutsideCoverage states a window that cannot hold an event because
// it lies wholly before or wholly after everything the ledger recorded. It is
// the --since/--until member of the same class as a coordinate compared to a
// path: a value that cannot match by construction, rather than one that matched
// nothing.
func ledgerWindowOutsideCoverage(since, until, first, last time.Time) string {
	if first.IsZero() || last.IsZero() {
		return ""
	}
	if !since.IsZero() && since.After(last) {
		return fmt.Sprintf("--since %s is after the last event the ledger holds (%s); no event can fall at or after it",
			formatLedgerTime(since), formatLedgerTime(last))
	}
	if !until.IsZero() && until.Before(first) {
		return fmt.Sprintf("--until %s is before the first event the ledger holds (%s); no event can fall at or before it",
			formatLedgerTime(until), formatLedgerTime(first))
	}
	return ""
}

func parseLedgerTime(flag, value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, &exitError{code: ExitConfig, msg: fmt.Sprintf("parsing %s %q: want RFC3339 (e.g. 2026-07-23T00:00:00Z): %v", flag, value, err)}
	}
	return t.UTC(), nil
}

// formatLedgerTime renders a timestamp, or the empty string for a zero time so
// an absent bound is omitted rather than printed as year one.
func formatLedgerTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// writeLedgerText renders the human form: the log's coverage first, the events
// second, the caveats last. Coverage leads because it is the frame every line
// below it has to be read in.
func writeLedgerText(w io.Writer, r ledgerResult) error {
	if _, err := fmt.Fprintf(w, "ledger: %s\n", r.LedgerPath); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	if r.Coverage.Events == 0 {
		if _, err := fmt.Fprintf(w, "coverage: none — the ledger holds no readable event (%d line(s) read)\n", r.Coverage.LinesRead); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	} else if _, err := fmt.Fprintf(w, "coverage: %s .. %s (%d event(s) from %d line(s))\n",
		r.Coverage.FirstEvent, r.Coverage.LastEvent, r.Coverage.Events, r.Coverage.LinesRead); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	if r.UnreadableCount > 0 {
		lines := make([]string, 0, len(r.Unreadable))
		for _, u := range r.Unreadable {
			lines = append(lines, fmt.Sprintf("%d", u.Line))
		}
		if _, err := fmt.Fprintf(w, "unreadable: %d line(s) — %s\n", r.UnreadableCount, strings.Join(lines, ", ")); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	for _, e := range r.Events {
		if _, err := fmt.Fprintf(w, "%s  %s  %s  [line %d]\n", e.Timestamp, e.EventType, renderLedgerFields(e.Fields), e.Line); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if len(r.Events) > 0 {
		if _, err := fmt.Fprintln(w); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}

	if _, err := fmt.Fprintf(w, "matched: %d event(s)", r.Matched); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	switch {
	case r.Truncated:
		// The next page is named as well as the whole set, so a reader told the
		// listing stopped short is not left choosing between this page and all
		// of it.
		if _, err := fmt.Fprintf(w, " (%d listed from %d; raise --limit to see the rest, or --offset %d for the next page)",
			len(r.Events), r.Skipped, r.Skipped+len(r.Events)); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	case r.Skipped > 0:
		if _, err := fmt.Fprintf(w, " (%d listed from %d; the last page)", len(r.Events), r.Skipped); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	if len(r.ZeroReasons) > 0 {
		if _, err := fmt.Fprintf(w, "why this reading is empty:\n"); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		for _, s := range r.ZeroReasons {
			if _, err := fmt.Fprintf(w, "  - %s\n", s); err != nil {
				return fmt.Errorf("writing output: %w", err)
			}
		}
	}
	if r.UnreadableInWindow > 0 {
		if _, err := fmt.Fprintf(w,
			"caveat: %d unreadable line(s) fall inside the window queried; the matched count is a lower bound for it\n",
			r.UnreadableInWindow); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	return writeLedgerCaveats(w, r)
}

// writeLedgerCaveats prints the two standing statements every reading owes: what
// the log does not witness, and which question each half of it answers.
func writeLedgerCaveats(w io.Writer, r ledgerResult) error {
	if _, err := fmt.Fprintf(w, "\nnot witnessed by this ledger (silence here is not evidence that nothing happened):\n"); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	for _, s := range r.NotWitnessed {
		if _, err := fmt.Fprintf(w, "  - %s\n", s); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if _, err := fmt.Fprintf(w, "\nquestions this ledger answers:\n"); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	for _, s := range r.Questions {
		if _, err := fmt.Fprintf(w, "  - %s\n", s); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	return nil
}

// renderLedgerFields renders an event body as sorted key=value pairs.
//
// It is deliberately generic rather than a per-event-type renderer: the
// vocabulary grows every few weeks, and a switch would print a new event type as
// a bare line with its facts invisible — the ledger's own version of the silence
// this command exists to end.
func renderLedgerFields(fields map[string]any) string {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, fields[k]))
	}
	return strings.Join(parts, " ")
}
