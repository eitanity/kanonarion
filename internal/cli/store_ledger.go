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
		Use:   "ledger",
		Short: "List the store's append-only assurance-log events",
		Long: `List the events in the store's append-only assurance log (audit.jsonl).

Events are listed in chronological order. The ledger's own coverage window —
its first and last event — is always stated, so an empty result over a window
the log never spanned is distinguishable from a window in which nothing
happened. Lines that cannot be read are counted and named by line number; they
are never dropped and never abort the read.`,
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
	cmd.Flags().StringVar(&f.module, "module", "", "list only events naming this module path")
	cmd.Flags().StringVar(&f.eventType, "event-type", "", "list only events of this type")
	cmd.Flags().IntVar(&f.limit, "limit", 0, "maximum number of events to list (0 = unlimited)")
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
	UnreadableInWindow int                 `json:"unreadable_in_window"`
	Matched            int                 `json:"matched"`
	Truncated          bool                `json:"truncated"`
	Events             []ledgerEventResult `json:"events"`
	NotWitnessed       []string            `json:"not_witnessed"`
	Questions          []string            `json:"questions_answered"`
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

	path := factsqlite.AuditLogPath(root)
	led, err := factsqlite.ReadLedger(path)
	if err != nil {
		return fmt.Errorf("reading the assurance log: %w", err)
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
		if !ledgerEntryMatches(e, since, until, f.module, f.eventType) {
			continue
		}
		result.Matched++
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
func ledgerEntryMatches(e factsqlite.LedgerEntry, since, until time.Time, module, eventType string) bool {
	if !since.IsZero() && e.Timestamp.Before(since) {
		return false
	}
	if !until.IsZero() && e.Timestamp.After(until) {
		return false
	}
	if eventType != "" && string(e.Type) != eventType {
		return false
	}
	if module != "" && !ledgerEntryNamesModule(e, module) {
		return false
	}
	return true
}

// ledgerModuleKeys are the payload keys under which an event names a module
// path. Three exist because three envelope generations do: the historical
// fact-record line uses module_path, the per-module events use module, and the
// project-scoped events (directives, GODEBUG, FIPS, vendor) name the project
// they scanned. A filter that knew only one of them would silently answer "no
// events" for whole families of the log.
var ledgerModuleKeys = []string{"module", "module_path", "project"}

func ledgerEntryNamesModule(e factsqlite.LedgerEntry, module string) bool {
	for _, k := range ledgerModuleKeys {
		if s, ok := e.Fields[k].(string); ok && s == module {
			return true
		}
	}
	return false
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
	if r.Truncated {
		if _, err := fmt.Fprintf(w, " (%d listed; raise --limit to see the rest)", len(r.Events)); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return fmt.Errorf("writing output: %w", err)
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
