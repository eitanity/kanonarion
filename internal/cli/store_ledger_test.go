package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ledgerFixture writes a store root holding the given ledger lines verbatim and
// returns the root. Lines are written raw so a test can plant a torn one.
func ledgerFixture(t *testing.T, lines ...string) string {
	t.Helper()
	root := t.TempDir()
	body := ""
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(filepath.Join(root, "audit.jsonl"), []byte(body), 0o600); err != nil {
		t.Fatalf("writing ledger fixture: %v", err)
	}
	return root
}

const (
	ledgerFindingJWT = `{"event_type":"vuln_finding_observed","timestamp":"2026-07-23T15:09:05.123456789Z",` +
		`"payload":{"module":"github.com/golang-jwt/jwt/v4","version":"v4.5.1","vuln_id":"GO-2025-3553","overall_status":"Affected"}}`
	ledgerFindingLater = `{"event_type":"vuln_finding_observed","timestamp":"2026-07-30T11:00:00Z",` +
		`"payload":{"module":"github.com/golang-jwt/jwt/v4","version":"v4.5.1","vuln_id":"GO-2025-3553","overall_status":"Affected"}}`
	ledgerFactWritten = `{"event_type":"fact_record_written","timestamp":"2026-07-20T08:00:00Z",` +
		`"module_path":"github.com/spf13/cobra","module_version":"v1.8.1","content_hash":"h1:abc"}`
	ledgerScanServed = `{"event_type":"vuln_scan_served","timestamp":"2026-08-03T09:00:00Z",` +
		`"payload":{"scan_id":"vscan-1","walk_id":"walk-1","surface":"vuln-scan"}}`
	ledgerTorn = `{"{"event_type":"license_extracted","timestamp":"2026-07-25T16:30:01Z"}`
)

func runLedger(t *testing.T, root string, f storeLedgerFlags, asJSON bool) string {
	t.Helper()
	var out bytes.Buffer
	if err := runStoreLedger(root, f, asJSON, &out); err != nil {
		t.Fatalf("runStoreLedger: %v", err)
	}
	return out.String()
}

func decodeLedger(t *testing.T, s string) ledgerResult {
	t.Helper()
	var r ledgerResult
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		t.Fatalf("decoding ledger JSON: %v\n%s", err, s)
	}
	return r
}

// TestStoreLedger_StatesItsCoverageWindow pins the distinction the command
// exists for. A query that returns nothing over a window the ledger never
// spanned has found no evidence of absence; without the window stated, that
// output is indistinguishable from a window in which genuinely nothing happened,
// and only one of the two supports "we could not have known".
func TestStoreLedger_StatesItsCoverageWindow(t *testing.T) {
	root := ledgerFixture(t, ledgerFactWritten, ledgerFindingJWT, ledgerScanServed)
	got := decodeLedger(t, runLedger(t, root, storeLedgerFlags{}, true))

	if got.Coverage.FirstEvent != "2026-07-20T08:00:00Z" {
		t.Errorf("first_event = %q, want the earliest event", got.Coverage.FirstEvent)
	}
	if !strings.HasPrefix(got.Coverage.LastEvent, "2026-08-03T09:00:00") {
		t.Errorf("last_event = %q, want the latest event", got.Coverage.LastEvent)
	}
	if got.Coverage.Events != 3 || got.Coverage.LinesRead != 3 {
		t.Errorf("coverage = %d event(s) from %d line(s), want 3 from 3", got.Coverage.Events, got.Coverage.LinesRead)
	}

	// The same statement in the human form, because that is the one an operator
	// under pressure actually reads.
	text := runLedger(t, root, storeLedgerFlags{}, false)
	if !strings.Contains(text, "coverage: 2026-07-20T08:00:00Z .. ") {
		t.Errorf("text output does not state the coverage window:\n%s", text)
	}
}

// An empty ledger says it has NO coverage rather than reporting a window of
// nothing, so a zero result over it can never be read as "nothing happened".
func TestStoreLedger_EmptyLedgerReportsNoCoverage(t *testing.T) {
	root := ledgerFixture(t)

	got := decodeLedger(t, runLedger(t, root, storeLedgerFlags{}, true))
	if got.Coverage.FirstEvent != "" || got.Coverage.LastEvent != "" {
		t.Errorf("an empty ledger claimed coverage %q .. %q", got.Coverage.FirstEvent, got.Coverage.LastEvent)
	}
	if got.Coverage.Events != 0 || got.Matched != 0 {
		t.Errorf("an empty ledger reported %d event(s), %d matched", got.Coverage.Events, got.Matched)
	}

	text := runLedger(t, root, storeLedgerFlags{}, false)
	if !strings.Contains(text, "coverage: none") {
		t.Errorf("an empty ledger did not say it has no coverage:\n%s", text)
	}
	// Control: the populated fixture does NOT say "coverage: none", so the
	// assertion above distinguishes the two rather than matching everything.
	populated := runLedger(t, ledgerFixture(t, ledgerFactWritten), storeLedgerFlags{}, false)
	if strings.Contains(populated, "coverage: none") {
		t.Errorf("a populated ledger reported no coverage:\n%s", populated)
	}
}

// TestStoreLedger_CountsAndNamesUnreadableLines is the prove-can-fail test at
// the command level: a torn line must be counted, named by its line number, and
// must not stop the read. It fails if the reader aborts (the events after the
// tear go missing) and it fails if the reader skips silently (the count is zero).
func TestStoreLedger_CountsAndNamesUnreadableLines(t *testing.T) {
	root := ledgerFixture(t, ledgerFactWritten, ledgerTorn, ledgerFindingJWT)

	got := decodeLedger(t, runLedger(t, root, storeLedgerFlags{}, true))
	if got.UnreadableCount != 1 {
		t.Fatalf("unreadable_count = %d, want 1: the torn line was dropped silently", got.UnreadableCount)
	}
	if len(got.Unreadable) != 1 || got.Unreadable[0].Line != 2 {
		t.Fatalf("unreadable = %+v, want the torn line named as line 2", got.Unreadable)
	}
	if got.Coverage.LinesRead != 3 || got.Coverage.Events != 2 {
		t.Errorf("read %d line(s) into %d event(s), want 3 into 2", got.Coverage.LinesRead, got.Coverage.Events)
	}
	if got.Matched != 2 {
		t.Errorf("matched %d event(s), want 2: the read stopped at the tear", got.Matched)
	}

	text := runLedger(t, root, storeLedgerFlags{}, false)
	if !strings.Contains(text, "unreadable: 1 line(s) — 2") {
		t.Errorf("text output does not name the unreadable line:\n%s", text)
	}
	// Control: a clean ledger prints no unreadable line at all.
	clean := runLedger(t, ledgerFixture(t, ledgerFactWritten), storeLedgerFlags{}, false)
	if strings.Contains(clean, "unreadable:") {
		t.Errorf("a clean ledger reported unreadable lines:\n%s", clean)
	}
}

// A window that may be missing events says so. The torn line carries no
// timestamp, so it is placed by its readable neighbours, and any window that
// could contain it gets the lower-bound caveat rather than a count that looks
// complete.
func TestStoreLedger_CaveatsAWindowContainingATornLine(t *testing.T) {
	root := ledgerFixture(t, ledgerFactWritten, ledgerTorn, ledgerFindingJWT, ledgerScanServed)

	within := decodeLedger(t, runLedger(t, root, storeLedgerFlags{
		since: "2026-07-20T00:00:00Z", until: "2026-07-24T00:00:00Z",
	}, true))
	if within.UnreadableInWindow != 1 {
		t.Errorf("unreadable_in_window = %d over the window holding the tear, want 1", within.UnreadableInWindow)
	}

	// Control: a window entirely after the tear does not inherit its caveat.
	after := decodeLedger(t, runLedger(t, root, storeLedgerFlags{since: "2026-08-01T00:00:00Z"}, true))
	if after.UnreadableInWindow != 0 {
		t.Errorf("unreadable_in_window = %d over a window after the tear, want 0", after.UnreadableInWindow)
	}

	text := runLedger(t, root, storeLedgerFlags{
		since: "2026-07-20T00:00:00Z", until: "2026-07-24T00:00:00Z",
	}, false)
	if !strings.Contains(text, "lower bound") {
		t.Errorf("a window holding an unreadable line did not state that its count is a lower bound:\n%s", text)
	}
}

// TestStoreLedger_FiltersAndOrdersChronologically covers the query shapes an
// evidence question actually takes, including the first-awareness one: the
// earliest observation of a module, reachable in a single command.
func TestStoreLedger_FiltersAndOrdersChronologically(t *testing.T) {
	root := ledgerFixture(t, ledgerFindingLater, ledgerFactWritten, ledgerFindingJWT, ledgerScanServed)

	// First awareness: earliest event of a type, for a module, in one call.
	first := decodeLedger(t, runLedger(t, root, storeLedgerFlags{
		eventType: "vuln_finding_observed",
		module:    "github.com/golang-jwt/jwt/v4",
		limit:     1,
	}, true))
	if first.Matched != 2 {
		t.Errorf("matched = %d, want 2 observations of this module", first.Matched)
	}
	if len(first.Events) != 1 {
		t.Fatalf("listed %d event(s) under --limit 1", len(first.Events))
	}
	if !strings.HasPrefix(first.Events[0].Timestamp, "2026-07-23T15:09:05") {
		t.Errorf("first listed event = %q, want the EARLIEST observation and not the first line",
			first.Events[0].Timestamp)
	}
	if !first.Truncated {
		t.Error("a limited listing did not say the result was truncated")
	}

	// The module filter reaches the flat fact-record layout too, which carries
	// its module under module_path rather than module.
	flat := decodeLedger(t, runLedger(t, root, storeLedgerFlags{module: "github.com/spf13/cobra"}, true))
	if flat.Matched != 1 {
		t.Errorf("matched = %d for a module named only by the flat fact-record layout, want 1", flat.Matched)
	}

	// A window restricts.
	windowed := decodeLedger(t, runLedger(t, root, storeLedgerFlags{
		since: "2026-07-23T00:00:00Z", until: "2026-07-24T00:00:00Z",
	}, true))
	if windowed.Matched != 1 {
		t.Errorf("matched = %d over one day, want 1", windowed.Matched)
	}
	// Control: unfiltered, everything matches — so the counts above measure the
	// filters rather than a reader that finds nothing.
	all := decodeLedger(t, runLedger(t, root, storeLedgerFlags{}, true))
	if all.Matched != 4 {
		t.Errorf("unfiltered match = %d, want all 4 events", all.Matched)
	}
}

// TestStoreLedger_StatesWhatItDoesNotWitness pins the standing caveat. The
// ledger's most dangerous property is that it reads as complete: several
// persisted record kinds append nothing, and a reader not told so will take
// silence for proof.
func TestStoreLedger_StatesWhatItDoesNotWitness(t *testing.T) {
	root := ledgerFixture(t, ledgerFactWritten)

	got := decodeLedger(t, runLedger(t, root, storeLedgerFlags{}, true))
	if len(got.NotWitnessed) == 0 {
		t.Fatal("the reader states nothing about what the ledger does not witness")
	}
	joined := strings.Join(got.NotWitnessed, "\n")
	// The measured gap the maintainer named explicitly: generations are counted,
	// never listed.
	if !strings.Contains(joined, "vulnerability record generations") {
		t.Errorf("the statement does not name individual vuln record generations:\n%s", joined)
	}
	if len(got.Questions) != 2 {
		t.Errorf("questions_answered has %d entr(ies), want the two the ledger distinguishes", len(got.Questions))
	}

	text := runLedger(t, root, storeLedgerFlags{}, false)
	for _, want := range []string{"not witnessed by this ledger", "questions this ledger answers", "vuln_scan_served"} {
		if !strings.Contains(text, want) {
			t.Errorf("text output is missing %q:\n%s", want, text)
		}
	}
}

// Malformed query bounds are refused by name rather than silently ignored, and
// an absent ledger is an error rather than an empty answer.
func TestStoreLedger_RefusesUnusableQueries(t *testing.T) {
	root := ledgerFixture(t, ledgerFactWritten)
	var out bytes.Buffer

	for name, f := range map[string]storeLedgerFlags{
		"bad since":       {since: "yesterday"},
		"bad until":       {until: "yesterday"},
		"until < since":   {since: "2026-08-01T00:00:00Z", until: "2026-07-01T00:00:00Z"},
		"negative limit":  {limit: -1},
		"negative offset": {offset: -1},
	} {
		if err := runStoreLedger(root, f, false, &out); err == nil {
			t.Errorf("%s: accepted an unusable query", name)
		}
	}

	if err := runStoreLedger(t.TempDir(), storeLedgerFlags{}, false, &out); err == nil {
		t.Error("a store with no ledger read as an empty one")
	}
}

// The ledger is paged like every other capped listing: --offset steps over
// MATCHED events, so paging and filtering compose rather than one silently
// re-scoping the other, and the answer states how many it stepped over.
//
// The zero-paired control is the last page: it has withheld nothing and must
// not offer a next page, which is what stops the remedy line being boilerplate.
func TestStoreLedger_PagesTheMatchedEvents(t *testing.T) {
	root := ledgerFixture(t, ledgerFactWritten, ledgerFindingJWT, ledgerFindingLater, ledgerScanServed)

	all := decodeLedger(t, runLedger(t, root, storeLedgerFlags{}, true))
	if len(all.Events) != 4 {
		t.Fatalf("the fixture holds %d events, want 4", len(all.Events))
	}

	page := decodeLedger(t, runLedger(t, root, storeLedgerFlags{limit: 2, offset: 1}, true))
	if len(page.Events) != 2 {
		t.Fatalf("page holds %d events, want 2", len(page.Events))
	}
	if page.Skipped != 1 {
		t.Errorf("skipped = %d, want 1", page.Skipped)
	}
	if page.Matched != all.Matched {
		t.Errorf("matched = %d on a paged read, want the whole window %d", page.Matched, all.Matched)
	}
	for i := range page.Events {
		if page.Events[i].Line != all.Events[i+1].Line {
			t.Errorf("paged event %d is line %d, want line %d", i, page.Events[i].Line, all.Events[i+1].Line)
		}
	}

	// The offset walks matched events, not ledger lines: with a filter applied
	// it pages the filtered answer.
	filtered := decodeLedger(t, runLedger(t, root,
		storeLedgerFlags{eventType: "vuln_finding_observed", offset: 1}, true))
	if len(filtered.Events) != 1 || filtered.Matched != 2 || filtered.Skipped != 1 {
		t.Errorf("paging a filtered window gave %d event(s), matched %d, skipped %d; want 1/2/1",
			len(filtered.Events), filtered.Matched, filtered.Skipped)
	}

	text := runLedger(t, root, storeLedgerFlags{limit: 2, offset: 0}, false)
	if !strings.Contains(text, "--offset 2 for the next page") {
		t.Errorf("a truncated ledger read does not name the next page:\n%s", text)
	}
	last := runLedger(t, root, storeLedgerFlags{limit: 2, offset: 2}, false)
	if strings.Contains(last, "for the next page") {
		t.Errorf("the last page offered a next one:\n%s", last)
	}
}

// The reader never writes. It is the command an operator reaches for while
// deciding whether evidence is intact, and one that mutated the artefact it
// reports on would be unusable for that.
func TestStoreLedger_NeverWritesToTheLedger(t *testing.T) {
	root := ledgerFixture(t, ledgerFactWritten, ledgerTorn, ledgerFindingJWT)
	path := filepath.Join(root, "audit.jsonl")

	before, err := os.ReadFile(path) // #nosec G304 -- test fixture path
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	_ = runLedger(t, root, storeLedgerFlags{}, false)
	_ = runLedger(t, root, storeLedgerFlags{module: "github.com/spf13/cobra"}, true)

	after, err := os.ReadFile(path) // #nosec G304 -- test fixture path
	if err != nil {
		t.Fatalf("re-reading fixture: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("reading the ledger changed it")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading store root: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("reading the ledger created %d extra entr(ies) in the store root", len(entries)-1)
	}
}
