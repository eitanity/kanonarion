package sqlite_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sqlite "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	"github.com/eitanity/kanonarion/internal/audit"
)

// writeLedger plants a ledger file with the exact lines given and returns its
// path. Lines are written verbatim so a test can plant a torn one.
func writeLedger(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	body := ""
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing ledger fixture: %v", err)
	}
	return path
}

// The three shapes the reference store's own torn lines take, reproduced from
// the measurement of it: a spliced prefix, a splice mid-string, and a bare
// truncation. All three are the same mechanism — two unsynchronised appends
// interleaving — and a reader that tolerates one but not another would still
// abort on a production ledger.
const (
	tornSplicedPrefix = `{"{"event_type":"license_extracted","timestamp":"2026-07-08T16:30:01Z"}`
	tornMidString     = `{"event_type":"license_extracted","timestamp":"2026-07-08T16:30:04Z","payload":{"module":"github.com/docker/docke{"event_type":"license_extracted"}`
	tornTruncated     = `{"event_type":"license_extracted","timestamp":"2026-07-08T16:3`
)

func goodLine(ts, module string) string {
	return `{"event_type":"license_extracted","timestamp":"` + ts + `","payload":{"module":"` + module + `"}}`
}

// TestReadLedger_CountsATornLineAndKeepsReading is the prove-can-fail test for
// the whole reader. A torn line must be COUNTED as a named category and the read
// must continue: a strict line-by-line parse aborts at line 4,601 of the
// reference store's 33,012-line ledger and takes the other 33,008 events with
// it, and a silent skip is worse still — the reader would report a smaller
// ledger than exists and nothing would say so.
//
// It fails on both failure modes. If the reader aborts, the entries after the
// tear are missing. If it skips silently, the fault count is zero.
func TestReadLedger_CountsATornLineAndKeepsReading(t *testing.T) {
	path := writeLedger(t,
		goodLine("2026-07-08T16:29:00Z", "example.com/a"),
		tornSplicedPrefix,
		goodLine("2026-07-08T16:31:00Z", "example.com/b"),
		tornMidString,
		goodLine("2026-07-08T16:33:00Z", "example.com/c"),
		tornTruncated,
		goodLine("2026-07-08T16:35:00Z", "example.com/d"),
	)

	led, err := sqlite.ReadLedger(path)
	if err != nil {
		t.Fatalf("ReadLedger aborted on a torn line: %v", err)
	}
	if led.LinesRead != 7 {
		t.Errorf("LinesRead = %d, want 7 (every line accounted for)", led.LinesRead)
	}
	if len(led.Entries) != 4 {
		t.Fatalf("recovered %d event(s), want 4: the read stopped at the first tear", len(led.Entries))
	}
	if len(led.Faults) != 3 {
		t.Fatalf("counted %d unreadable line(s), want 3: torn lines were skipped silently", len(led.Faults))
	}
	wantLines := []int{2, 4, 6}
	for i, f := range led.Faults {
		if f.Line != wantLines[i] {
			t.Errorf("fault %d reported line %d, want %d", i, f.Line, wantLines[i])
		}
		if f.Reason == "" {
			t.Errorf("fault on line %d carries no reason", f.Line)
		}
	}
	// The events after the last tear are present, which is what "keeps reading"
	// means and what a control-less count of 4 could not distinguish.
	if got := led.Entries[len(led.Entries)-1].Fields["module"]; got != "example.com/d" {
		t.Errorf("last recovered event names %v, want the module written after the last tear", got)
	}
}

// Control for the test above: a ledger with no torn lines reports no faults, so
// the count of 3 there is attributable to the plants and not to the reader
// mis-reading well-formed lines.
func TestReadLedger_CleanLedgerReportsNoFaults(t *testing.T) {
	path := writeLedger(t,
		goodLine("2026-07-08T16:29:00Z", "example.com/a"),
		goodLine("2026-07-08T16:31:00Z", "example.com/b"),
	)
	led, err := sqlite.ReadLedger(path)
	if err != nil {
		t.Fatalf("ReadLedger: %v", err)
	}
	if len(led.Faults) != 0 {
		t.Errorf("a well-formed ledger reported %d fault(s): %+v", len(led.Faults), led.Faults)
	}
	if led.LinesRead != len(led.Entries) {
		t.Errorf("LinesRead = %d but recovered %d event(s); the two must reconcile", led.LinesRead, len(led.Entries))
	}
}

// TestReadLedger_BracketsATornLineInTime pins what makes a torn line reportable
// against a window. The line carries no timestamp of its own, so the only honest
// placement is between its readable neighbours — and that placement is what lets
// a query over 2026-07-08 say its count for that day is a lower bound.
func TestReadLedger_BracketsATornLineInTime(t *testing.T) {
	path := writeLedger(t,
		goodLine("2026-07-08T16:29:00Z", "example.com/a"),
		tornSplicedPrefix,
		goodLine("2026-07-08T16:31:00Z", "example.com/b"),
	)
	led, err := sqlite.ReadLedger(path)
	if err != nil {
		t.Fatalf("ReadLedger: %v", err)
	}
	if len(led.Faults) != 1 {
		t.Fatalf("want 1 fault, got %d", len(led.Faults))
	}
	f := led.Faults[0]
	if got := f.After.Format(time.RFC3339); got != "2026-07-08T16:29:00Z" {
		t.Errorf("fault After = %s, want the preceding readable event", got)
	}
	if got := f.Before.Format(time.RFC3339); got != "2026-07-08T16:31:00Z" {
		t.Errorf("fault Before = %s, want the following readable event", got)
	}

	// The window that contains the tear reports it.
	day := func(s string) time.Time {
		ts, perr := time.Parse(time.RFC3339, s)
		if perr != nil {
			t.Fatalf("parsing %s: %v", s, perr)
		}
		return ts
	}
	if got := led.FaultsWithin(day("2026-07-08T00:00:00Z"), day("2026-07-09T00:00:00Z")); len(got) != 1 {
		t.Errorf("the day containing the tear reported %d fault(s), want 1", len(got))
	}
	// Control: a window entirely after the tear does not inherit its caveat.
	if got := led.FaultsWithin(day("2026-07-09T00:00:00Z"), day("2026-07-10T00:00:00Z")); len(got) != 0 {
		t.Errorf("a window after the tear reported %d fault(s), want 0", len(got))
	}
}

// TestReadLedger_CoverageWindow pins the distinction the whole reader exists
// for: an empty ledger has no coverage, and a populated one states a window.
// Without that, "no event in this window" and "the ledger never spanned this
// window" are the same output, and only one of them supports "we could not have
// known".
func TestReadLedger_CoverageWindow(t *testing.T) {
	empty, err := sqlite.ReadLedger(writeLedger(t))
	if err != nil {
		t.Fatalf("ReadLedger on an empty ledger: %v", err)
	}
	first, last := empty.Coverage()
	if !first.IsZero() || !last.IsZero() {
		t.Errorf("an empty ledger claimed coverage %s .. %s", first, last)
	}
	if empty.LinesRead != 0 {
		t.Errorf("LinesRead = %d on an empty file, want 0", empty.LinesRead)
	}

	populated, err := sqlite.ReadLedger(writeLedger(t,
		goodLine("2026-07-08T16:31:00Z", "example.com/b"),
		goodLine("2026-07-08T16:29:00Z", "example.com/a"),
		goodLine("2026-07-08T16:33:00Z", "example.com/c"),
	))
	if err != nil {
		t.Fatalf("ReadLedger: %v", err)
	}
	first, last = populated.Coverage()
	if got := first.Format(time.RFC3339); got != "2026-07-08T16:29:00Z" {
		t.Errorf("first event = %s, want the earliest event and not the first LINE", got)
	}
	if got := last.Format(time.RFC3339); got != "2026-07-08T16:33:00Z" {
		t.Errorf("last event = %s, want the latest event", got)
	}
}

// TestReadLedger_ReadsTheFlatFactRecordLayout pins that the historical
// fact-record line — flat fields, no payload — is normalised into the same shape
// as every generic envelope. A reader that understood only the payload envelope
// would silently answer "no events" for the largest event family in the log.
func TestReadLedger_ReadsTheFlatFactRecordLayout(t *testing.T) {
	flat := `{"event_type":"fact_record_written","timestamp":"2026-07-08T16:29:00Z",` +
		`"module_path":"example.com/a","module_version":"v1.0.0","content_hash":"h1:abc"}`
	led, err := sqlite.ReadLedger(writeLedger(t, flat))
	if err != nil {
		t.Fatalf("ReadLedger: %v", err)
	}
	if len(led.Entries) != 1 {
		t.Fatalf("recovered %d event(s), want 1", len(led.Entries))
	}
	e := led.Entries[0]
	if e.Type != audit.EventFactRecordWritten {
		t.Errorf("event type = %q, want %q", e.Type, audit.EventFactRecordWritten)
	}
	if got := e.Fields["module_path"]; got != "example.com/a" {
		t.Errorf("flat field module_path = %v, want example.com/a", got)
	}
	// The envelope fields are lifted out, so the body carries only the event's
	// own facts, exactly as a payload does.
	for _, envelope := range []string{"event_type", "timestamp"} {
		if _, present := e.Fields[envelope]; present {
			t.Errorf("envelope field %q leaked into the event body", envelope)
		}
	}
}

// TestReadLedger_AcceptsAnUnknownEventType pins that an event written by a newer
// build is data, not damage. Counting it as unreadable would make an older
// reader report a newer store's evidence as corruption.
func TestReadLedger_AcceptsAnUnknownEventType(t *testing.T) {
	line := `{"event_type":"invented_by_a_newer_build","timestamp":"2026-07-08T16:29:00Z","payload":{"module":"example.com/a"}}`
	led, err := sqlite.ReadLedger(writeLedger(t, line))
	if err != nil {
		t.Fatalf("ReadLedger: %v", err)
	}
	if len(led.Faults) != 0 {
		t.Fatalf("an unrecognised event type was reported as unreadable: %+v", led.Faults)
	}
	if got := string(led.Entries[0].Type); got != "invented_by_a_newer_build" {
		t.Errorf("event type = %q, want it carried through verbatim", got)
	}
}

// A line that parses as JSON but carries no readable timestamp is a fault: an
// event that cannot be placed in time cannot take part in any answer, and
// counting it as readable would put it in a coverage window it has no claim on.
func TestReadLedger_UntimedLineIsAFault(t *testing.T) {
	led, err := sqlite.ReadLedger(writeLedger(t,
		`{"event_type":"license_extracted","payload":{"module":"example.com/a"}}`,
		goodLine("2026-07-08T16:29:00Z", "example.com/b"),
	))
	if err != nil {
		t.Fatalf("ReadLedger: %v", err)
	}
	if len(led.Faults) != 1 {
		t.Fatalf("want 1 fault for the untimed line, got %d", len(led.Faults))
	}
	if !strings.Contains(led.Faults[0].Reason, "timestamp") {
		t.Errorf("fault reason %q does not say the timestamp was the problem", led.Faults[0].Reason)
	}
}

// A missing ledger is an error rather than an empty read: "no ledger here" and
// "a ledger that recorded nothing" are different answers.
func TestReadLedger_MissingFileIsAnError(t *testing.T) {
	if _, err := sqlite.ReadLedger(filepath.Join(t.TempDir(), "absent.jsonl")); err == nil {
		t.Fatal("a missing ledger read as an empty one")
	}
}

// AuditLogPath is where the writer puts it, so the reader and the writer cannot
// drift apart on the name.
func TestAuditLogPath(t *testing.T) {
	root := t.TempDir()
	path := sqlite.AuditLogPath(root)
	if _, err := sqlite.NewAuditLog(path); err != nil {
		t.Fatalf("NewAuditLog at the reader's path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "audit.jsonl")); err != nil {
		t.Errorf("the writer did not create the file the reader looks for: %v", err)
	}
}
