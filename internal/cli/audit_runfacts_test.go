package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// The guard on what `audit --json` says about its own run.
//
// audit narrates its provenance to a person on stderr and its staleness date to
// a person on stdout. The document carried the rows and nothing else, so a --json
// consumer could not tell a measurement from a record served out of the store —
// the distinction that decides what the answer is worth. These tests hold the
// two channels to one story: every statement the run makes about itself is a
// field, the field is built from the same measurement the sentence is, and an
// axis that was not measured says so rather than going missing.

// auditWalkForFacts is the walk record a derivation names.
func auditWalkForFacts() walkdomain.WalkRecord {
	return walkdomain.WalkRecord{
		ID:          "01KZ0AVM2897N6J6YE4GABYG27",
		CompletedAt: time.Date(2026, 8, 2, 4, 14, 7, 0, time.UTC),
	}
}

// auditRunFields marshals the run-level half and returns its top-level keys.
func auditRunFields(t *testing.T, run auditRunJSON) map[string]json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(run)
	if err != nil {
		t.Fatalf("encoding the run facts: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("the run facts do not decode as an object: %v", err)
	}
	return fields
}

// TestAuditRunFactsStateAReusedRun is the arm the surface exists for.
//
// A served answer is the case where "who measured this" changes what it is
// worth, and it was the case with nothing in the document: the walk's identity
// and date, the scan's run id and snapshot, and the fact that the reachability
// verdicts rest on source THIS run did not read, all reached the person and not
// the machine.
//
// Each assertion is against the sentence as well as the value, because the two
// must be one measurement: the derivation statement is rendered from the same
// struct, so a field that disagrees with the line beside it fails here.
func TestAuditRunFactsStateAReusedRun(t *testing.T) {
	d := auditDerivation{
		walkReused:               true,
		walkRecord:               auditWalkForFacts(),
		scanReused:               true,
		scanRun:                  reusedRunForBasis(),
		scanReachabilityVerdicts: 4,
	}
	run := newAuditRunJSON(d, nil, time.Hour, time.Now())
	fields := auditRunFields(t, run)

	var sentence bytes.Buffer
	if err := writeAuditDerivation(&sentence, d); err != nil {
		t.Fatal(err)
	}
	said := sentence.String()

	if !run.Walk.Resolved || run.Walk.ID != d.walkRecord.ID || !run.Walk.Reused {
		t.Errorf("walk = %+v, want the reused record %s", run.Walk, d.walkRecord.ID)
	}
	if want := "2026-08-02T04:14:07Z"; run.Walk.CompletedAt != want {
		t.Errorf("walk.completed_at = %q, want %q — the date the sentence prints", run.Walk.CompletedAt, want)
	}
	if !strings.Contains(said, run.Walk.CompletedAt) || !strings.Contains(said, run.Walk.ID) {
		t.Errorf("the walk field and the derivation sentence name different records:\nfield: %+v\nsaid:  %s", run.Walk, said)
	}

	if !run.Scan.Answered || run.Scan.RunID != d.scanRun.ID || !run.Scan.Reused {
		t.Errorf("scan = %+v, want the reused run %s", run.Scan, d.scanRun.ID)
	}
	if got, want := run.Scan.Snapshot, vulnScanSnapshotOf(d.scanRun.Snapshot); got != want {
		t.Errorf("scan.snapshot = %+v, want the snapshot the run names, %+v", got, want)
	}
	if !strings.Contains(said, run.Scan.RunID) || !strings.Contains(said, run.Scan.Snapshot.Version) {
		t.Errorf("the scan field and the derivation sentence name different runs:\nfield: %+v\nsaid:  %s", run.Scan, said)
	}

	if run.Reachability.Verdicts != 4 || run.Reachability.SourceReadByThisRun {
		t.Errorf("reachability_basis = %+v, want 4 verdicts resting on source this run did not read", run.Reachability)
	}
	if _, ok := fields["reachability_basis"]; !ok {
		t.Error("reachability_basis is not a key of the document: it is the fact this surface was opened for")
	}
}

// TestAuditRunFactsStateADerivedRun is the control, and it is what shows the
// fields track the run rather than being constants.
//
// It also holds the one thing the sentence does NOT say: a scan derived by this
// run states "derived by this run" and names no id, so the run a --json caller
// just paid for was unnameable. The field carries it on both arms.
func TestAuditRunFactsStateADerivedRun(t *testing.T) {
	facts := vulnScanRunFacts{
		RunID:        "vscan-01KZ0AVM2897N6J6YE4GABYG27-1754107500",
		Snapshot:     vulnScanSnapshotOf(vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z")),
		Reachability: vulnScanReachability{Verdicts: 7, SourceReadByThisRun: true},
	}
	d := auditDerivation{walkRecord: auditWalkForFacts(), scanFacts: facts}
	run := newAuditRunJSON(d, nil, time.Hour, time.Now())

	if !run.Walk.Resolved || run.Walk.Reused {
		t.Errorf("walk = %+v, want a walk this run derived", run.Walk)
	}
	if !run.Scan.Answered || run.Scan.Reused || run.Scan.RunID != facts.RunID {
		t.Errorf("scan = %+v, want the run this invocation wrote, %s", run.Scan, facts.RunID)
	}
	if run.Scan.Snapshot != facts.Snapshot {
		t.Errorf("scan.snapshot = %+v, want %+v", run.Scan.Snapshot, facts.Snapshot)
	}
	if run.Reachability != facts.Reachability {
		t.Errorf("reachability_basis = %+v, want the count that run took, %+v", run.Reachability, facts.Reachability)
	}

	var sentence bytes.Buffer
	if err := writeAuditDerivation(&sentence, d); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sentence.String(), facts.RunID) {
		t.Errorf("the derivation sentence now names the scan run id; this test's premise — that the field "+
			"carries what the prose does not — needs re-measuring:\n%s", sentence.String())
	}
}

// TestAuditRunFactsNeverOmitAnUnmeasuredAxis is the rule the toolchain axis
// already follows on `vuln-scan`, applied to the whole run-level half.
//
// An audit that resolved nothing took no walk, ran no scan and judged no
// toolchain. Leaving those keys out would make "not measured" and "nothing to
// report" the same document, which is the one thing an unmeasured axis does not
// mean — so every key is present, and each says so in a value.
func TestAuditRunFactsNeverOmitAnUnmeasuredAxis(t *testing.T) {
	fields := auditRunFields(t, unauditedRunJSON())
	for _, key := range []string{"walk", "scan", "reachability_basis", "toolchain", "staleness"} {
		if _, ok := fields[key]; !ok {
			t.Errorf("a run that audited nothing omits %q; an absent key reads as nothing to report", key)
		}
	}

	run := unauditedRunJSON()
	if run.Walk.Resolved || run.Scan.Answered || run.Staleness.Measured {
		t.Errorf("an unaudited run claims to have measured something: %+v", run)
	}
	if run.Toolchain.Judged || run.Toolchain.Status != string(vulndomain.ToolchainUnjudged) {
		t.Errorf("toolchain = %+v, want the unjudged section", run.Toolchain)
	}
	if run.Toolchain.Reason == "" {
		t.Error("the unjudged toolchain names no reason: a judgment that was not made must say what stopped it")
	}
	// The arrays are arrays, not null, for the reason the vuln-scan section is:
	// an empty list says none covered it, where null says nothing.
	if run.Toolchain.Covering == nil || run.Toolchain.WithdrawnCovering == nil {
		t.Errorf("toolchain advisory lists are null rather than empty: %+v", run.Toolchain)
	}
}

// TestAuditStalenessFieldAndFooterDateOneColumn holds the two renderings of the
// staleness date to one measurement.
//
// The footer is on STDOUT in the text form and had no counterpart in the
// document at all. It is the run-level statement "this is how current the whole
// column is", and it is dated by the OLDEST lookup behind the column — so a
// field taken from any other row would be a second, more flattering answer.
func TestAuditStalenessFieldAndFooterDateOneColumn(t *testing.T) {
	oldest := time.Date(2026, 8, 2, 3, 0, 0, 0, time.UTC)
	results := []auditModuleResult{
		{Coordinate: "example.com/a@v1.0.0", StalenessLookedUpAt: time.Date(2026, 8, 2, 5, 0, 0, 0, time.UTC)},
		{Coordinate: "example.com/b@v1.0.0", StalenessLookedUpAt: oldest},
		{Coordinate: "example.com/c@v1.0.0"},
	}
	now := oldest.Add(90 * time.Minute)
	st := auditStalenessOf(results, time.Hour, now)

	if !st.Measured {
		t.Fatalf("staleness = %+v, want a measured column", st)
	}
	if want := oldest.Format(time.RFC3339); st.AsOf != want {
		t.Errorf("staleness.as_of = %q, want the OLDEST lookup %q — the newest would date the column "+
			"more favourably than any row supports", st.AsOf, want)
	}
	if st.Age != "1h30m0s" {
		t.Errorf("staleness.age = %q, want 1h30m0s", st.Age)
	}
	if st.TTL != "1h0m0s" {
		t.Errorf("staleness.ttl = %q, want the TTL in force in the same units as the age beside it", st.TTL)
	}
	if st.RefreshWith != stalenessRefreshCommand {
		t.Errorf("staleness.refresh_with = %q, want %q", st.RefreshWith, stalenessRefreshCommand)
	}

	// The footer the person reads is dated from the same helper, so the two
	// cannot name different lookups.
	var table bytes.Buffer
	if err := printAuditTable(&table, results); err != nil {
		t.Fatal(err)
	}
	if asOf := stalenessAsOf(oldest); !strings.Contains(table.String(), asOf) {
		t.Errorf("the footer does not carry %q:\n%s", asOf, table.String())
	}
	if !strings.Contains(table.String(), stalenessRefreshCommand) {
		t.Errorf("the footer offers a different remedy than the field:\n%s", table.String())
	}

	// No lookup at all is the unmeasured value, never a fabricated date.
	if empty := auditStalenessOf(results[2:], time.Hour, now); empty.Measured || empty.AsOf != "" {
		t.Errorf("a column with no lookup reports %+v, want the unmeasured value", empty)
	}
}

// TestAuditOutputCarriesTheRunBesideTheRows is the shape assertion: the run
// facts are keys of the envelope the rows are framed in, not a nested object a
// consumer has to know to open, and the rows are untouched.
func TestAuditOutputCarriesTheRunBesideTheRows(t *testing.T) {
	d := auditDerivation{
		walkReused: true, walkRecord: auditWalkForFacts(),
		scanReused: true, scanRun: reusedRunForBasis(),
		toolchain: vulndomain.ToolchainJudgment{
			Version: "go1.26.5", Status: vulndomain.ToolchainClear,
			Snapshot: vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z"),
		},
	}
	out := newAuditOutput(unscopedEnvelope(1), newAuditRunJSON(d, nil, time.Hour, time.Now()),
		[]auditModuleResult{{Coordinate: "example.com/a@v1.0.0"}})
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"dependency_scope", "module_count", "walk", "scan",
		"reachability_basis", "toolchain", "staleness", "modules"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("audit --json omits the top-level key %q: %s", key, raw)
		}
	}
	// The toolchain key is vuln-scan's own section, so it carries the version and
	// the sentence rather than a second rendering invented here.
	if !strings.Contains(string(doc["toolchain"]), "go1.26.5") {
		t.Errorf("the toolchain section names no version: %s", doc["toolchain"])
	}
	if !strings.Contains(string(doc["toolchain"]), "statement") {
		t.Errorf("the toolchain section carries no statement, so the document and the screen no longer "+
			"say the same thing in the same words: %s", doc["toolchain"])
	}
}
