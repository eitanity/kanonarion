package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// reusedRunForBasis is the run every case here reuses: one completed scan,
// against a named snapshot.
func reusedRunForBasis() vulndomain.WalkScanRun {
	return vulndomain.WalkScanRun{
		ID:              "vscan-01KZ0AVM2897N6J6YE4GABYG27-1754107449",
		WalkID:          "01KZ0AVM2897N6J6YE4GABYG27",
		Snapshot:        vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z"),
		CompletedAt:     time.Date(2026, 8, 2, 4, 14, 9, 0, time.UTC),
		CoverageStatus:  vulndomain.CoverageComplete,
		FindingsStatus:  vulndomain.FindingsAffected,
		PipelineVersion: vulnapp.PipelineVersion,
	}
}

// recordWithReachability is a record whose finding carries a reachability
// answer — the half of a scan computed from the project's own source.
func recordWithReachability(t *testing.T, path string) vulndomain.VulnerabilityRecord {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate(path, "v1.2.0")
	if err != nil {
		t.Fatalf("building coordinate %s: %v", path, err)
	}
	return vulndomain.VulnerabilityRecord{
		Coordinate: coord,
		WalkID:     "01KZ0AVM2897N6J6YE4GABYG27",
		Findings: []vulndomain.VulnerabilityFinding{{
			ID:        "GO-2026-0001",
			Summary:   "a finding whose reachability was answered from source",
			Reachable: &vulndomain.ReachabilityResult{IsReachable: true, Confidence: vulndomain.ConfidenceHigh},
		}},
	}
}

// TestReusedScanLine_StatesWhatTheReachabilityLegWasComputedAgainst is the
// headline. Which advisories apply is fixed by the module versions the walk
// resolved, so reuse is sound there; reachability is computed from the
// project's own source, which the reuse key does not consider. The line has to
// say so, because nothing else in the output does.
//
// Run against the code before the change, this fails: the line named the run,
// the date and the snapshot, and said nothing about source.
func TestReusedScanLine_StatesWhatTheReachabilityLegWasComputedAgainst(t *testing.T) {
	got := reusedScanLine(reusedRunForBasis(), 4)

	for _, want := range []string{
		"vscan-01KZ0AVM2897N6J6YE4GABYG27-1754107449",
		"2026-08-02T04:14:09Z",
		"vuln.go.dev@2026-07-27T20:14:16Z",
		"4 reachability answers",
		"the source that run read",
		"this run did not re-read",
		"--force",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the reuse line does not state %q:\n%s", want, got)
		}
	}

	// The line must not claim an identity nothing measured. The call-graph line
	// may say the tree is unchanged because it re-reads and compares; this run
	// never opened the source.
	for _, forbidden := range []string{"identical", "unchanged", "re-read the working tree"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("the reuse line claims %q, which this run did not measure:\n%s", forbidden, got)
		}
	}
}

// A run that answered no reachability question has nothing for the statement to
// qualify, and must not be handed a caveat about a verdict it never gave.
func TestReusedScanLine_SaysNothingAboutReachabilityWhenTheRunGaveNoVerdict(t *testing.T) {
	got := reusedScanLine(reusedRunForBasis(), 0)

	if strings.Contains(got, "reachab") {
		t.Errorf("a run with no reachability verdict was given a reachability caveat:\n%s", got)
	}
	// It is still a reuse statement, and still names the remedy.
	for _, want := range []string{"nothing was re-scanned", "--force to re-measure"} {
		if !strings.Contains(got, want) {
			t.Errorf("the reuse line no longer states %q:\n%s", want, got)
		}
	}
}

// The count is of ANSWERS, not of findings. A nil Reachable means reachability
// was not computed for that finding, and counting it would put a source caveat
// on a run whose answer does not rest on source.
func TestReachabilityVerdicts_CountsAnsweredFindingsOnly(t *testing.T) {
	answered := recordWithReachability(t, "example.com/mod")
	unanswered := recordWithReachability(t, "example.com/other")
	unanswered.Findings[0].Reachable = nil

	if n := reachabilityVerdicts([]vulndomain.VulnerabilityRecord{answered, unanswered}); n != 1 {
		t.Errorf("counted %d reachability verdicts over one answered and one unanswered finding, want 1", n)
	}
	if n := reachabilityVerdicts(nil); n != 0 {
		t.Errorf("counted %d reachability verdicts over no records, want 0", n)
	}
}

// audit's derivation block carries the same sentence, and its non-zero control
// is beside it: a scan this run derived says so, with no source caveat, because
// this run is the one that read the source.
func TestAuditDerivation_StatesTheSourceBasisOfAReusedScan(t *testing.T) {
	run := reusedRunForBasis()

	var reused bytes.Buffer
	if err := writeAuditDerivation(&reused, auditDerivation{
		walkRecord:               walkdomain.WalkRecord{ID: run.WalkID},
		scanReused:               true,
		scanRun:                  run,
		scanReachabilityVerdicts: 2,
	}); err != nil {
		t.Fatalf("writeAuditDerivation: %v", err)
	}
	if !strings.Contains(reused.String(), reusedScanLine(run, 2)) {
		t.Errorf("audit's derivation does not carry the shared reuse sentence:\n%s", reused.String())
	}

	var derived bytes.Buffer
	if err := writeAuditDerivation(&derived, auditDerivation{
		walkRecord: walkdomain.WalkRecord{ID: run.WalkID},
	}); err != nil {
		t.Fatalf("writeAuditDerivation: %v", err)
	}
	if got := derived.String(); !strings.Contains(got, "vulnerability scan: derived by this run") || strings.Contains(got, "reachab") {
		t.Errorf("a scan derived by this run gained a reuse caveat:\n%s", got)
	}
}

// One fact, one sentence, both surfaces. `vuln-scan` announcing the reuse in
// wording of its own is how the two come to disagree, so the announcement is
// asserted to be the exact string audit's derivation block carries.
func TestServeStoredScanRun_AnnouncesTheSharedReuseSentence(t *testing.T) {
	run := reusedRunForBasis()
	scan := &testfakes.FakeScanWalk{}
	qv := testfakes.NewFakeQueryVuln()
	qv.SetRunRecords(run.ID, []vulndomain.VulnerabilityRecord{recordWithReachability(t, "example.com/mod")})
	walks := testfakes.NewFakeQueryWalks()
	ctr := &Container{ScanWalk: scan, QueryVuln: qv, QueryWalks: walks}

	var stdout, stderr bytes.Buffer
	if _, err := serveStoredScanRun(t.Context(), run, ctr, false, true, false, vulnapp.ServeSurfaceVulnScan, &stdout, &stderr); err != nil {
		t.Fatalf("serveStoredScanRun: %v", err)
	}

	want := reusedScanLine(run, 1)
	if !strings.Contains(stderr.String(), want) {
		t.Errorf("the announcement is not the shared sentence.\nwant to contain: %s\ngot:\n%s", want, stderr.String())
	}
}

// The JSON surface owes the same fact as data: an agent cannot read the stderr
// sentence. The run's own keys stay where they were — the addition is one key
// beside them, not a new envelope around them.
func TestVulnScanJSON_CarriesTheReachabilityBasis(t *testing.T) {
	run := reusedRunForBasis()

	var served bytes.Buffer
	if err := printVulnScanResult(run, nil, nil, nil, nil,
		vulnScanReachability{Answers: 3}, vulnScanToolchainJSON{}, true, &served); err != nil {
		t.Fatalf("printVulnScanResult: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(served.Bytes(), &doc); err != nil {
		t.Fatalf("decoding the served document: %v\n%s", err, served.String())
	}
	if doc["id"] != run.ID {
		t.Errorf("the run's own keys moved: id=%v, want %q", doc["id"], run.ID)
	}
	basis, ok := doc["reachability_basis"].(map[string]any)
	if !ok {
		t.Fatalf("the document carries no reachability_basis:\n%s", served.String())
	}
	if basis["answers"] != float64(3) {
		t.Errorf("reachability_basis.answers = %v, want 3", basis["answers"])
	}
	if basis["source_read_by_this_run"] != false {
		t.Errorf("a served run reports source_read_by_this_run = %v, want false", basis["source_read_by_this_run"])
	}

	// Emitted always, not only on a reused run: a consumer reads one key rather
	// than inferring the fact from a key's absence.
	var fresh bytes.Buffer
	if err := printVulnScanResult(run, nil, nil, nil, nil,
		vulnScanReachability{Answers: 3, SourceReadByThisRun: true}, vulnScanToolchainJSON{}, true, &fresh); err != nil {
		t.Fatalf("printVulnScanResult: %v", err)
	}
	if err := json.Unmarshal(fresh.Bytes(), &doc); err != nil {
		t.Fatalf("decoding the fresh document: %v", err)
	}
	if basis, _ := doc["reachability_basis"].(map[string]any); basis["source_read_by_this_run"] != true {
		t.Errorf("a run that measured for itself reports source_read_by_this_run = %v, want true", basis["source_read_by_this_run"])
	}
}
