package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	coordinatetest "github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

var displayWithdrawnAt = time.Date(2026, 4, 8, 13, 33, 56, 0, time.UTC)

// withdrawnBboltRecord is the record a v16 scan produces for the coordinate that
// caused the false finding: analysed, carrying the retracted advisory, reporting
// Withdrawn on the findings axis and in the summary word.
func withdrawnBboltRecord() vuldomain.VulnerabilityRecord {
	return vuldomain.VulnerabilityRecord{
		Coordinate:     coordinatetest.MustNew("go.etcd.io/bbolt", "v1.4.3"),
		WalkID:         "walk-1",
		OverallStatus:  vuldomain.StatusWithdrawn,
		CoverageStatus: vuldomain.CoverageAnalysed,
		FindingsStatus: vuldomain.FindingsRecordWithdrawn,
		ScannedAt:      time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC),
		Findings: []vuldomain.VulnerabilityFinding{{
			ID:            "GO-2026-4923",
			Aliases:       []string{"CVE-2026-33817", "GHSA-6jwv-w5xf-7j27"},
			Summary:       "WITHDRAWN: out-of-range-index in go.etcd.io/bbolt",
			AffectedRange: ">= v1.4.0",
			WithdrawnAt:   displayWithdrawnAt,
			Reachable:     &vuldomain.ReachabilityResult{IsReachable: false, Confidence: vuldomain.ConfidenceHigh},
		}},
	}
}

// TestPrintVulnRecord_NamesTheRetractionAndItsDate covers the `vuln` / `vuln-show`
// output. Before the fix the same coordinate printed "Clean / No findings", and
// after the coordinate-matching change it printed a bare Affected verdict; neither
// said the advisory had been retracted. The word WITHDRAWN did appear, echoed from
// the upstream summary, which is why the test asserts the date too: the summary
// prefix is prose kanonarion happens to pass through, and asserting only the word
// would pass on the unfixed tree.
func TestPrintVulnRecord_NamesTheRetractionAndItsDate(t *testing.T) {
	var out bytes.Buffer
	printVulnRecord(&out, withdrawnBboltRecord(), nil)
	got := out.String()

	if !strings.Contains(got, "go.etcd.io/bbolt@v1.4.3 — Withdrawn") {
		t.Errorf("status line does not report Withdrawn:\n%s", got)
	}
	if !strings.Contains(got, "retracted upstream 2026-04-08T13:33:56Z") {
		t.Errorf("output does not carry the retraction date:\n%s", got)
	}
	if !strings.Contains(got, "not a finding against this module") {
		t.Errorf("output does not say the advisory no longer counts against the module:\n%s", got)
	}
	// The finding stays listed — it is the historical fact — so "No findings" must
	// not appear beside it.
	if strings.Contains(got, "No findings") {
		t.Errorf("output claims no findings for a record carrying a retracted advisory:\n%s", got)
	}
	if !strings.Contains(got, "GO-2026-4923") {
		t.Errorf("the retracted advisory was dropped from the output:\n%s", got)
	}
}

// TestBuildScanAffectedModules_WithdrawnIsItsOwnSection covers `vuln-scan-show`.
// A withdrawn module must be out of the affected list — that is the false positive
// removed — and must not thereby vanish from the report, which would restore the
// silence in a different place.
func TestBuildScanAffectedModules_WithdrawnIsItsOwnSection(t *testing.T) {
	rec := withdrawnBboltRecord()
	// The run names this record by its hash: the report is read by that identity,
	// never by re-resolving the coordinate.
	rec.ContentHash = "h1"
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecord(rec.Coordinate, rec)

	run := vuldomain.WalkScanRun{
		PerModuleResults: map[coordinate.ModuleCoordinate]string{rec.Coordinate: "h1"},
	}
	summary := buildScanAffectedModules(t.Context(), run, uc, nil)

	if len(summary.affected) != 0 {
		t.Errorf("affected = %+v, want empty: a retracted advisory is not an affected verdict", summary.affected)
	}
	if len(summary.withdrawn) != 1 || summary.withdrawn[0].Coordinate != rec.Coordinate.String() {
		t.Fatalf("withdrawn = %+v, want the module named", summary.withdrawn)
	}

	var out bytes.Buffer
	writeScanModuleFindings(&out, "Withdrawn advisories, not counted as findings", summary.withdrawn)
	if got := out.String(); !strings.Contains(got, "GO-2026-4923 (withdrawn 2026-04-08T13:33:56Z)") {
		t.Errorf("section does not carry the advisory and its retraction date:\n%s", got)
	}
}

// TestPrintVulnScanResult_WithdrawnIsOutOfTheFindingsCountButInTheReport is the
// `vuln-scan` summary. The affected count is what a reader acts on, so the
// retraction must leave it; the report is what a reader reads, so the retraction
// must not leave that.
func TestPrintVulnScanResult_WithdrawnIsOutOfTheFindingsCountButInTheReport(t *testing.T) {
	rec := withdrawnBboltRecord()
	withdrawn := []vulnScanAffected{{coord: rec.Coordinate.String(), record: rec}}

	var out bytes.Buffer
	if err := printVulnScanResult(vuldomain.WalkScanRun{ID: "run-1"}, nil, withdrawn, nil, nil, vulnScanReachability{}, false, &out); err != nil {
		t.Fatalf("printVulnScanResult: %v", err)
	}
	got := out.String()
	if strings.Contains(got, "Findings (") {
		t.Errorf("a retracted advisory was counted as a finding:\n%s", got)
	}
	if !strings.Contains(got, "Withdrawn advisories (1, not counted as findings)") {
		t.Errorf("the withdrawn roll-up is missing:\n%s", got)
	}
	if !strings.Contains(got, "GO-2026-4923: retracted upstream 2026-04-08T13:33:56Z") {
		t.Errorf("the roll-up does not name the advisory and its date:\n%s", got)
	}
	// No fix or reachability line: neither applies to an advisory that no longer
	// stands, and printing them would invite acting on them.
	if strings.Contains(got, "not reachable") {
		t.Errorf("the roll-up offers reachability as though it mattered here:\n%s", got)
	}
}

// TestVulnScanStatusLabel_WithdrawnUnderACoverageGap keeps the findings answer in
// front of the coverage caveat for the withdrawal, exactly as it is for a live
// match. Dropping to the bare coverage label would hide the transition on the
// per-module progress line.
func TestVulnScanStatusLabel_WithdrawnUnderACoverageGap(t *testing.T) {
	rec := withdrawnBboltRecord()
	rec.OverallStatus = vuldomain.StatusWithdrawn
	rec.CoverageStatus = vuldomain.CoverageUnscannable
	rec.UnscanReason = vuldomain.UnscanReasonVersionNotInToolchain
	rec.UnscannableReason = "metadata-only"

	got := vulnScanStatusLabel(rec)
	if !strings.HasPrefix(got, string(vuldomain.StatusWithdrawn)+" — ") {
		t.Errorf("label = %q, want it to lead with %q", got, vuldomain.StatusWithdrawn)
	}
}

// TestVulnReachabilityVerdict_WithdrawnIsNotAReachabilityAnswer pins the ticket
// comment's point: reachability is not the mitigation for a retracted advisory.
// Answering "not reachable" would offer one, inviting the reader to conclude the
// module would be at risk if something called it.
func TestVulnReachabilityVerdict_WithdrawnIsNotAReachabilityAnswer(t *testing.T) {
	rec := withdrawnBboltRecord()

	q, err := vulnReachabilityVerdict(rec.Coordinate, rec, true, "GO-2026-4923", nil, nil)
	if err != nil {
		t.Fatalf("vulnReachabilityVerdict: %v", err)
	}
	if q.Verdict != verdictWithdrawn {
		t.Errorf("verdict = %q, want %q", q.Verdict, verdictWithdrawn)
	}
	if q.WithdrawnAt != "2026-04-08T13:33:56Z" {
		t.Errorf("WithdrawnAt = %q, want the retraction date", q.WithdrawnAt)
	}

	var out bytes.Buffer
	printVulnReachability(&out, q)
	if got := out.String(); !strings.Contains(got, "WITHDRAWN upstream 2026-04-08T13:33:56Z") {
		t.Errorf("rendered verdict does not state the retraction:\n%s", got)
	}
}
