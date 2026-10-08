package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// confirmingSearcher stands in for the call-graph search: it attaches a clean
// search over a graph built with bodies to every live negative, which is what
// raises a govulncheck silence to confirmed.
type confirmingSearcher struct {
	records int
}

func (s *confirmingSearcher) Search(_ context.Context, rec *vuldomain.VulnerabilityRecord) {
	s.records++
	for i := range rec.Findings {
		f := &rec.Findings[i]
		if f.Reachable != nil && !f.Reachable.IsReachable && !f.IsWithdrawn() {
			f.NegativeSearch = &vuldomain.NegativeSearch{EntryPointRoots: 3, Fidelity: "BUILT_WITH_BODIES"}
		}
	}
}

// freshScanRollups is what a scan's Progress callback leaves behind: one module
// with a govulncheck negative and one whose only advisory was retracted.
func freshScanRollups() *vulnScanRollups {
	r := newVulnScanRollups()
	neg := negativeRecord(vuldomain.AnalyserGovulncheck, "source")
	r.add(neg.Coordinate, neg)
	wd := withdrawnBboltRecord()
	r.add(wd.Coordinate, wd)
	return r
}

func renderFreshScan(t *testing.T, searcher negativeSearcher, jsonOut bool) string {
	t.Helper()
	var out bytes.Buffer
	if err := printFreshScanResult(t.Context(), searcher, vuldomain.WalkScanRun{ID: "run-1"}, freshScanRollups(),
		vulnScanReachability{}, vulnScanToolchainJSON{}, nil, jsonOut, &out); err != nil {
		t.Fatalf("printFreshScanResult: %v", err)
	}
	return out.String()
}

// TestFreshScanReport_StatesTheSearchedRung: a fresh scan prints records the
// store has not served, so unless it searches them itself it states the
// pre-search rung while every later read of the same records states the
// searched one.
func TestFreshScanReport_StatesTheSearchedRung(t *testing.T) {
	var unsearchedText bytes.Buffer
	plain := freshScanRollups()
	if err := printVulnScanResult(vuldomain.WalkScanRun{ID: "run-1"}, plain.affected, plain.withdrawn, plain.failed, plain.unscannable,
		vulnScanReachability{}, vulnScanToolchainJSON{}, nil, false, &unsearchedText); err != nil {
		t.Fatalf("printVulnScanResult: %v", err)
	}
	// Control: without a search the negative reads the silence it was stamped from.
	if !strings.Contains(unsearchedText.String(), "GO-2025-3487 [not reachable in call graph — inferred]") {
		t.Fatalf("control: the unsearched negative is not labelled inferred:\n%s", unsearchedText.String())
	}

	searcher := &confirmingSearcher{}
	text := renderFreshScan(t, searcher, false)
	if !strings.Contains(text, "GO-2025-3487 [not reachable in call graph — confirmed]") {
		t.Errorf("the fresh scan does not state the searched rung:\n%s", text)
	}
	if strings.Contains(text, "inferred") {
		t.Errorf("the fresh scan still states the pre-search rung:\n%s", text)
	}
	// Both findings roll-ups go through the search, as both do on the read seam.
	if searcher.records != 2 {
		t.Errorf("searched %d records, want 2 (the affected and the withdrawn module)", searcher.records)
	}
	// The retraction line is untouched by a search.
	if !strings.Contains(text, "GO-2026-4923: retracted upstream 2026-04-08T13:33:56Z") {
		t.Errorf("the withdrawn advisory lost its line:\n%s", text)
	}
}

// TestFreshScanReport_NilSearcherLeavesOutputUnchanged: no searcher means the
// report is exactly the one printed before the search existed.
func TestFreshScanReport_NilSearcherLeavesOutputUnchanged(t *testing.T) {
	for _, jsonOut := range []bool{false, true} {
		var want bytes.Buffer
		plain := freshScanRollups()
		if err := printVulnScanResult(vuldomain.WalkScanRun{ID: "run-1"}, plain.affected, plain.withdrawn, plain.failed, plain.unscannable,
			vulnScanReachability{}, vulnScanToolchainJSON{}, nil, jsonOut, &want); err != nil {
			t.Fatalf("printVulnScanResult: %v", err)
		}
		if got := renderFreshScan(t, nil, jsonOut); got != want.String() {
			t.Errorf("json=%v: a nil searcher changed the report:\n got: %s\nwant: %s", jsonOut, got, want.String())
		}
	}
}

// TestFreshScanReport_JSONCarriesNoFindings pins why the search cannot move the
// fresh scan's --json: that document is the run record and its counts, and
// names no finding, so it has no rung to state either way.
func TestFreshScanReport_JSONCarriesNoFindings(t *testing.T) {
	searched := renderFreshScan(t, &confirmingSearcher{}, true)
	unsearched := renderFreshScan(t, nil, true)
	if !strings.Contains(searched, `"run-1"`) {
		t.Fatalf("control: the document does not carry the run:\n%s", searched)
	}
	if strings.Contains(searched, "GO-2025-3487") || strings.Contains(searched, "soundness") {
		t.Errorf("the fresh scan's document now carries findings; it must carry the searched rung:\n%s", searched)
	}
	if searched != unsearched {
		t.Errorf("the search changed a document that names no finding:\n searched: %s\nunsearched: %s", searched, unsearched)
	}
}

// TestScanShowText_LabelsEachFinding: vuln-scan-show's text names each finding
// with the reachability label the scan prints, read through the searched seam,
// so the two text surfaces state one rung for one stored finding.
func TestScanShowText_LabelsEachFinding(t *testing.T) {
	neg := negativeRecord(vuldomain.AnalyserGovulncheck, "source")
	neg.ContentHash = "h-neg"
	reachable := vuldomain.VulnerabilityFinding{
		ID:              "GO-2025-0001",
		AffectedSymbols: []string{"golang.org/x/crypto/ssh.Dial"},
		Reachable:       &vuldomain.ReachabilityResult{IsReachable: true, Confidence: vuldomain.ConfidenceHigh},
	}
	retracted := withdrawnBboltRecord().Findings[0]
	neg.Findings = append(neg.Findings, reachable, retracted)
	wd := withdrawnBboltRecord()
	wd.ContentHash = "h-wd"

	inner := testfakes.NewFakeQueryVuln()
	inner.AddRecord(neg.Coordinate, neg)
	inner.AddRecord(wd.Coordinate, wd)
	run := vuldomain.WalkScanRun{PerModuleResults: map[coordinate.ModuleCoordinate]string{
		neg.Coordinate: "h-neg", wd.Coordinate: "h-wd",
	}}

	render := func(uc QueryVulnUseCase) string {
		summary := buildScanAffectedModules(t.Context(), run, uc, nil)
		var out bytes.Buffer
		writeScanModuleFindings(&out, "Affected modules", summary.affected)
		writeScanModuleFindings(&out, "Withdrawn advisories, not counted as findings", summary.withdrawn)
		return out.String()
	}

	// Control: the same records read unsearched carry the pre-search rung, so the
	// label below is the search's doing and not a fixture that was already confirmed.
	if got := render(inner); !strings.Contains(got, "    GO-2025-3487 [not reachable in call graph — inferred]\n") {
		t.Fatalf("control: unsearched negative not labelled inferred:\n%s", got)
	}

	got := render(newSearchedVulnQuery(inner, &confirmingSearcher{}))
	for _, want := range []string{
		"  golang.org/x/crypto@v0.31.0\n",
		"    GO-2025-3487 [not reachable in call graph — confirmed]\n",
		"    GO-2025-0001 [reachable]\n",
		"    GO-2026-4923 (withdrawn 2026-04-08T13:33:56Z)\n",
		"  go.etcd.io/bbolt@v1.4.3\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// A retracted advisory carries no reachability tag: reachability is not the
	// lever for an advisory that no longer stands.
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "GO-2026-4923") && strings.Contains(line, "[") {
			t.Errorf("withdrawn finding carries a reachability tag: %q", line)
		}
	}
	if n := strings.Count(got, "GO-2026-4923"); n != 2 {
		t.Errorf("the retracted advisory appears %d times, want 2 (once per module holding it):\n%s", n, got)
	}
}
