package cli

import (
	"bytes"
	"strings"
	"testing"

	vuldomain "code.eitanity.com/kanonarion/internal/vuln/domain"
)

const unscannableNote = "source analysis unavailable: requires a module version outside the analysed project toolchain"

func unscannableRecord(f vuldomain.VulnerabilityFinding) vuldomain.VulnerabilityRecord {
	return vuldomain.VulnerabilityRecord{
		Coordinate:        reachCoord,
		OverallStatus:     vuldomain.StatusAffected,
		CoverageStatus:    vuldomain.CoverageUnscannable,
		FindingsStatus:    vuldomain.FindingsRecordAffected,
		UnscanReason:      vuldomain.UnscanReasonVersionNotInToolchain,
		UnscannableReason: unscannableNote,
		Rooting:           vuldomain.RootingIsolated,
		Findings:          []vuldomain.VulnerabilityFinding{f},
	}
}

func callGraphFinding(reachable bool) vuldomain.VulnerabilityFinding {
	return vuldomain.VulnerabilityFinding{
		ID:              "GO-2021-0113",
		AffectedSymbols: []string{"Parse"},
		Reachable: &vuldomain.ReachabilityResult{
			IsReachable: reachable, Confidence: vuldomain.ConfidenceHigh,
			DerivedBy: vuldomain.ReachabilityDerivation{
				Analyser: vuldomain.AnalyserCallGraphBFS, Fidelity: "BUILT_WITH_BODIES",
				GraphPipeline: "0.10.0", Rooting: vuldomain.RootingIsolated,
			},
		},
	}
}

// An Unscannable record whose finding the call graph answered is served, with
// the coverage gap and the graph's derivation on both surfaces.
func TestVulnReachability_UnscannableRecordServesTheCallGraphAnswer(t *testing.T) {
	res, err := vulnReachabilityAnswer(reachCoord, unscannableRecord(callGraphFinding(true)), true, "GO-2021-0113", nil, nil)
	if err != nil {
		t.Fatalf("answer refused: %v", err)
	}
	if res.ReachabilityState != verdictReachable || res.Method != string(vuldomain.AnalyserCallGraphBFS) {
		t.Errorf("answer = %s by %s, want reachable by callgraph-bfs", res.ReachabilityState, res.Method)
	}
	doc := decodeAnswer(t, res)
	for key, want := range map[string]string{
		"coverage_status": "Unscannable", "unscannable_reason": unscannableNote,
		"fidelity": "BUILT_WITH_BODIES", "graph_pipeline": "0.10.0", "method": "callgraph-bfs",
	} {
		if doc[key] != want {
			t.Errorf("%s = %v, want %q", key, doc[key], want)
		}
	}
	var buf bytes.Buffer
	printVulnReachability(&buf, res)
	for _, want := range []string{"by: callgraph-bfs", "fidelity: BUILT_WITH_BODIES", "call-graph pipeline: 0.10.0", "coverage: Unscannable", "call graph alone"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("text lacks %q:\n%s", want, buf.String())
		}
	}
}

// The other two Unscannable shapes: no answer at all keeps the coverage
// refusal, and a failed attempt names its reason.
func TestVulnReachability_UnscannableRecordWithoutAnAnswer(t *testing.T) {
	noAnswer := vuldomain.VulnerabilityFinding{ID: "GO-2021-0113", AffectedSymbols: []string{"Parse"}}
	if _, err := vulnReachabilityAnswer(reachCoord, unscannableRecord(noAnswer), true, "GO-2021-0113", nil, nil); err == nil ||
		!strings.Contains(err.Error(), "is unscannable") {
		t.Errorf("err = %v, want the unscannable refusal", err)
	}
	failed := noAnswer
	failed.ReachabilityNote = "callgraph subprocess failed: exit status 2"
	if _, err := vulnReachabilityAnswer(reachCoord, unscannableRecord(failed), true, "GO-2021-0113", nil, nil); err == nil ||
		!strings.Contains(err.Error(), "callgraph subprocess failed") {
		t.Errorf("err = %v, want the failed attempt's note", err)
	}
}

// An analysed record's answer carries no coverage keys, so its bytes do not move.
func TestVulnReachability_AnalysedRecordCarriesNoCoverageKeys(t *testing.T) {
	rec := unscannableRecord(callGraphFinding(false))
	rec.CoverageStatus, rec.UnscanReason, rec.UnscannableReason = vuldomain.CoverageAnalysed, "", ""
	res, err := vulnReachabilityAnswer(reachCoord, rec, true, "GO-2021-0113", nil, nil)
	if err != nil {
		t.Fatalf("answer refused: %v", err)
	}
	doc := decodeAnswer(t, res)
	for _, key := range []string{"coverage_status", "unscannable_reason"} {
		if _, ok := doc[key]; ok {
			t.Errorf("%s present on an analysed record", key)
		}
	}
}
