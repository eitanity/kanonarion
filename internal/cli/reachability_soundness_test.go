package cli

import (
	"bytes"
	"strings"
	"testing"

	coordinatetest "github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// negativeRecord is a stored not-reachable answer of exactly the shape a working
// store holds: no route, ConfidenceHigh, and a derivation naming the analyser
// and the fidelity it saw at.
func negativeRecord(analyser vuldomain.ReachabilityAnalyser, fidelity string) vuldomain.VulnerabilityRecord {
	return vuldomain.VulnerabilityRecord{
		Coordinate:     coordinatetest.MustNew("golang.org/x/crypto", "v0.31.0"),
		Rooting:        vuldomain.TargetRootedAt(coordinatetest.MustNew("example.com/app", "local")),
		OverallStatus:  vuldomain.StatusAffected,
		CoverageStatus: vuldomain.CoverageAnalysed,
		FindingsStatus: vuldomain.FindingsRecordAffected,
		Findings: []vuldomain.VulnerabilityFinding{{
			ID:              "GO-2025-3487",
			Summary:         "a flaw",
			AffectedSymbols: []string{"golang.org/x/crypto/ssh.Handshake"},
			Reachable: &vuldomain.ReachabilityResult{
				IsReachable: false,
				Confidence:  vuldomain.ConfidenceHigh,
				DerivedBy: vuldomain.ReachabilityDerivation{
					Analyser: analyser,
					Fidelity: fidelity,
				},
			},
		}},
	}
}

// TestNotReachableStatesItsSoundness is the ticket's observable. Three negatives
// that are byte-identical apart from the analyser and its fidelity — and which
// all read "confidence: High" — must now render three distinguishable answers,
// and only the one backed by a built call graph may read as a clean negative.
func TestNotReachableStatesItsSoundness(t *testing.T) {
	cases := []struct {
		name       string
		analyser   vuldomain.ReachabilityAnalyser
		fidelity   string
		wantSound  vuldomain.ReachabilitySoundness
		wantReason string
	}{
		{"govulncheck source", vuldomain.AnalyserGovulncheck, "source", vuldomain.SoundnessInferred, "silence"},
		{"govulncheck binary", vuldomain.AnalyserGovulncheck, "binary", vuldomain.SoundnessUnconfirmed, "symbol table"},
		{"built call graph", vuldomain.AnalyserCallGraphBFS, "BUILT_WITH_BODIES", vuldomain.SoundnessConfirmed, "found no path"},
		{"metadata-only graph", vuldomain.AnalyserCallGraphBFS, "METADATA_ONLY", vuldomain.SoundnessUnconfirmed, "METADATA_ONLY"},
	}

	rendered := map[string]string{}
	for _, tc := range cases {
		rec := negativeRecord(tc.analyser, tc.fidelity)
		res, err := vulnReachabilityVerdict(rec.Coordinate, rec, true, "GO-2025-3487", unclassifiedRoutes, nil)
		if err != nil {
			t.Fatalf("%s: vulnReachabilityVerdict: %v", tc.name, err)
		}
		if res.Verdict != verdictNotReachable {
			t.Fatalf("%s: verdict = %q, want the negative under test", tc.name, res.Verdict)
		}
		if res.Soundness != tc.wantSound {
			t.Errorf("%s: soundness = %q, want %q", tc.name, res.Soundness, tc.wantSound)
		}
		if !strings.Contains(res.SoundnessReason, tc.wantReason) {
			t.Errorf("%s: reason = %q, want it to name %q", tc.name, res.SoundnessReason, tc.wantReason)
		}

		var out bytes.Buffer
		printVulnReachability(&out, res)
		got := out.String()
		verdict := findLineWith(t, got, "NOT reachable")
		if !strings.Contains(verdict, "soundness: "+tc.wantSound.String()) {
			t.Errorf("%s: verdict line = %q, want the soundness on the line an operator acts on", tc.name, verdict)
		}
		if !strings.Contains(got, res.SoundnessReason) {
			t.Errorf("%s: the reason behind the rung was not printed:\n%s", tc.name, got)
		}
		rendered[tc.name] = got
	}

	// The defect this closes: before, these three were the same sentence.
	if rendered["govulncheck source"] == rendered["govulncheck binary"] {
		t.Error("a binary-mode negative still renders identically to a source-mode one")
	}
	if rendered["govulncheck source"] == rendered["built call graph"] {
		t.Error("a searched negative still renders identically to an inferred one")
	}
	if strings.Contains(rendered["govulncheck binary"], "soundness: confirmed") {
		t.Error("a symbol-table negative reports itself confirmed")
	}
}

// TestPackageLevelVerdictStatesItIsUnsearchable covers the rung the other three
// cannot reach: an advisory naming no symbols for this module path had no target
// to search for, whatever the analyser did.
func TestPackageLevelVerdictStatesItIsUnsearchable(t *testing.T) {
	rec := negativeRecord(vuldomain.AnalyserGovulncheck, "source")
	rec.Findings[0].AffectedSymbols = nil
	rec.Findings[0].AdvisoryNamesNoSymbols = true

	res, err := vulnReachabilityVerdict(rec.Coordinate, rec, true, "GO-2025-3487", unclassifiedRoutes, nil)
	if err != nil {
		t.Fatalf("vulnReachabilityVerdict: %v", err)
	}
	if res.Verdict != verdictPackageLevelOnly {
		t.Fatalf("verdict = %q, want the package-level one", res.Verdict)
	}
	if res.Soundness != "unsearchable" {
		t.Errorf("soundness = %q, want unsearchable", res.Soundness)
	}
	var out bytes.Buffer
	printVulnReachability(&out, res)
	if !strings.Contains(out.String(), "soundness: unsearchable") {
		t.Errorf("the package-level answer does not state its soundness:\n%s", out.String())
	}
}

// TestReachablePositiveStatesNoSoundness keeps positives untouched. A route is
// its own evidence; a soundness rung beside it would suggest the route needed
// one.
func TestReachablePositiveStatesNoSoundness(t *testing.T) {
	rec := rootedRecord()
	res, err := vulnReachabilityVerdict(rec.Coordinate, rec, true, "GO-2026-0001", unclassifiedRoutes, nil)
	if err != nil {
		t.Fatalf("vulnReachabilityVerdict: %v", err)
	}
	if res.Verdict != verdictReachable {
		t.Fatalf("verdict = %q, want reachable", res.Verdict)
	}
	if res.Soundness != "" || res.SoundnessReason != "" {
		t.Errorf("positive carried soundness %q / %q", res.Soundness, res.SoundnessReason)
	}
	var out bytes.Buffer
	printVulnReachability(&out, res)
	if strings.Contains(out.String(), "soundness") {
		t.Errorf("soundness leaked onto a positive:\n%s", out.String())
	}
}

// TestFindingListLabelStatesSoundness carries the rung to the surface where the
// negatives are actually counted — the per-finding list in vuln-show and
// vuln-scan-show, where a bare "[not reachable]" is what an operator reads
// before deciding not to upgrade.
func TestFindingListLabelStatesSoundness(t *testing.T) {
	inferred := negativeRecord(vuldomain.AnalyserGovulncheck, "source").Findings[0]
	searched := negativeRecord(vuldomain.AnalyserCallGraphBFS, "BUILT_WITH_BODIES").Findings[0]

	gotInferred := reachabilityLabel(inferred, " [not reachable]")
	gotSearched := reachabilityLabel(searched, " [not reachable]")
	if !strings.Contains(gotInferred, "inferred") {
		t.Errorf("inferred negative labelled %q", gotInferred)
	}
	if !strings.Contains(gotSearched, "confirmed") {
		t.Errorf("searched negative labelled %q", gotSearched)
	}
	if gotInferred == gotSearched {
		t.Errorf("both negatives still carry the same label %q", gotInferred)
	}
}
