package cli

import (
	"strings"
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	localdomain "github.com/eitanity/kanonarion/internal/local/domain"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestReachabilityResultToOutput: the pure projection function maps every
// field from the domain result to the JSON-serialisable output type.
func TestReachabilityResultToOutput(t *testing.T) {
	result := localdomain.LocalReachabilityResult{
		Root:       "/workspace/app",
		ModulePath: "example.com/app",
		VersionID:  "v1.2.3",
		ProbeKind:  "binary",
		Notice:     "experimental",
		Modules: []localdomain.ModuleProbeResult{
			{
				Path:    "example.com/dep",
				Version: "v0.1.0",
				Findings: []localdomain.SymbolProbeFinding{
					{
						CVEID:          "CVE-2024-0001",
						Aliases:        []string{"GO-2024-0001"},
						Summary:        "buffer overflow",
						Verdict:        localdomain.SymbolProbePresent,
						VerdictSource:  localdomain.VerdictSourceSymbolTable,
						Reason:         "symbol in call path",
						MatchedSymbols: []string{"example.com/dep.Vuln"},
					},
				},
			},
		},
	}

	out := reachabilityResultToOutput(result)

	if out.Root != "/workspace/app" {
		t.Errorf("Root = %q, want /workspace/app", out.Root)
	}
	if out.ModulePath != "example.com/app" {
		t.Errorf("ModulePath = %q", out.ModulePath)
	}
	if out.VersionID != "v1.2.3" {
		t.Errorf("VersionID = %q", out.VersionID)
	}
	if out.ProbeKind != "binary" {
		t.Errorf("ProbeKind = %q", out.ProbeKind)
	}
	if out.Notice != "experimental" {
		t.Errorf("Notice = %q", out.Notice)
	}
	if len(out.Modules) != 1 {
		t.Fatalf("Modules len = %d, want 1", len(out.Modules))
	}
	m := out.Modules[0]
	if m.Path != "example.com/dep" || m.Version != "v0.1.0" {
		t.Errorf("module = %+v", m)
	}
	if len(m.Findings) != 1 {
		t.Fatalf("findings len = %d, want 1", len(m.Findings))
	}
	f := m.Findings[0]
	if f.CVEID != "CVE-2024-0001" {
		t.Errorf("CVEID = %q", f.CVEID)
	}
	if len(f.Aliases) != 1 || f.Aliases[0] != "GO-2024-0001" {
		t.Errorf("Aliases = %v", f.Aliases)
	}
	if f.Verdict != string(localdomain.SymbolProbePresent) {
		t.Errorf("Verdict = %q", f.Verdict)
	}
	if f.VerdictSource != string(localdomain.VerdictSourceSymbolTable) {
		t.Errorf("VerdictSource = %q", f.VerdictSource)
	}
	if len(f.MatchedSymbols) != 1 {
		t.Errorf("MatchedSymbols = %v", f.MatchedSymbols)
	}
}

// TestReachabilityResultToOutput_Empty: an empty result maps to empty slices
// (not nil) so JSON consumers can iterate unconditionally.
func TestReachabilityResultToOutput_Empty(t *testing.T) {
	out := reachabilityResultToOutput(localdomain.LocalReachabilityResult{})
	if out.Modules == nil {
		t.Error("Modules must not be nil for empty result")
	}
}

var reachCoord = fetchdomain.ModuleCoordinate{Path: "golang.org/x/text", Version: "v0.3.7"}

func scannedRecord(status vuldomain.VulnerabilityStatus, findings ...vuldomain.VulnerabilityFinding) vuldomain.VulnerabilityRecord {
	return vuldomain.VulnerabilityRecord{
		Coordinate:    reachCoord,
		OverallStatus: status,
		Findings:      findings,
	}
}

// TestVulnReachabilityVerdict_ConfidentAnswers: the three cases that are a real
// answer (exit 0) — reachable, not-reachable, and not-affected — return a result
// with the expected verdict and never an error.
func TestVulnReachabilityVerdict_ConfidentAnswers(t *testing.T) {
	reachable := vuldomain.VulnerabilityFinding{
		ID:        "GO-2021-0113",
		Reachable: &vuldomain.ReachabilityResult{IsReachable: true, Confidence: vuldomain.ConfidenceHigh, ExamplePaths: [][]string{{"main.main", "x.Vuln"}}},
	}
	notReachable := vuldomain.VulnerabilityFinding{
		ID:        "GO-2021-0113",
		Reachable: &vuldomain.ReachabilityResult{IsReachable: false, Confidence: vuldomain.ConfidenceHigh},
	}

	tests := []struct {
		name        string
		rec         vuldomain.VulnerabilityRecord
		vulnID      string
		wantVerdict string
	}{
		{"reachable", scannedRecord(vuldomain.StatusAffected, reachable), "GO-2021-0113", verdictReachable},
		{"not reachable", scannedRecord(vuldomain.StatusAffected, notReachable), "GO-2021-0113", verdictNotReachable},
		{"not affected: scanned clean, CVE absent", scannedRecord(vuldomain.StatusClean), "GO-2021-0113", verdictNotAffected},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := vulnReachabilityVerdict(reachCoord, tt.rec, true, tt.vulnID)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Verdict != tt.wantVerdict {
				t.Errorf("verdict = %q, want %q", res.Verdict, tt.wantVerdict)
			}
			if res.Method != reachabilityMethodCallGraph {
				t.Errorf("method = %q, want %q", res.Method, reachabilityMethodCallGraph)
			}
		})
	}
}

// TestVulnReachabilityVerdict_Unresolved: the cases where the answer is genuinely
// unknown must return a directing error (non-zero) rather than a confident
// negative — the absence-as-answer floor. Paired with the confident cases above.
func TestVulnReachabilityVerdict_Unresolved(t *testing.T) {
	notRun := vuldomain.VulnerabilityFinding{ID: "GO-2021-0113"} // Reachable == nil
	undetermined := vuldomain.VulnerabilityFinding{
		ID:        "GO-2021-0113",
		Reachable: &vuldomain.ReachabilityResult{IsReachable: false, Confidence: vuldomain.ConfidenceUnknown},
	}

	tests := []struct {
		name      string
		rec       vuldomain.VulnerabilityRecord
		found     bool
		wantMatch string
	}{
		{"module never scanned", vuldomain.VulnerabilityRecord{}, false, "has not been vuln-scanned"},
		{"scan failed", scannedRecord(vuldomain.StatusScanFailed), true, "ScanFailed"},
		{"unscannable", scannedRecord(vuldomain.StatusUnscannable), true, "unscannable"},
		{"reachability not computed", scannedRecord(vuldomain.StatusAffected, notRun), true, "without --reachability"},
		{"call graph unavailable", scannedRecord(vuldomain.StatusAffected, undetermined), true, "undetermined"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := vulnReachabilityVerdict(reachCoord, tt.rec, tt.found, "GO-2021-0113")
			if err == nil {
				t.Fatal("want directing error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantMatch) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantMatch)
			}
		})
	}
}

// TestFindFindingByID_AliasCaseInsensitive: --vuln matches the primary ID or any
// alias, case-insensitively.
func TestFindFindingByID_AliasCaseInsensitive(t *testing.T) {
	findings := []vuldomain.VulnerabilityFinding{
		{ID: "GO-2021-0113", Aliases: []string{"CVE-2021-38561", "GHSA-ppp9-7jff-5vj2"}},
	}
	for _, q := range []string{"GO-2021-0113", "go-2021-0113", "CVE-2021-38561", "cve-2021-38561", "GHSA-ppp9-7jff-5vj2"} {
		if _, ok := findFindingByID(findings, q); !ok {
			t.Errorf("query %q did not match", q)
		}
	}
	if _, ok := findFindingByID(findings, "GO-2099-9999"); ok {
		t.Error("unrelated ID should not match")
	}
}
