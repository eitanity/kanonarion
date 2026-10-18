package domain_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

var wasiSupply = domain.TinyGoSupply{TinyGo: []string{"os", "runtime"}}

func partitioned() ([]domain.VulnerabilityFinding, []domain.VulnerabilityFinding, *domain.ReachabilityResult) {
	reach := &domain.ReachabilityResult{IsReachable: true, Confidence: domain.ConfidenceHigh,
		Routes: []domain.ReachabilityRoute{{}}}
	in := []domain.VulnerabilityFinding{
		{ID: "os", AffectedPackages: []string{"os"}, Reachable: reach},
		{ID: "strconv", AffectedPackages: []string{"strconv"}, Reachable: reach},
		{ID: "mixed", AffectedPackages: []string{"os", "strconv"}, Reachable: reach},
		{ID: "none"},
	}
	return in, domain.PartitionTinyGoFindings(in, wasiSupply), reach
}

func TestPartitionTinyGoFindings_TinyGoOnlyIsNotEstablished(t *testing.T) {
	in, out, _ := partitioned()
	if !out[0].NotEstablished || out[0].TinyGoNote != "TinyGo supplies os; Go's affected range describes Go's code" {
		t.Errorf("os = %+v", out[0])
	}
	if out[0].Reachable.IsReachable || out[0].Reachable.Confidence != domain.ConfidenceUnknown || len(out[0].Reachable.Routes) != 1 {
		t.Errorf("os reachability = %+v, want the verdict withdrawn and the routes kept", out[0].Reachable)
	}
	if !in[0].Reachable.IsReachable {
		t.Error("the caller's finding was written through")
	}
}

func TestPartitionTinyGoFindings_GoOnlyIsLeftAsItCame(t *testing.T) {
	_, out, reach := partitioned()
	if out[1].NotEstablished || out[1].TinyGoNote != "" || out[1].Reachable != reach {
		t.Errorf("strconv was not left as it came: %+v", out[1])
	}
}

func TestPartitionTinyGoFindings_MixedAndNoPackage(t *testing.T) {
	_, out, _ := partitioned()
	if out[2].NotEstablished || out[2].TinyGoNote != "judged on strconv, which TinyGo does not supply; TinyGo supplies os, which Go's affected range does not describe" {
		t.Errorf("mixed = %+v", out[2])
	}
	if !out[3].NotEstablished || out[3].TinyGoNote != domain.NoPackageNote || out[3].Reachable != nil {
		t.Errorf("no-package = %+v", out[3])
	}
	if domain.PartitionTinyGoFindings(nil, wasiSupply) != nil {
		t.Error("no findings partitioned into some")
	}
}

func TestDetermineFindingsAxis_NotEstablished(t *testing.T) {
	ne := domain.VulnerabilityFinding{ID: "a", NotEstablished: true}
	live := domain.VulnerabilityFinding{ID: "b"}
	gone := domain.VulnerabilityFinding{ID: "c", WithdrawnAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	for name, tc := range map[string]struct {
		in   []domain.VulnerabilityFinding
		want domain.RecordFindingsStatus
	}{
		"all not established":                 {[]domain.VulnerabilityFinding{ne}, domain.FindingsRecordInconclusive},
		"not established beside withdrawn":    {[]domain.VulnerabilityFinding{gone, ne}, domain.FindingsRecordInconclusive},
		"not established beside a live match": {[]domain.VulnerabilityFinding{ne, live}, domain.FindingsRecordAffected},
		"withdrawn alone":                     {[]domain.VulnerabilityFinding{gone}, domain.FindingsRecordWithdrawn},
	} {
		if got := domain.DetermineFindingsAxis(tc.in); got != tc.want {
			t.Errorf("%s: axis = %s, want %s", name, got, tc.want)
		}
	}
}

func TestInconclusive_ProjectsOntoBothAxes(t *testing.T) {
	if got := domain.DetermineRecordCoverageStatus(domain.StatusInconclusive); got != domain.CoverageAnalysed {
		t.Errorf("coverage of Inconclusive = %s, want Analysed", got)
	}
	if got := domain.DetermineRecordFindingsStatus(domain.StatusInconclusive); got != domain.FindingsRecordInconclusive {
		t.Errorf("findings of Inconclusive = %s", got)
	}
	if got := domain.DetermineRecordOverallStatus(domain.CoverageAnalysed, domain.FindingsRecordInconclusive); got != domain.StatusInconclusive {
		t.Errorf("summary = %s, want Inconclusive", got)
	}
	if got := domain.DetermineRecordOverallStatus(domain.CoverageUnscannable, domain.FindingsRecordInconclusive); got != domain.StatusUnscannable {
		t.Errorf("coverage no longer outranks findings: %s", got)
	}
}

func TestNotEstablished_StateSoundnessAndWire(t *testing.T) {
	f := domain.PartitionTinyGoFindings([]domain.VulnerabilityFinding{{ID: "a", AffectedPackages: []string{"os"},
		AdvisoryNamesNoSymbols: true, Reachable: &domain.ReachabilityResult{Confidence: domain.ConfidenceHigh}}}, wasiSupply)[0]
	if s := domain.FindingReachabilityState(f); s != domain.StateNotDetermined {
		t.Errorf("state = %s, want not_determined ahead of package_level_only", s)
	}
	if s, why := domain.NegativeSoundness(f); s != domain.SoundnessUnconfirmed || !strings.Contains(why, "TinyGo supplies os") {
		t.Errorf("soundness = (%s, %q)", s, why)
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"not_established":true`) || !strings.Contains(string(data), `"tinygo_note":"TinyGo supplies os;`) {
		t.Errorf("wire form = %s", data)
	}
	host, err := json.Marshal(domain.VulnerabilityFinding{ID: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(host), "not_established") || strings.Contains(string(host), "tinygo_note") {
		t.Errorf("a host finding marshals the new keys: %s", host)
	}
}

func TestRunLevel_Inconclusive(t *testing.T) {
	if got := domain.DetermineFindingsStatus(0, 1); got != domain.FindingsInconclusive {
		t.Errorf("findings(0 affected, 1 inconclusive) = %s", got)
	}
	if got := domain.DetermineFindingsStatus(1, 1); got != domain.FindingsAffected {
		t.Errorf("findings(1 affected, 1 inconclusive) = %s", got)
	}
	if got := domain.DetermineWalkScanStatus(0, 0, 1, 0, 2); got != domain.WalkStatusInconclusive {
		t.Errorf("overall(complete, 1 inconclusive) = %s", got)
	}
	if got := domain.DetermineWalkScanStatus(0, 1, 1, 0, 2); got != domain.WalkStatusAffected {
		t.Errorf("overall(1 affected, 1 inconclusive) = %s", got)
	}
	if got := domain.DetermineWalkScanStatus(0, 0, 1, 1, 2); got != domain.WalkStatusPartial {
		t.Errorf("coverage no longer outranks findings: %s", got)
	}
	data, err := json.Marshal(domain.WalkScanCounts{Total: 1, Analysed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "inconclusive") {
		t.Errorf("a run with none marshals the count: %s", data)
	}
}
