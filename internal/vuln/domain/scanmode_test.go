package domain_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// A module-level govulncheck answer examined no package, so it is unconfirmed
// and says why, and is told apart from the binary-mode rung by its reason.
func TestNegativeSoundness_ModuleMode(t *testing.T) {
	f := negative(domain.AnalyserGovulncheck, string(domain.ScanModeModule))
	f.Reachable.Confidence = domain.ConfidenceUnknown
	rung, reason := domain.NegativeSoundness(f)
	if rung != domain.SoundnessUnconfirmed {
		t.Errorf("module-mode soundness = %s, want %s", rung, domain.SoundnessUnconfirmed)
	}
	for _, w := range []string{"module level", "TinyGo closure compiles C", "reachability is not established"} {
		if !strings.Contains(reason, w) {
			t.Errorf("reason %q does not say %q", reason, w)
		}
	}
	_, binary := domain.NegativeSoundness(negative(domain.AnalyserGovulncheck, string(domain.ScanModeBinary)))
	if reason == binary {
		t.Error("the module and binary rungs give one reason")
	}
	if got := domain.FindingReachabilityState(f); got != domain.StateNotDetermined {
		t.Errorf("state = %s, want not_determined", got)
	}
}

func TestScanModes_ListsTheThree(t *testing.T) {
	want := []domain.ScanMode{domain.ScanModeSource, domain.ScanModeBinary, domain.ScanModeModule}
	if got := domain.ScanModes(); !slices.Equal(got, want) {
		t.Errorf("ScanModes() = %v, want %v", got, want)
	}
	if n := len(domain.ReachabilityStates()); n != 8 {
		t.Errorf("reachability states = %d, want the eight unchanged", n)
	}
}

// A read-time search beside a module-level answer is not weighed: no stored
// graph describes the TinyGo frame it was measured in.
func TestNegativeSoundness_ModuleModeIgnoresAReadTimeSearch(t *testing.T) {
	f := negative(domain.AnalyserGovulncheck, string(domain.ScanModeModule))
	f.Reachable.Confidence = domain.ConfidenceUnknown
	f.NegativeSearch = &domain.NegativeSearch{}
	rung, reason := domain.NegativeSoundness(f)
	if rung != domain.SoundnessUnconfirmed || !strings.Contains(reason, "module level") {
		t.Errorf("soundness = %s %q", rung, reason)
	}
	if strings.Contains(reason, "No call-graph search stands behind") {
		t.Errorf("a module-level rung carries a read-time search note: %q", reason)
	}
}
