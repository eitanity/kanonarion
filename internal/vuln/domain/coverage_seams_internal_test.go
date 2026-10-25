package domain

import (
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

// Both word types wrap a marshal failure rather than emitting nothing.
func TestWordMarshal_FailureIsWrapped(t *testing.T) {
	original := wordMarshal
	t.Cleanup(func() { wordMarshal = original })
	boom := errors.New("boom")
	wordMarshal = func(any) ([]byte, error) { return nil, boom }

	if _, err := ReachabilityState("").MarshalJSON(); !errors.Is(err, boom) {
		t.Errorf("ReachabilityState: err = %v", err)
	}
	if _, err := ReachabilitySoundness("").MarshalJSON(); !errors.Is(err, boom) {
		t.Errorf("ReachabilitySoundness: err = %v", err)
	}
}

// No search at all is a reason, never a certified absence.
func TestUnsearchedReason_NoSearch(t *testing.T) {
	var s *NegativeSearch
	if got := s.unsearchedReason(); got != "no search was attempted" {
		t.Errorf("unsearchedReason = %q", got)
	}
	if got := (&NegativeSearch{NotSearched: "the graph was refused"}).unsearchedReason(); got != "the graph was refused" {
		t.Errorf("unsearchedReason = %q", got)
	}
}

// A symbol-less advisory with no reachability verdict loses its symbols and
// gains no verdict.
func TestWithdrawSymbolLevelClaim_NoVerdictToWithdraw(t *testing.T) {
	f := &VulnerabilityFinding{AdvisoryNamesNoSymbols: true, AffectedSymbols: []string{"X"}}
	WithdrawSymbolLevelClaim(f)
	if f.AffectedSymbols != nil || f.Reachable != nil {
		t.Errorf("finding = %+v", f)
	}
}

// Requires order by path, then by version.
func TestRequireLess(t *testing.T) {
	a := coordinatetest.MustNew("example.com/a", "v1.0.0")
	a2 := coordinatetest.MustNew("example.com/a", "v1.1.0")
	b := coordinatetest.MustNew("example.com/b", "v0.1.0")
	if !requireLess(a, b) || requireLess(b, a) || !requireLess(a, a2) || requireLess(a2, a) {
		t.Error("requireLess is not path-then-version")
	}
}
