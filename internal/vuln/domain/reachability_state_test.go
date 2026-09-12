package domain_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// answered builds a finding whose analysis produced the given bit at High
// confidence — the shape all but a handful of stored findings have.
func answered(bit bool) domain.VulnerabilityFinding {
	return domain.VulnerabilityFinding{
		ID: "GO-2026-0001",
		Reachable: &domain.ReachabilityResult{
			IsReachable: bit,
			Confidence:  domain.ConfidenceHigh,
			DerivedBy: domain.ReachabilityDerivation{
				Analyser: domain.AnalyserGovulncheck,
				Fidelity: "source",
			},
		},
	}
}

// TestFindingReachabilityState_TheAdvisoryOutranksTheStoredBit is the defect
// itself. A project-rooted analysis reports a symbolic trace for an advisory
// whose entry for THIS module path names no symbols, so the stored bit reads
// true while nothing showed this module's vulnerable code running — measured on
// 24 findings in a working store. Reading the bit as the answer published one of
// them as reachable.
func TestFindingReachabilityState_TheAdvisoryOutranksTheStoredBit(t *testing.T) {
	for _, bit := range []bool{true, false} {
		f := answered(bit)
		f.AdvisoryNamesNoSymbols = true
		if got := domain.FindingReachabilityState(f); got != domain.StatePackageLevelOnly {
			t.Errorf("advisory names no symbols and is_reachable=%v: state = %q, want %q",
				bit, got, domain.StatePackageLevelOnly)
		}
	}
}

// TestFindingReachabilityState_TheOrdinaryPairIsUnchanged is the control: a
// finding the advisory names symbols in still answers off the bit, in both
// positions.
func TestFindingReachabilityState_TheOrdinaryPairIsUnchanged(t *testing.T) {
	if got := domain.FindingReachabilityState(answered(true)); got != domain.StateReachable {
		t.Errorf("state = %q, want %q", got, domain.StateReachable)
	}
	if got := domain.FindingReachabilityState(answered(false)); got != domain.StateNotReachable {
		t.Errorf("state = %q, want %q", got, domain.StateNotReachable)
	}
}

// TestFindingReachabilityState_RetractionIsAnsweredFirst pins the order. A
// retracted advisory is not a flavour of not_reachable: answering that would
// offer reachability as the mitigation for a report that no longer stands.
func TestFindingReachabilityState_RetractionIsAnsweredFirst(t *testing.T) {
	f := answered(true)
	f.WithdrawnAt = time.Date(2026, 4, 8, 13, 33, 56, 0, time.UTC)
	f.AdvisoryNamesNoSymbols = true
	if got := domain.FindingReachabilityState(f); got != domain.StateWithdrawn {
		t.Errorf("state = %q, want %q", got, domain.StateWithdrawn)
	}
}

// TestFindingReachabilityState_TheThreeAbsencesAreDistinct pins the distinction
// a bare nil cannot carry: nobody asked, someone asked and the analysis failed,
// and an analysis that ran and declined to decide.
func TestFindingReachabilityState_TheThreeAbsencesAreDistinct(t *testing.T) {
	none := domain.VulnerabilityFinding{ID: "GO-2026-0002"}
	if got := domain.FindingReachabilityState(none); got != domain.StateNotAnalysed {
		t.Errorf("no answer, no note: state = %q, want %q", got, domain.StateNotAnalysed)
	}

	failed := domain.VulnerabilityFinding{ID: "GO-2026-0003", ReachabilityNote: "the call graph would not load"}
	if got := domain.FindingReachabilityState(failed); got != domain.StateNotComputed {
		t.Errorf("requested and failed: state = %q, want %q", got, domain.StateNotComputed)
	}

	undecided := answered(false)
	undecided.Reachable.Confidence = domain.ConfidenceUnknown
	if got := domain.FindingReachabilityState(undecided); got != domain.StateNotDetermined {
		t.Errorf("Unknown confidence: state = %q, want %q", got, domain.StateNotDetermined)
	}
}

// TestReachabilityStateZeroValueTravelsAsAWord pins the encoding rule the
// soundness ladder set. The zero value is the empty string, so a surface
// emitting the raw value would leave "nothing analysed this finding" and "this
// producer does not derive a state" as the same bytes — the collapse this type
// exists to undo, one level down.
func TestReachabilityStateZeroValueTravelsAsAWord(t *testing.T) {
	raw, err := json.Marshal(domain.StateNotAnalysed)
	if err != nil {
		t.Fatalf("marshalling the zero state: %v", err)
	}
	if string(raw) != `"not_analysed"` {
		t.Errorf("zero state serialised as %s, want the named zero value", raw)
	}
}

// TestReachabilityStatesEachStateStatesItself refuses a state added to the
// vocabulary without its own words. A renderer prints the word and the sentence
// beside it, and a state inheriting a neighbour's sentence is a state that
// misdescribes itself.
func TestReachabilityStatesEachStateStatesItself(t *testing.T) {
	seen := map[string]domain.ReachabilityState{}
	for _, s := range domain.ReachabilityStates() {
		if s.Statement() == "" {
			t.Errorf("state %q states nothing about itself", s)
		}
		if prev, dup := seen[s.Statement()]; dup {
			t.Errorf("state %q reuses the sentence of %q", s, prev)
		}
		seen[s.Statement()] = s
		if s.String() == "" {
			t.Errorf("state %q renders as an empty field", string(s))
		}
	}
}

// TestReachabilityStateIsAnsweredIsNotTheWholeVocabulary pins the one predicate
// callers use to tell a measurement about the code from a statement about why
// there is none.
func TestReachabilityStateIsAnsweredIsNotTheWholeVocabulary(t *testing.T) {
	answered := 0
	for _, s := range domain.ReachabilityStates() {
		if s.IsAnswered() {
			answered++
		}
	}
	if answered != 2 {
		t.Errorf("%d state(s) report an answer about the code, want exactly reachable and not_reachable", answered)
	}
	if domain.StatePackageLevelOnly.IsAnswered() {
		t.Error("package_level_only reports as an answer about the code; nothing showed that code running")
	}
}

// TestStatementSaysNothingForAWordItDoesNotDefine covers the branch a renderer
// reaches when it is handed a state from a newer producer than itself.
//
// The empty string is the answer, and it has to be: a renderer that printed some
// other state's sentence beside an unrecognised word would explain the wrong
// thing with total confidence, which is worse than printing the word alone.
func TestStatementSaysNothingForAWordItDoesNotDefine(t *testing.T) {
	if got := domain.ReachabilityState("partially_reachable").Statement(); got != "" {
		t.Errorf("Statement() for an undefined state = %q, want the empty string", got)
	}
	for _, s := range domain.ReachabilityStates() {
		if s.Statement() == "" {
			t.Errorf("%s states nothing: every state this type defines owes a renderer its meaning", s)
		}
	}
}
