package domain

import (
	"encoding/json"
	"fmt"
)

// ReachabilityState is the answer a finding carries about whether the
// vulnerable code can be reached, as one word.
//
// It is not a boolean and never was. ReachabilityResult.IsReachable is a stored
// bit with two positions, and the question has at least five answers: the
// advisory may name no symbol in this module path at all, so symbol-level
// reachability was never determinable; the advisory may be retracted, so there
// is nothing to reach; the analysis may have been asked and failed; it may never
// have been asked. Collapsing those onto the bit puts a finding nothing showed
// running under the same word as one with a route, which is how a
// package-level-only finding was read and reported as reachable.
//
// It is DERIVED at read time from what the finding already records — the stored
// bit, AdvisoryNamesNoSymbols, the withdrawal timestamp, the reachability note —
// and is never stored. That is the contract ReachabilitySoundness follows and it
// is here for the same reason: a derived answer reaches every record already in
// the store the moment this build serves it, costs no re-scan and no pipeline
// generation, and improves whenever its inputs do. A stored word would be frozen
// at scan time and blank on every existing record.
//
// The value is EMITTED ALWAYS on every surface that publishes it, never omitted
// at a "normal" value. A consumer must be able to tell not_reachable from
// package_level_only from a producer that does not derive the state at all, and
// only a key that is always present can carry that third distinction.
type ReachabilityState string

const (
	// StateNotAnalysed is the zero value: the finding carries no reachability
	// answer and no record of an attempt, so nobody asked. It is a statement about
	// the scan, not about the code, and it is not a negative.
	StateNotAnalysed ReachabilityState = ""
	// StateReachable means the analysis found a path from an entry point of the
	// analysed build to the vulnerable symbol. It is the one state that carries
	// its own evidence: the route.
	StateReachable ReachabilityState = "reachable"
	// StateNotReachable means the analysis ran, could have named a symbol, and
	// reported no path to one. How thorough that search was is ReachabilitySoundness's
	// question, not this one — a negative here may be confirmed or merely inferred
	// from an analyser's silence.
	StateNotReachable ReachabilityState = "not_reachable"
	// StatePackageLevelOnly means the advisory matches this coordinate but names
	// no symbol in it, so symbol-level reachability was never determinable: there
	// was no target for a search to look for.
	//
	// It is neither reachable — nothing showed the vulnerable code running — nor
	// not_reachable, which would offer a search that was never possible as the
	// reason to stand down. It outranks the stored bit in both directions,
	// including a bit reading true: a project-rooted analysis reports a symbolic
	// trace for the advisory as a whole, and where the entry matching THIS module
	// path names no symbols that trace is not evidence that this module's
	// vulnerable code runs. Measured on a working store, 24 findings carry the bit
	// true beside an advisory naming no symbols for their path.
	StatePackageLevelOnly ReachabilityState = "package_level_only"
	// StateWithdrawn means the advisory was retracted upstream. It is answered
	// ahead of reachability because it makes the reachability question moot, and it
	// is not a flavour of not_reachable: answering "not reachable" for a retracted
	// advisory offers reachability as the mitigation, inviting the reader to
	// conclude the module would be at risk if only something called it, when there
	// is nothing to be at risk from.
	StateWithdrawn ReachabilityState = "withdrawn"
	// StateNotDetermined means an analysis ran and could not decide: it recorded an
	// answer at Unknown confidence. A project-rooted scan that observed only the
	// vulnerable package being initialised lands here — the package is in the
	// build, which is not an answer about the code the advisory is about.
	StateNotDetermined ReachabilityState = "not_determined"
	// StateNotComputed means reachability WAS requested for this finding and could
	// not be produced — the call graph would not load, the analysis subprocess
	// failed. The finding records the cause in ReachabilityNote. It is the same
	// absence as StateNotAnalysed in the record and it is not the same fact: this
	// one is a question the run could not answer and must degrade the run's claim.
	StateNotComputed ReachabilityState = "not_computed"
	// StateNotAffected is the answer for an advisory that is not among a scanned
	// record's findings at all. It is a statement about the advisory set rather
	// than about a finding, so FindingReachabilityState — which is handed a
	// finding — never returns it; the reader that asked about one named advisory
	// and did not find it does. It is defined here so the vocabulary lives in one
	// place and the surfaces cannot drift into different words for it.
	StateNotAffected ReachabilityState = "not_affected"
)

// FindingReachabilityState is the one reading of a finding's reachability
// answer, shared by every surface that publishes one.
//
// The order of the tests is the substance, and it is the order the stored-module
// reachability query has always applied:
//
//  1. A retraction first. It makes the rest moot, and the two absences below
//     would otherwise send a reader to compute a call graph for an advisory that
//     no longer stands.
//  2. No answer at all, split by whether an attempt was recorded. Those are
//     different facts with opposite remedies and only the record can say which.
//  3. An advisory naming no symbols for this module path, checked BEFORE the
//     stored bit and before confidence. It is the one cause no fidelity and no
//     re-run can change, so neither a bit reading true nor a confidence reading
//     Unknown describes it.
//  4. Undetermined confidence: the analysis ran and declined to decide.
//  5. Only then the stored bit.
func FindingReachabilityState(f VulnerabilityFinding) ReachabilityState {
	if f.IsWithdrawn() {
		return StateWithdrawn
	}
	if f.Reachable == nil {
		if f.ReachabilityAttemptFailed() {
			return StateNotComputed
		}
		return StateNotAnalysed
	}
	if f.AdvisoryNamesNoSymbols {
		return StatePackageLevelOnly
	}
	if f.Reachable.Confidence == ConfidenceUnknown {
		return StateNotDetermined
	}
	if f.Reachable.IsReachable {
		return StateReachable
	}
	return StateNotReachable
}

// ReachabilityStates is every state this type defines, with the zero value last.
// Consumers that render or tally states walk this rather than restating the
// list.
func ReachabilityStates() []ReachabilityState {
	return []ReachabilityState{
		StateReachable,
		StateNotReachable,
		StatePackageLevelOnly,
		StateWithdrawn,
		StateNotDetermined,
		StateNotComputed,
		StateNotAffected,
		StateNotAnalysed,
	}
}

// String renders the state for display, naming the zero value rather than
// printing an empty field.
func (s ReachabilityState) String() string {
	if s == StateNotAnalysed {
		return "not_analysed"
	}
	return string(s)
}

// MarshalJSON emits the word String renders, so the zero value travels as
// "not_analysed" rather than as an empty string.
//
// Without it the state a finding carries when nothing analysed it and the state
// a producer that never derives one carries would both serialise to nothing —
// the collapse this type exists to undo, reintroduced one level down.
func (s ReachabilityState) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(s.String())
	if err != nil {
		return nil, fmt.Errorf("marshalling reachability state: %w", err)
	}
	return b, nil
}

// Statement is what this state means, in one line, for a surface that prints the
// word and owes the reader what it stands for. The empty string is the answer
// for a value this type does not define, so a renderer prints the word alone
// rather than a sentence about some other state.
func (s ReachabilityState) Statement() string {
	switch s {
	case StateReachable:
		return "the analysis found a path from an entry point of this build to the vulnerable symbol"
	case StateNotReachable:
		return "the analysis reported no path to the vulnerable symbol; soundness says how thorough that search was"
	case StatePackageLevelOnly:
		return "affected at package level; the advisory names no symbols for this module path, so symbol-level reachability was never determinable"
	case StateWithdrawn:
		return "the advisory was retracted upstream, so there is nothing here to reach"
	case StateNotDetermined:
		return "an analysis ran and could not decide; it recorded its answer at Unknown confidence"
	case StateNotComputed:
		return "reachability was requested and could not be computed; the finding records the cause"
	case StateNotAffected:
		return "the module was scanned and this advisory is not among its findings"
	case StateNotAnalysed:
		return "no reachability analysis was asked for this finding"
	default:
		return ""
	}
}

// IsAnswered reports whether the state is one an analysis actually produced
// about the code, as opposed to one describing the analysis or the advisory.
// Only reachable and not_reachable qualify: everything else is a statement about
// why the question has no symbol-level answer.
func (s ReachabilityState) IsAnswered() bool {
	return s == StateReachable || s == StateNotReachable
}
