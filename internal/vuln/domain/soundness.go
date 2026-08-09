package domain

// ReachabilitySoundness states how thorough the search behind a NEGATIVE
// reachability answer was.
//
// A positive and a negative are not symmetric claims, and the store already
// treats them asymmetrically without saying so. A positive carries a route: a
// hop-by-hop path that either exists or does not, and a reader can check it. A
// negative is the ABSENCE of a route, and an absence is worth exactly as much as
// the search that failed to find one. Measured on a working store: 236 negatives
// all read "confidence: High", and not one of them rested on a call-graph search
// — every one was read off an analyser's silence.
//
// So this is not a second confidence scale. Confidence answers "how sure is the
// verdict"; soundness answers "what was actually searched", which is the
// question an operator who is about to NOT upgrade is really asking. It is
// derived at read time from what the answer already records — the producing
// analyser and that analyser's own fidelity — so it classifies every stored
// record immediately, rather than being frozen into new records at scan time and
// leaving every existing one blank. See NegativeSoundness.
//
// The ladder, most to least sound:
//
//	confirmed    a search ran at a fidelity that can support a negative
//	inferred     no search ran; the negative reads a source-fidelity analysis's silence
//	unconfirmed  an analysis ran that could not have found a route at all
//	unsearchable the advisory names no symbol, so no search was ever possible
//
// inferred outranks unconfirmed deliberately. A source-mode analysis that loaded
// the whole build, built a call graph over it and never mentioned the advisory is
// weaker evidence than a search — it is an inference — but it is stronger than a
// symbol table inspected with no call graph behind it. unsearchable is the floor
// because it is the only rung no amount of fidelity can raise: the other three
// improve when the analysis does, and this one never will.
type ReachabilitySoundness string

const (
	// SoundnessNotStated is the zero value: there is no negative here to qualify.
	// It is what a reachable finding carries — a route is its own evidence and
	// answers its own soundness question — and what a finding with no
	// reachability answer at all carries.
	SoundnessNotStated ReachabilitySoundness = ""
	// SoundnessConfirmed means a search ran over a call graph built with function
	// bodies and found no path from an entry point to the vulnerable symbol. This
	// is the only rung the completeness ladder permits a confident negative to
	// rest on, stated on CompletenessBuiltWithBodies and applied here.
	SoundnessConfirmed ReachabilitySoundness = "confirmed"
	// SoundnessInferred means no search was run for this finding. An analysis
	// loaded the build from source and did not report a route to the vulnerable
	// symbol, and the negative reads that silence. It is real evidence — the
	// analysis examined this module at its resolved version from the project's
	// real entry points — and it is not a search that ran and came back empty.
	SoundnessInferred ReachabilitySoundness = "inferred"
	// SoundnessUnconfirmed means an analysis ran that could not have found a route
	// even if one existed: a symbol table inspected in binary mode with no call
	// graph behind it, a call graph below BUILT_WITH_BODIES, or an answer that
	// does not say what produced it. A negative here is not a finding about the
	// code; it is a finding about the analysis.
	SoundnessUnconfirmed ReachabilitySoundness = "unconfirmed"
	// SoundnessUnsearchable means the advisory names no symbols for this module
	// path, so there was never a target for a search to look for. Re-running at
	// any fidelity produces the same answer, which is what separates this from
	// unconfirmed.
	SoundnessUnsearchable ReachabilitySoundness = "unsearchable"
)

// ReachabilitySoundnessLevels is every rung this type defines, most to least
// sound, with the zero value last. Consumers that render or tally soundness walk
// this rather than restating the list — three restatements of the completeness
// ladder drifted before they were made to derive, and this one starts derived.
func ReachabilitySoundnessLevels() []ReachabilitySoundness {
	return []ReachabilitySoundness{
		SoundnessConfirmed,
		SoundnessInferred,
		SoundnessUnconfirmed,
		SoundnessUnsearchable,
		SoundnessNotStated,
	}
}

// String renders the rung for display, naming the zero value rather than
// printing an empty field.
func (s ReachabilitySoundness) String() string {
	if s == SoundnessNotStated {
		return "not stated"
	}
	return string(s)
}

// Rank orders the ladder, higher being more sound. The zero value ranks below
// every stated rung: an answer that states no soundness must never displace one
// that does.
func (s ReachabilitySoundness) Rank() int {
	switch s {
	case SoundnessConfirmed:
		return 4
	case SoundnessInferred:
		return 3
	case SoundnessUnconfirmed:
		return 2
	case SoundnessUnsearchable:
		return 1
	case SoundnessNotStated:
		return 0
	default:
		return 0
	}
}

// IsConfirmed reports whether a negative on this rung may be reported as a clean
// negative. Only a search that ran at a fidelity able to find a route qualifies;
// every other rung is reported as unconfirmed to the operator, which is the whole
// behavioural change this ladder exists to make.
func (s ReachabilitySoundness) IsConfirmed() bool { return s == SoundnessConfirmed }
