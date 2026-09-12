package domain

import "fmt"

// CompletenessLevel records the fidelity at which a module's call graph was
// analysed. The same module can be analysed at very different fidelity from run
// to run — fully built into SSA, registered from type information with no
// bodies, reduced to package metadata, or failed to load — and that fidelity,
// not a code change, can make an edge appear or disappear between two runs.
// Recording the level per module lets a diff assert that a before/after
// comparison is fidelity-symmetric before it trusts a "resolved"/"unaffected"
// verdict.
//
// The levels are ordered most to least complete. A verdict is only ever as
// sound as the least-complete side of the comparison that produced it.
//
// Every level here has a production producer, and that is a standing property of
// this type rather than an observation about it. A level nothing writes tells a
// reader — of the type, of a record, or of the docs — that the analyser can
// report a fidelity it has never once reported, and the ladders built on this
// one (composition of call-graph generations, the soundness rung for a negative
// reachability answer) then order on a rung nobody can occupy.
// TestEveryCompletenessLevelHasAProducer pins it.
type CompletenessLevel string

const (
	// CompletenessUnknown is the zero value: no completeness was recorded (a
	// legacy record, or a path that consulted no call graph). It participates in
	// parity like any other level — Unknown vs a concrete level is a mismatch.
	CompletenessUnknown CompletenessLevel = ""
	// CompletenessBuiltWithBodies means the module's target packages were built
	// into SSA with function bodies, so interface dispatch and intra-body call
	// edges were resolvable. This is the only level a confident negative verdict
	// may rest on.
	CompletenessBuiltWithBodies CompletenessLevel = "BUILT_WITH_BODIES"
	// CompletenessTypeOnly means the module's packages type-checked and were
	// registered with the SSA program, but not one of them was built into SSA
	// with function bodies. Types are known, so the interface/implementation
	// relation and every declaration are visible; method bodies were never
	// analysed, so call edges out of them are absent.
	//
	// It is written when SSA construction fails for every target package that
	// type-checked — see the staticcha analyser. That is the state the level
	// names, and it is strictly more than METADATA_ONLY: the distinction between
	// "we had types but no bodies" and "we had neither" is known at the point the
	// build result is read and must not be discarded there.
	CompletenessTypeOnly CompletenessLevel = "TYPE_ONLY"
	// CompletenessMetadataOnly means only package metadata (names, imports) was
	// loaded — no types, no bodies. Nothing about dispatch can be concluded.
	CompletenessMetadataOnly CompletenessLevel = "METADATA_ONLY"
	// CompletenessFailed means loading or SSA construction failed and no usable
	// graph was produced for the module.
	CompletenessFailed CompletenessLevel = "FAILED"
)

// CompletenessLevels is every level this type defines, most to least complete,
// with the zero value last. It is the ladder other domains mirror and the list
// the producer guard walks; adding a level without adding it here is caught by
// TestCompletenessLevels_IsExhaustive.
//
// VERSION_NOT_IN_TOOLCHAIN was removed from this ladder rather than given a
// producer. The condition it named — the module resolved to a version outside
// the analysed project's toolchain — is a property of an isolated SCAN, not of a
// call graph's fidelity, and it is already reported where it belongs and with a
// real producer, as vuln domain's UnscanReasonVersionNotInToolchain. Restating
// it as a call-graph level asserted a second, unmaintained account of one fact.
func CompletenessLevels() []CompletenessLevel {
	return []CompletenessLevel{
		CompletenessBuiltWithBodies,
		CompletenessTypeOnly,
		CompletenessMetadataOnly,
		CompletenessFailed,
		CompletenessUnknown,
	}
}

// String returns the human-readable name of the level, rendering the zero value
// as "Unknown".
func (l CompletenessLevel) String() string {
	if l == CompletenessUnknown {
		return "Unknown"
	}
	return string(l)
}

// IsBuiltWithBodies reports whether the module was analysed at full fidelity —
// the only level on which a confident "not reachable" / "resolved" verdict is
// sound.
func (l CompletenessLevel) IsBuiltWithBodies() bool {
	return l == CompletenessBuiltWithBodies
}

// CompletenessDescriptor is the per-side fidelity signature a diff compares for
// parity. The completeness level names how much of the module was built, and the
// algorithm captures the algorithm/devirt tier that produced the graph, so
// equality across both fields is "same completeness level, same algorithm/devirt
// tier".
type CompletenessDescriptor struct {
	Level     CompletenessLevel
	Algorithm CallGraphAlgorithm
}

// RecordCompleteness projects a record onto its completeness descriptor. It is a
// free function rather than a method so CallGraphRecord stays a read-shaped
// result type with no behaviour.
func RecordCompleteness(r CallGraphRecord) CompletenessDescriptor {
	return CompletenessDescriptor{Level: r.Completeness, Algorithm: r.Algorithm}
}

// CompletenessParity reports whether two analysed sides are fidelity-comparable,
// and when they are not, the specific axis that differs. A diff that produces a
// "resolved"/"unaffected" verdict must first check parity: a green result across
// asymmetric fidelity is worse than no answer, because the finding (or its
// reachability) may have changed only because one side was analysed at lower
// fidelity. When ok is false, reason names the mismatch for the operator.
func CompletenessParity(before, after CompletenessDescriptor) (ok bool, reason string) {
	if before.Level != after.Level {
		return false, fmt.Sprintf("completeness level differs: before=%s after=%s", before.Level, after.Level)
	}
	if before.Algorithm != after.Algorithm {
		return false, fmt.Sprintf("algorithm/devirt tier differs: before=%s after=%s", before.Algorithm, after.Algorithm)
	}
	return true, ""
}

// AnalysisPhase is the operating phase whose trust model decides how missing
// fidelity is handled. The completeness signal is the same across phases; the
// response to it is not.
type AnalysisPhase string

const (
	// PhaseInclusion is dependency vetting of untrusted code in a hermetic
	// environment that must never execute the target — so generators are never
	// run to recover fidelity; a below-full verdict is degraded and caveated.
	PhaseInclusion AnalysisPhase = "inclusion"
	// PhaseCoding is analysis of a local working tree the developer controls and
	// can rebuild — so a below-full verdict is an instruction to rebuild
	// (go generate / go build), not a silent degradation.
	PhaseCoding AnalysisPhase = "coding"
	// PhaseDiff is a before/after comparison, where missing fidelity is handled
	// by the parity guard (see CompletenessParity) rather than a per-module
	// caveat.
	PhaseDiff AnalysisPhase = "diff"
)

// CompletenessCaveat returns the phase-appropriate caveat for a module analysed
// below full fidelity, or "" when the level is BUILT_WITH_BODIES (no caveat is
// warranted). Inclusion degrades and explains; coding instructs a rebuild. This
// reuses the existing degradation path — the caveat rides alongside the verdict
// rather than suppressing it.
func CompletenessCaveat(level CompletenessLevel, phase AnalysisPhase) string {
	if level.IsBuiltWithBodies() {
		return ""
	}
	switch phase {
	case PhaseCoding:
		return fmt.Sprintf("call graph is %s, not built with bodies — run `go generate ./...` and `go build ./...`, then re-analyse; answers over this module may be incomplete", level)
	case PhaseInclusion:
		return fmt.Sprintf("call graph is %s, not built with bodies — generators are not run on untrusted code, so this answer is degraded and may be incomplete", level)
	case PhaseDiff:
		return fmt.Sprintf("call graph is %s, not built with bodies — a before/after answer over this module is unresolved unless both sides match", level)
	default:
		return fmt.Sprintf("call graph is %s, not built with bodies — answers over this module may be incomplete", level)
	}
}
