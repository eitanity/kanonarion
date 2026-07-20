package domain

import "fmt"

// CompletenessLevel records the fidelity at which a module's call graph was
// analysed. The same module can be analysed at very different fidelity from run
// to run — fully built into SSA, registered type-only, reduced to package
// metadata, failed to load, or resolved at a version the host toolchain never
// built — and that fidelity, not a code change, can make an edge appear or
// disappear between two runs. Recording the level per module lets a diff assert
// that a before/after comparison is fidelity-symmetric before it trusts a
// "resolved"/"unaffected" verdict.
//
// The levels are ordered most to least complete. A verdict is only ever as
// sound as the least-complete side of the comparison that produced it.
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
	// CompletenessTypeOnly means the module was registered from type information
	// only (no SSA bodies were built), as happens for a dependency package pulled
	// in type-only. Method bodies were never analysed, so call edges out of them
	// are absent.
	CompletenessTypeOnly CompletenessLevel = "TYPE_ONLY"
	// CompletenessMetadataOnly means only package metadata (names, imports) was
	// loaded — no types, no bodies. Nothing about dispatch can be concluded.
	CompletenessMetadataOnly CompletenessLevel = "METADATA_ONLY"
	// CompletenessFailed means loading or SSA construction failed and no usable
	// graph was produced for the module.
	CompletenessFailed CompletenessLevel = "FAILED"
	// CompletenessVersionNotInToolchain means the module resolved to a version
	// the host toolchain never built (scanned in isolation it selects a version
	// the project's build list never resolved). Its in-toolchain status differs
	// from an ordinary analysed module, so it is never fidelity-comparable with
	// one even if some graph was produced.
	CompletenessVersionNotInToolchain CompletenessLevel = "VERSION_NOT_IN_TOOLCHAIN"
)

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
// parity. The completeness level folds in in-toolchain status (a
// VERSION_NOT_IN_TOOLCHAIN level is its own value), and the algorithm captures
// the algorithm/devirt tier that produced the graph, so equality across both
// fields is "same completeness level, same in-toolchain status, same
// algorithm/devirt tier".
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
		return fmt.Sprintf("call graph is %s, not built with bodies — run `go generate ./...` and `go build ./...`, then re-analyse; verdicts over this module may be incomplete", level)
	case PhaseInclusion:
		return fmt.Sprintf("call graph is %s, not built with bodies — generators are not run on untrusted code, so this verdict is degraded and may be incomplete", level)
	case PhaseDiff:
		return fmt.Sprintf("call graph is %s, not built with bodies — a before/after verdict over this module is unresolved unless both sides match", level)
	default:
		return fmt.Sprintf("call graph is %s, not built with bodies — verdicts over this module may be incomplete", level)
	}
}
