package domain

// FailureCause names what a failed call-graph extraction is a statement about:
// the module, or the run that tried to analyse it.
//
// The distinction is the difference between a finding and a measurement that
// never happened. A module whose source does not type-check is a real, stable
// property of that module — re-analysing it tomorrow rediscovers it at full
// analysis cost. A run that could not find a usable Go toolchain has measured
// nothing at all, and the same module analysed a minute later on a repaired box
// may well produce a complete graph.
//
// The fetch ledger draws the same line for the same reason, and states it as
// "a failure is a statement about the lookup, not about the module, and a later
// attempt may well succeed. Collapsing the two lets one network flake be
// recorded — and cached — as a property of a dependency." Here the flake is a
// toolchain rather than a network, and the record is a call graph rather than a
// checksum, but the failure mode is identical: without the axis, one bad run is
// filed as a fact about a dependency and served on every subsequent run.
//
// The cause is classified where the failure is still a value — at the analyser
// boundary, from whether the environment can run the toolchain at all — and
// never by re-reading the prose of a stored FailureDetail, on the same terms
// x/mod/sumdb's errors are classified at ClientOps rather than recovered from a
// flattened string.
//
// It is not a ladder and composition never picks between its values: it
// qualifies a failure or an incompleteness, and a record carrying a graph
// outranks any failure regardless of what caused it. What it decides is cache
// eligibility — see RecordIsCacheable.
type FailureCause string

const (
	// FailureCauseUnrecorded is the zero value. It is carried by every record
	// that came back complete, and by the failed and partial records written
	// before the axis reached them. It states no cause, and must never be read as
	// one: an extraction that does not say what limited it is not evidence that
	// the module is at fault.
	FailureCauseUnrecorded FailureCause = ""

	// FailureCauseModule means the module is what limited the analysis: its
	// published bytes carry no Go packages, its source does not type-check, its
	// module graph cannot be resolved from what it ships. It qualifies a partial
	// extraction as well as a failed one — packages of the module's own that did
	// not typecheck are the module's property too. The finding is about the
	// module and is stable across runs, so it is served from cache exactly as a
	// successful analysis is.
	FailureCauseModule FailureCause = "module"

	// FailureCauseEnvironment means the analysis environment is what limited the
	// run: no usable go on PATH, a toolchain that is absent or unresolvable, a
	// cancelled context, the memory cap, a module cache too cold to resolve a
	// dependency the load needed. What the run reached says as much about this
	// host as about the module, so the record is kept as evidence that this run
	// ran the way it did — the ledger never goes silent — but it is not eligible
	// as a cache hit. That holds whether the run produced no graph at all or an
	// incomplete one: a repaired environment must get its chance to measure the
	// rest.
	FailureCauseEnvironment FailureCause = "environment"
)

// String renders the cause, showing the zero value as "not recorded" rather than
// as an empty field a reader would take for an absence of cause.
func (c FailureCause) String() string {
	if c == FailureCauseUnrecorded {
		return "not recorded"
	}
	return string(c)
}

// RecordIsCacheable reports whether a record may satisfy a later extraction of
// the same coordinate, or whether that extraction must re-derive instead.
//
// It is the call-graph ledger's answer to the question fetch answers with its own
// RecordIsCacheable, and it lives here, beside Compose, rather than in the
// extraction use case: the vuln stage's on-demand call-graph spawner asks the
// same question from a different context, and a rule each caller re-decides is a
// rule that holds in whichever of them was edited last.
//
// Three cases, and the third is the one that carries the argument:
//
//   - An environment failure is never cacheable. Its status describes a run that
//     never measured the module, so serving it back makes one bad moment
//     permanent: every later run reports the same toolchain error, and no amount
//     of repairing the environment clears it. Re-attempting costs one analysis on
//     a run that would otherwise have skipped it, and is the only way the record
//     can ever be superseded on its own.
//
//   - A module failure is cacheable, exactly like a successful extraction. A
//     module that genuinely cannot be built is a real, stable finding, and
//     re-deriving it every walk would pay full analysis cost to rediscover it.
//     Keeping that distinction is the whole point of the axis.
//
//   - A record that FAILED, or came back INCOMPLETE, and states no cause is not
//     cacheable. It predates the axis, so nothing about it says the module was at
//     fault, and treating "we do not know" as "the module is broken" is the exact
//     collapse this type exists to prevent. It costs one re-attempt per such
//     record, once: the re-attempt writes a record that does state its cause, and
//     from then on the coordinate settles either way. Records that came back
//     COMPLETE are unaffected — they are the overwhelming majority, they keep
//     answering, and no purge or pipeline-version bump is owed for any of this.
//
// Partial is inside that third case, and it is where the rule was learned. A
// partial graph is a graph, so a partial record whose cause is stated is served
// or re-derived on the cause exactly as a failure is: a module whose own sources
// do not typecheck keeps answering, and a graph left incomplete because this
// host's module cache was cold does not. What could not be done is to read the
// unrecorded cause as the module's fault. A run served that record is served an
// answer measured under an environment nobody can name, and it is served it after
// repairing the environment too — the remedy the tool prints then reads as tried
// and failed.
//
// It is a free function rather than a method, on the same terms as
// ImplementersOf: CallGraphRecord is a result type carrying facts, and cache
// policy is behaviour over those facts rather than one of them.
func RecordIsCacheable(r CallGraphRecord) bool {
	switch r.FailureCause {
	case FailureCauseEnvironment:
		return false
	case FailureCauseModule:
		return true
	case FailureCauseUnrecorded:
		return !RecordIsFailure(r) && !RecordIsIncomplete(r)
	default:
		// A cause this generation does not define. It was written by a newer
		// generation, or by nothing this code knows about; either way it is not a
		// stated module fault, so it is not served.
		return false
	}
}

// RecordIsFailure reports whether a record describes an extraction that produced
// no call graph at all.
//
// Partial is deliberately absent: a partial graph is a graph, its incompleteness
// is scoped by FailedPackages, and every query over it is caveated per package.
// Whether that graph may be SERVED is a different question, asked by
// RecordIsIncomplete — a partial record is not a failure and is still not always
// a usable answer. ExcludedByConfig is absent too — a module the operator chose
// not to analyse is a decision, not a failure, and re-attempting it every run
// would ignore the decision.
func RecordIsFailure(r CallGraphRecord) bool {
	switch r.OverallStatus {
	case CallGraphStatusUnknown,
		CallGraphStatusLoadFailed,
		CallGraphStatusOutOfMemory,
		CallGraphStatusCancelled,
		CallGraphStatusExtractionFailed:
		return true
	case CallGraphStatusExtracted, CallGraphStatusPartial, CallGraphStatusExcludedByConfig:
		return false
	default:
		return false
	}
}

// RecordIsIncomplete reports whether a record describes an extraction that
// produced a graph the analysis itself could not finish.
//
// It is the companion to RecordIsFailure and exists because the two questions
// diverged. A failure produced no graph; an incomplete extraction produced one
// with packages missing from it. Both are extractions whose outcome depended on
// something the run may not have controlled, and both are therefore records that
// must state a cause before they may be served back — which is all this function
// is used for.
//
// It is not a claim that the record is worthless. A Partial graph answers
// everything it covers, every query over it is caveated per failed package, and
// a Partial record with a stated module cause is cacheable exactly like a
// successful one.
func RecordIsIncomplete(r CallGraphRecord) bool {
	return r.OverallStatus == CallGraphStatusPartial
}
