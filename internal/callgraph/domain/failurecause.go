package domain

import "github.com/eitanity/kanonarion/internal/failurecause"

// FailureCause is the call-graph ledger's name for the shared axis: whether a
// failed or incomplete extraction is a statement about the module or about the
// run that tried to analyse it. The vocabulary, and the argument for it, live in
// internal/failurecause; the alias keeps the ledger's own spelling while the
// scan and the extraction stage answer with the same three words.
//
// What it decides here is cache eligibility — see RecordIsCacheable.
type FailureCause = failurecause.Cause

const (
	// FailureCauseUnrecorded is the zero value, carried by every record that came
	// back complete and by the failed and partial records written before the axis
	// reached them.
	FailureCauseUnrecorded = failurecause.Unrecorded

	// FailureCauseModule means the module is what limited the analysis, which is a
	// stable finding about published bytes and is served from cache like any other.
	FailureCauseModule = failurecause.Module

	// FailureCauseEnvironment means this host is what limited the run, so the
	// record is kept as evidence and is never served as a cache hit.
	FailureCauseEnvironment = failurecause.Environment
)

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
	return StatusIsFailure(r.OverallStatus)
}

// StatusIsFailure is RecordIsFailure over the status alone, for a store that
// reads it from a column rather than from a decoded record.
func StatusIsFailure(status CallGraphStatus) bool {
	switch status {
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

// EnvironmentLimitedGraph reports whether a record carries a graph that THIS
// HOST, rather than the module, cut short.
//
// It is the ordering rule's reading of the cause axis, and it is narrower than
// the axis itself on purpose. A run that produced no graph at all measured
// nothing either way, and there is no lesser measurement to demote: two accounts
// of a run that got nowhere are ordered by recency, so the newest account of why
// is what a reader is shown. What this names is the other case — a graph exists,
// and the record's own row says the environment is why there is not more of it.
//
// Both halves come from columns, so a store answers it without decoding a
// record. See GenerationRank for what the answer decides.
func EnvironmentLimitedGraph(status CallGraphStatus, cause FailureCause) bool {
	return cause.IsEnvironmentLimit() && !StatusIsFailure(status)
}
