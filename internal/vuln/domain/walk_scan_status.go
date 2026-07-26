package domain

// DetermineWalkScanStatus computes the overall status of a walk-wide
// vulnerability scan from the per-module outcome counts. total is the number
// of modules scanned (the walk's node count).
//
// The rule, in priority order:
// - every module failed (failed == total) -> Failed
// - some failed or unscannable -> Partial
// - any module is affected (affected > 0) -> Affected
// - otherwise -> AllClean
//
// Incomplete coverage outranks findings. A run that both found something and
// could not analyse part of the build list is not a complete run, and reporting
// Affected asserted a completeness it never had: the failures vanished from the
// stored status and from the JSON, leaving a reader who trusts the one-word
// status unaware that any module went unanalysed. Findings are never concealed
// by this — they are listed in full in the output regardless of the status word,
// and the per-reason roll-up names every module that could not be scanned. It is
// only the summary word that stops over-claiming.
//
// This matches the precedence inspectSummaryStatus already applies one layer up,
// where a stage failure likewise outranks a finding, so the two layers agree
// about the same run instead of disagreeing.
//
// Note the failed == total branch is evaluated first, so a zero-module walk
// (total == 0, failed == 0) yields Failed — this preserves the existing
// scan-walk behavior unchanged.
func DetermineWalkScanStatus(failed, affected, unscannable, total int) WalkScanStatus {
	switch {
	case failed == total:
		return WalkStatusFailed
	case failed > 0 || unscannable > 0:
		return WalkStatusPartial
	case affected > 0:
		return WalkStatusAffected
	default:
		return WalkStatusAllClean
	}
}

// DetermineCoverageStatus computes the coverage axis alone: whether every module
// in the build list was analysed. It carries the same precedence as the coverage
// portion of DetermineWalkScanStatus (failed == total outranks a partial gap, so
// a zero-module walk yields Failed) but is blind to findings, so an affected run
// with complete coverage still reports Complete here.
func DetermineCoverageStatus(failed, unscannable, total int) CoverageStatus {
	switch {
	case failed == total:
		return CoverageFailed
	case failed > 0 || unscannable > 0:
		return CoveragePartial
	default:
		return CoverageComplete
	}
}

// DetermineFindingsStatus computes the findings axis alone: whether any module
// was affected. It is blind to coverage, so a run that could not analyse part of
// the build list still reports Affected here when a finding exists — the fact
// DetermineWalkScanStatus discards when coverage is incomplete.
func DetermineFindingsStatus(affected int) FindingsStatus {
	if affected > 0 {
		return FindingsAffected
	}
	return FindingsClean
}
