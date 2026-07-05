package domain

// DetermineWalkScanStatus computes the overall status of a walk-wide
// vulnerability scan from the per-module outcome counts. total is the number
// of modules scanned (the walk's node count).
//
// The rule, in priority order:
// - every module failed (failed == total) -> Failed
// - any module is affected (affected > 0) -> Affected
// - some failed or unscannable -> Partial
// - otherwise -> AllClean
//
// Note the failed == total branch is evaluated first, so a zero-module walk
// (total == 0, failed == 0) yields Failed — this preserves the existing
// scan-walk behavior unchanged.
func DetermineWalkScanStatus(failed, affected, unscannable, total int) WalkScanStatus {
	switch {
	case failed == total:
		return WalkStatusFailed
	case affected > 0:
		return WalkStatusAffected
	case failed > 0 || unscannable > 0:
		return WalkStatusPartial
	default:
		return WalkStatusAllClean
	}
}
