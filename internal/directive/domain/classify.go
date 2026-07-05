package domain

import "golang.org/x/mod/semver"

// Classify assigns a RiskClass to d (rules). resolvedVersion is the
// version the build actually resolves OldPath to, used only for `exclude`
// newer/older comparison; "" means the resolved version is unknown.
//
// Per, an unknown resolved version for an exclude is NOT silently
// treated as the benign (older/cleanup) case: it fails safe to RiskHigh,
// because an exclude that *might* be removing a patched version is a
// high-risk finding until proven otherwise.
func Classify(d Directive, resolvedVersion string) RiskClass {
	switch d.Kind {
	case KindReplace:
		switch {
		case d.IsLocal:
			return RiskHighest
		case d.NewPath != "" && d.NewPath != d.OldPath:
			return RiskHigh // fork: different module path
		default:
			return RiskMedium // same module, different version
		}
	case KindExclude:
		if resolvedVersion == "" || !semver.IsValid(d.OldVersion) || !semver.IsValid(resolvedVersion) {
			return RiskHigh // cannot prove it is the benign older-than case
		}
		if semver.Compare(d.OldVersion, resolvedVersion) > 0 {
			return RiskHigh // excluding a version newer than resolved
		}
		return RiskLow // excluding an older version: cleanup
	default:
		return RiskUnknown
	}
}

// ReachabilityTargetOf returns the module path (or local path) whose code
// actually compiles for a replace directive — what must analyse
// instead of the original coordinate. Empty for an exclude.
func ReachabilityTargetOf(d Directive) string {
	if d.Kind != KindReplace {
		return ""
	}
	if d.IsLocal {
		return d.LocalPath
	}
	if d.NewPath != "" {
		return d.NewPath
	}
	return d.OldPath
}
