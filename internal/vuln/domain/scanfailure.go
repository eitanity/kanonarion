package domain

import "strings"

// IsBuildIncompatibility reports whether a scan-failure detail indicates the
// module could not be loaded or built under the host Go toolchain — for
// example an older version that no longer compiles — rather than a fault in the
// scanner itself. Source-mode analysis is impossible for such a module in this
// environment, so the scan falls back to metadata-only matching and the result
// is recorded as a coverage gap, never as a confident clean.
func IsBuildIncompatibility(detail string) bool {
	d := strings.ToLower(detail)
	for _, sig := range []string{
		"loading packages",
		"errors with the provided package patterns",
		"build constraints exclude all go files",
		"no required module provides package",
	} {
		if strings.Contains(d, sig) {
			return true
		}
	}
	return false
}

// ClassifyBuildIncompatibility returns a short human-readable category for a
// build-incompatibility failure given the raw error detail string. The category
// names the structural root cause so callers can display an actionable reason
// without reproducing the full govulncheck stderr.
func ClassifyBuildIncompatibility(detail string) string {
	d := strings.ToLower(detail)
	switch {
	case strings.Contains(d, "go.work file") && (strings.Contains(d, "no such file or directory") || strings.Contains(d, "cannot load module")):
		return "go.work mono-repo: sibling modules not present in module zip"
	case strings.Contains(d, "replacement directory") && strings.Contains(d, "does not exist"):
		return "relative replace directive: sibling module not present in module zip"
	case strings.Contains(d, "build constraints exclude all go files") && strings.Contains(d, "windows"):
		return "Windows-only package: not buildable on Linux"
	case strings.Contains(d, "fatal error:") && strings.Contains(d, ".h: no such file or directory"):
		return "requires C system headers not available on this host"
	case strings.Contains(d, "missing go.sum entry"):
		return "missing go.sum entry: module cannot be resolved without network access"
	case strings.Contains(d, "module lookup disabled by goproxy=off"):
		return "requires a module version outside the analysed project toolchain: scanned in isolation it selects a dependency version the project's build list never resolved, so it is absent from the verified store"
	case strings.Contains(d, "undefined:"):
		return "missing generated or embedded assets (module requires a code-generation step not present in the module zip)"
	default:
		return "module does not build under the host Go toolchain"
	}
}

// LocalReplaceUnscannableReason returns the human-readable UnscannableReason
// prose for a module that is a local filesystem replacement. The local path is
// retained in the message so a consumer keeps the same detail the retired
// error_detail string carried, now under the structured taxonomy field.
func LocalReplaceUnscannableReason(localPath string) string {
	return "local filesystem replacement at " + localPath +
		": not a fetched module version, so source is unavailable for vulnerability scanning"
}

// StructuredUnscanReason returns the machine-readable UnscanReason for a
// build-incompatibility failure. It mirrors ClassifyBuildIncompatibility but
// returns a typed constant instead of human prose, allowing consumers to filter
// or route on the root cause without string parsing.
func StructuredUnscanReason(detail string) UnscanReason {
	d := strings.ToLower(detail)
	switch {
	case strings.Contains(d, "go.work file") && (strings.Contains(d, "no such file or directory") || strings.Contains(d, "cannot load module")):
		return UnscanReasonGoWorkMonorepo
	case strings.Contains(d, "replacement directory") && strings.Contains(d, "does not exist"):
		return UnscanReasonRelativeReplace
	case strings.Contains(d, "build constraints exclude all go files") && strings.Contains(d, "windows"):
		return UnscanReasonWindowsOnly
	case strings.Contains(d, "fatal error:") && strings.Contains(d, ".h: no such file or directory"):
		return UnscanReasonCHeadersMissing
	case strings.Contains(d, "missing go.sum entry"):
		return UnscanReasonMissingGoSum
	case strings.Contains(d, "module lookup disabled by goproxy=off"):
		return UnscanReasonVersionNotInToolchain
	case strings.Contains(d, "undefined:"):
		return UnscanReasonGeneratedAssets
	default:
		return UnscanReasonBuildIncompatible
	}
}
