package domain

import (
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

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
	case isWorkspaceModeFailure(d):
		return "scan environment entered Go workspace mode: a go.work applied to a module scanned in isolation"
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
	case hasQualifiedUndefinedSymbol(d):
		return "missing generated or embedded assets (module requires a code-generation step not present in the module zip)"
	case strings.Contains(d, "undefined:"):
		return "package declarations missing: files excluded by build constraints, commonly a host Go version outside the range the module supports"
	default:
		return "module does not build under the host Go toolchain"
	}
}

// isWorkspaceModeFailure reports whether an already-lowercased error detail is
// the toolchain refusing to proceed because it is in workspace mode. It is
// matched ahead of the go.work mono-repo case: that one names a module whose
// workspace genuinely references absent siblings, whereas this one names a scan
// environment that let workspace mode apply at all, which the scanner disables
// (GOWORK=off). Seeing it means the environment is misconfigured, not that the
// module fails to build, so it must not fall through to the generic default.
func isWorkspaceModeFailure(d string) bool {
	return strings.Contains(d, "in workspace mode") || strings.Contains(d, "gowork=off to disable workspace mode")
}

// goProxyOffMarker is the toolchain's wording when an offline resolution needs a
// module version the cache does not hold.
const goProxyOffMarker = "module lookup disabled by goproxy=off"

// UnresolvedCoordinate returns the module version named by an offline
// resolution failure, if the error names one. The toolchain reports the failure
// as "<path>@<version>: module lookup disabled by GOPROXY=off", sometimes as the
// last line of a "requires" chain. Not every occurrence names a module: a failure
// attributed to a source position ("stdr.go:25:2: module lookup disabled by
// GOPROXY=off") names none, and the second return value is false.
//
// Knowing which version is missing is what separates a cache kanonarion failed to
// fill from a version the project genuinely never resolved, so this parse is the
// input to that distinction rather than a convenience for log prose.
func UnresolvedCoordinate(detail string) (coordinate.ModuleCoordinate, bool) {
	for _, line := range strings.Split(detail, "\n") {
		idx := strings.Index(strings.ToLower(line), goProxyOffMarker)
		if idx < 0 {
			continue
		}
		prefix := strings.TrimSpace(line[:idx])
		prefix = strings.TrimSuffix(prefix, ":")
		fields := strings.Fields(prefix)
		if len(fields) == 0 {
			continue
		}
		token := strings.TrimSuffix(fields[len(fields)-1], ":")
		at := strings.LastIndex(token, "@")
		if at <= 0 || at == len(token)-1 {
			continue
		}
		path, version := token[:at], token[at+1:]
		// A version always starts with "v"; without that check a source position
		// or an arbitrary token containing "@" would be read as a coordinate.
		if !strings.HasPrefix(version, "v") {
			continue
		}
		return coordinate.ModuleCoordinate{Path: path, Version: version}, true
	}
	return coordinate.ModuleCoordinate{}, false
}

// RefineOfflineResolutionReason downgrades a version-not-in-toolchain verdict to
// incomplete-scan-cache when the version the toolchain could not resolve is one
// the walk already knows about. known is the walk's node and superseded-edge
// coordinate set; a nil or empty set leaves the reason untouched, so a caller
// scanning without a graph keeps the conservative out-of-toolchain reading.
//
// Without this, every offline resolution failure lands in a bucket marked
// expected, and a cache kanonarion failed to fill is indistinguishable from a
// module whose isolated build reaches outside the project — the first is a bug,
// the second is by design.
func RefineOfflineResolutionReason(
	reason UnscanReason,
	detail string,
	known map[coordinate.ModuleCoordinate]struct{},
) UnscanReason {
	if reason != UnscanReasonVersionNotInToolchain || len(known) == 0 {
		return reason
	}
	coord, ok := UnresolvedCoordinate(detail)
	if !ok {
		return reason
	}
	if _, isKnown := known[coord]; isKnown {
		return UnscanReasonIncompleteScanCache
	}
	return reason
}

// IncompleteScanCacheReason returns the human-readable category for an
// incomplete-scan-cache outcome, naming the version that was missing when the
// error identifies one.
func IncompleteScanCacheReason(detail string) string {
	const base = "incomplete scan cache: a module version the walk graph records could not be resolved offline"
	if coord, ok := UnresolvedCoordinate(detail); ok {
		return base + " (" + coord.String() + ")"
	}
	return base
}

// hasQualifiedUndefinedSymbol reports whether an already-lowercased detail names
// at least one undefined symbol that is package-qualified ("undefined:
// assets.ReadFile") rather than a bare identifier ("undefined: moduledata").
//
// The distinction separates two failures the toolchain words identically. A
// qualified name means the import resolved but does not export that symbol,
// which is what an absent generated file looks like. A bare identifier means the
// declaration is missing from the package itself — the signature of every file
// that would declare it being excluded by build constraints, as happens when the
// host Go toolchain is outside the range the module supports.
//
// A detail mixing both reads as qualified: a genuinely missing generated file
// explains bare and qualified symbols alike, whereas build-constraint exclusion
// cannot produce a qualified one.
func hasQualifiedUndefinedSymbol(d string) bool {
	const marker = "undefined: "
	rest := d
	for {
		i := strings.Index(rest, marker)
		if i < 0 {
			return false
		}
		rest = rest[i+len(marker):]
		symbol := rest
		if cut := strings.IndexAny(symbol, " \t\n("); cut >= 0 {
			symbol = symbol[:cut]
		}
		if strings.Contains(symbol, ".") {
			return true
		}
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
	case isWorkspaceModeFailure(d):
		return UnscanReasonWorkspaceMode
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
	case hasQualifiedUndefinedSymbol(d):
		return UnscanReasonGeneratedAssets
	case strings.Contains(d, "undefined:"):
		return UnscanReasonPackageDeclarationsMissing
	default:
		return UnscanReasonBuildIncompatible
	}
}
