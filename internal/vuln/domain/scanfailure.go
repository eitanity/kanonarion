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
		if coord, ok := coordinateFromLine(line); ok {
			return coord, true
		}
	}
	return coordinate.ModuleCoordinate{}, false
}

// coordinateFromLine extracts the module version a single offline-resolution
// line names, if it names one. It is the per-line kernel of UnresolvedCoordinate,
// factored out so the source-position recovery can ask "does this line already
// name a coordinate?" without re-implementing the parse.
func coordinateFromLine(line string) (coordinate.ModuleCoordinate, bool) {
	idx := strings.Index(strings.ToLower(line), goProxyOffMarker)
	if idx < 0 {
		return coordinate.ModuleCoordinate{}, false
	}
	prefix := strings.TrimSpace(line[:idx])
	prefix = strings.TrimSuffix(prefix, ":")
	fields := strings.Fields(prefix)
	if len(fields) == 0 {
		return coordinate.ModuleCoordinate{}, false
	}
	token := strings.TrimSuffix(fields[len(fields)-1], ":")
	at := strings.LastIndex(token, "@")
	if at <= 0 || at == len(token)-1 {
		return coordinate.ModuleCoordinate{}, false
	}
	path, version := token[:at], token[at+1:]
	// A version always starts with "v"; without that check a source position
	// or an arbitrary token containing "@" would be read as a coordinate.
	if !strings.HasPrefix(version, "v") {
		return coordinate.ModuleCoordinate{}, false
	}
	// A module version never contains a path separator or a colon, and a module
	// path is never absolute. A source position whose absolute path embeds the
	// module — "/tmp/modcache/example.com/mod@v1.2.1/file.go:3:4: module lookup
	// disabled by GOPROXY=off" — splits on that "@" into an absolute path and a
	// "v1.2.1/file.go:3:4" pseudo-version. Rejecting both shapes keeps such a line
	// from being misread as naming mod@v1.2.1; it is the source-position shape,
	// which UnresolvedImportPath recovers from the paired could-not-import line.
	if strings.ContainsAny(version, "/:") || strings.HasPrefix(path, "/") {
		return coordinate.ModuleCoordinate{}, false
	}
	return coordinate.ModuleCoordinate{Path: path, Version: version}, true
}

// couldNotImportMarker is the toolchain's wording when a source position fails
// to load because its import could not be resolved. It is the companion line to
// a goProxyOffMarker line sharing the same source position, and it names the
// package the module could not import — the recovery input UnresolvedCoordinate
// has none of, because a source-position failure names no coordinate.
const couldNotImportMarker = "could not import "

// UnresolvedImportPath returns the package import path an offline resolution
// failure names when it attributes the failure to a source position rather than
// to a module coordinate — the dominant shape UnresolvedCoordinate cannot read.
//
// The toolchain emits this failure as a pair of lines sharing one source
// position: "<pos>: module lookup disabled by GOPROXY=off" names the failure but
// no module, and "<pos>: could not import <path> (...)" names the package that
// could not be imported. This resolves the pair by position and returns <path>.
// The caller maps that package to its module and reads the version the scanned
// module's own go.mod selects for it, which is the coordinate the toolchain
// could not resolve — the input the version-not-in-toolchain verdict must be
// checked against rather than asserted from.
//
// A line that already names a coordinate is skipped: it is UnresolvedCoordinate's
// to read, and pairing it here would recover a package path redundantly.
func UnresolvedImportPath(detail string) (string, bool) {
	var positions []string
	for _, line := range strings.Split(detail, "\n") {
		idx := strings.Index(strings.ToLower(line), goProxyOffMarker)
		if idx < 0 {
			continue
		}
		if _, named := coordinateFromLine(line); named {
			continue
		}
		if pos := failurePosition(line[:idx]); pos != "" {
			positions = append(positions, pos)
		}
	}
	if len(positions) == 0 {
		return "", false
	}
	for _, line := range strings.Split(detail, "\n") {
		mi := strings.Index(strings.ToLower(line), couldNotImportMarker)
		if mi < 0 {
			continue
		}
		if !positionMatchesAny(failurePosition(line[:mi]), positions) {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(line[mi+len(couldNotImportMarker):]))
		if len(fields) == 0 {
			continue
		}
		path := strings.TrimSuffix(fields[0], ":")
		if looksLikeImportPath(path) {
			return path, true
		}
	}
	return "", false
}

// failurePosition returns the file:line:col position a toolchain diagnostic
// prefixes its message with, given the text preceding the message marker. It is
// the last whitespace-separated token with a trailing colon stripped; a bare
// filename ("rich_url.go:7:2") and an absolute path
// ("/tmp/x/rich_url.go:7:2") both reduce to a single token, which
// positionMatchesAny then compares on their shared suffix.
func failurePosition(prefix string) string {
	prefix = strings.TrimSuffix(strings.TrimSpace(prefix), ":")
	fields := strings.Fields(prefix)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// positionMatchesAny reports whether pos names the same source position as any
// entry in positions. The two lines of an offline-resolution pair report the
// position at different path depths — one a bare filename, the other an absolute
// path — so equality alone would miss the pair; a suffix match on a path
// boundary ties "/tmp/x/rich_url.go:7:2" to "rich_url.go:7:2".
func positionMatchesAny(pos string, positions []string) bool {
	if pos == "" {
		return false
	}
	for _, p := range positions {
		if pos == p || strings.HasSuffix(pos, "/"+p) || strings.HasSuffix(p, "/"+pos) {
			return true
		}
	}
	return false
}

// looksLikeImportPath reports whether p is a plausible Go import path: its first
// segment carries a dot, the domain of a module path. It rejects the stray
// tokens a "could not import" line can trail (a bare word, an empty package
// name) so the recovery resolves a real package to a module rather than a
// coordinate invented from noise.
func looksLikeImportPath(p string) bool {
	if p == "" {
		return false
	}
	first := p
	if i := strings.IndexByte(p, '/'); i >= 0 {
		first = p[:i]
	}
	return strings.Contains(first, ".")
}

// LongestModulePrefix returns the longest module path in modulePaths that is a
// prefix of importPath on a path boundary — the module that provides the
// package. golang.org/x/net/publicsuffix resolves to golang.org/x/net when both
// golang.org/x and golang.org/x/net are present, never to the shorter one. ok
// is false when no module path covers the package, in which case the caller
// cannot name a coordinate and must not assert one.
func LongestModulePrefix(importPath string, modulePaths map[string]struct{}) (string, bool) {
	best := ""
	for m := range modulePaths {
		if m == "" {
			continue
		}
		if importPath == m || strings.HasPrefix(importPath, m+"/") {
			if len(m) > len(best) {
				best = m
			}
		}
	}
	return best, best != ""
}

// ClassifyOfflineResolution decides the reason and category prose for a
// version-not-in-toolchain failure from the evidence available, so the verdict
// is established rather than asserted. coord is the version the toolchain could
// not resolve, recovered by the caller (across both error shapes); recovered is
// false when none could be recovered from the error. known is the walk's node
// and superseded-edge coordinate set.
//
//   - No known set (a bare per-module scan with no graph): nothing to verify
//     against, so the conservative out-of-toolchain reading is preserved with the
//     standard category prose, matching callers that scan without a walk.
//   - Recovered and in the known set: incomplete-scan-cache, a fault — kanonarion
//     undertook to supply that version and did not.
//   - Recovered and outside the set: version-not-in-toolchain, confirmed and
//     stated with the coordinate that proves it.
//   - Not recovered: version-not-in-toolchain-unverified — the cause could not be
//     checked, so the reason says so rather than asserting an out-of-toolchain
//     re-selection nothing established. A genuine scan-cache hole produces the
//     same wording, and marking it expected on no evidence is the failure mode
//     this discrimination exists to prevent.
func ClassifyOfflineResolution(
	detail string,
	coord coordinate.ModuleCoordinate,
	recovered bool,
	known map[coordinate.ModuleCoordinate]struct{},
) (UnscanReason, string) {
	if len(known) == 0 {
		return UnscanReasonVersionNotInToolchain, ClassifyBuildIncompatibility(detail)
	}
	if !recovered {
		return UnscanReasonVersionNotInToolchainUnverified, UnverifiedOfflineResolutionReason()
	}
	if _, isKnown := known[coord]; isKnown {
		return UnscanReasonIncompleteScanCache, IncompleteScanCacheReasonForCoord(coord)
	}
	return UnscanReasonVersionNotInToolchain, VerifiedOutOfToolchainReason(coord)
}

// incompleteScanCacheBase is the category prose an incomplete-scan-cache outcome
// carries before the missing coordinate, when one is known, is appended.
const incompleteScanCacheBase = "incomplete scan cache: a module version the walk graph records could not be resolved offline"

// IncompleteScanCacheReason returns the human-readable category for an
// incomplete-scan-cache outcome, naming the version that was missing when the
// error identifies one.
func IncompleteScanCacheReason(detail string) string {
	if coord, ok := UnresolvedCoordinate(detail); ok {
		return IncompleteScanCacheReasonForCoord(coord)
	}
	return incompleteScanCacheBase
}

// IncompleteScanCacheReasonForCoord names the missing version from a coordinate
// the caller has already recovered. The source-position error shape names no
// coordinate in its own text, so IncompleteScanCacheReason cannot parse one from
// it; a caller that recovered the coordinate by other means passes it here so
// the operator is still told which version the scan cache is missing.
func IncompleteScanCacheReasonForCoord(coord coordinate.ModuleCoordinate) string {
	return incompleteScanCacheBase + " (" + coord.String() + ")"
}

// VerifiedOutOfToolchainReason is the category prose for a version-not-in-toolchain
// verdict whose coordinate was recovered and confirmed absent from the walk's
// known set. Naming the coordinate is what separates this established verdict
// from the same words asserted with no version behind them: the reader can check
// coord against the project's build list, which is exactly what an unverified
// reason denies them.
func VerifiedOutOfToolchainReason(coord coordinate.ModuleCoordinate) string {
	return "requires a module version outside the analysed project toolchain (" + coord.String() +
		"): scanned in isolation it selects a dependency version the project's build list never resolved, so it is absent from the verified store"
}

// UnverifiedOfflineResolutionReason is the category prose for an offline
// resolution failure whose version could not be recovered from the toolchain
// error at all. It states the uncertainty rather than asserting a cause: with no
// coordinate to compare against the walk, whether the module reaches outside the
// project toolchain or the scan cache is incomplete is genuinely unknown, and a
// scan-cache hole producing this wording would otherwise be filed as expected
// and never investigated. The verdict is presented as a coverage gap to look
// into, not an expected out-of-toolchain outcome carrying confidence it lacks.
func UnverifiedOfflineResolutionReason() string {
	return "offline module resolution failed but no version could be recovered from the toolchain error, " +
		"so whether the module reaches outside the project toolchain or the scan cache is incomplete is unverified: " +
		"treat as a coverage gap to investigate, not an expected out-of-toolchain outcome"
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
