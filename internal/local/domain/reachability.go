package domain

import (
	"sort"
	"time"
)

// BuildModule is one module the local build resolves — every non-main module
// `go list -deps ./...` reports, direct and transitive alike.
//
// The probe enumerates the whole build rather than the modules the workspace
// imports directly, because the binary it reads the symbol table of contains the
// whole build. Restricting the finding lookup to direct imports made the probe
// answer about a smaller set than the artefact it measured, and say nothing
// about the difference: a module reached only through a dependency — a JWT
// library pulled in by a SAML library, say — never entered the lookup at all, so
// a stored Affected finding for it was absent from the answer rather than
// reported.
type BuildModule struct {
	// Path is the module path.
	Path string
	// Version is the version the build selected. Empty when the build resolves
	// the module through a directory replacement, which names no coordinate.
	Version string
	// Direct reports whether a package of the main module imports a package of
	// this module in its non-test files.
	Direct bool
}

// Reasons a module in the local build carries no probe answer. They are stated
// rather than left to the reader: "not in the answer" has more than one cause
// and they take different remedies.
const (
	// UncoveredNoStoredRecord means the store holds no vulnerability record for
	// the coordinate, so nothing is known about it either way. It is NOT
	// "no known vulnerabilities" — that is a record with no findings, which is
	// an answer and is counted as covered.
	UncoveredNoStoredRecord = "no stored vulnerability record for this coordinate; it has never been vuln-scanned"
	// UncoveredNoCoordinate means the build resolves the module without a
	// version — a directory replacement — so there is no coordinate to look up.
	UncoveredNoCoordinate = "the local build resolves this module without a version (a directory replacement), so it names no coordinate to look up"
)

// UncoveredModule is one module in the local build the probe holds no answer
// about, and why.
type UncoveredModule struct {
	Path    string
	Version string
	Reason  string
}

// SortUncovered sorts mods in place by Path then Version for deterministic
// output.
func SortUncovered(mods []UncoveredModule) {
	sort.Slice(mods, func(i, j int) bool {
		if mods[i].Path != mods[j].Path {
			return mods[i].Path < mods[j].Path
		}
		return mods[i].Version < mods[j].Version
	})
}

// ProbeCoverage states what a local probe's answer was drawn from and what it
// left out, so an incomplete answer is visibly incomplete.
//
// A probe that reports ten modules and omits the eleventh reads exactly like a
// probe that examined eleven and cleared one. An operator asking "is the
// advisory I just found reachable from my product" is answered by the module's
// absence, and absence is the one thing in this output that carried no
// meaning at all.
type ProbeCoverage struct {
	// TakenAt is when the workspace snapshot behind VersionID was built. The
	// snapshot is computed from the working tree on every run, so this is the
	// age of the answer, not of a cache.
	TakenAt time.Time
	// BuildModules is how many non-main modules the local build resolves.
	BuildModules int
	// Queried is how many of them named a coordinate the store was asked about.
	Queried int
	// Covered is how many of those the store held a vulnerability record for,
	// with or without findings — the modules this answer speaks about.
	Covered int
	// WithFindings is how many carried at least one stored finding; these are
	// the entries in LocalReachabilityResult.Modules.
	WithFindings int
	// Uncovered names every module in the build this answer does not speak
	// about, with its reason. It is never capped: a cap would reintroduce the
	// silent omission this field exists to end.
	Uncovered []UncoveredModule
}

// SymbolProbeVerdict is the result of checking whether a CVE-affected symbol
// ships in the probe binary built from the local workspace.
type SymbolProbeVerdict string

const (
	// SymbolProbePresent means at least one affected symbol was found in the
	// probe binary's symbol table — the vulnerable code is present.
	SymbolProbePresent SymbolProbeVerdict = "present"
	// SymbolProbeAbsent means no affected symbols were found — the linker's
	// dead-code elimination removed the vulnerable code.
	SymbolProbeAbsent SymbolProbeVerdict = "absent"
	// SymbolProbeUnknown means the CVE record carries no AffectedSymbols and
	// the stored scan recorded no govulncheck reachability, so no
	// determination is possible from stored data.
	SymbolProbeUnknown SymbolProbeVerdict = "unknown"
	// SymbolProbeReachable means the symbol table probe could not run (no
	// AffectedSymbols) but the stored govulncheck scan marked the finding
	// reachable from the scanned module's entry points.
	SymbolProbeReachable SymbolProbeVerdict = "reachable"
	// SymbolProbeUnreachable means the stored govulncheck scan marked the
	// finding not reachable; used as the fallback when no AffectedSymbols are
	// available for a symbol table probe.
	SymbolProbeUnreachable SymbolProbeVerdict = "unreachable"
)

// VerdictSource identifies which signal produced a SymbolProbeFinding.Verdict.
type VerdictSource string

const (
	// VerdictSourceSymbolTable means the verdict came from probing the built
	// binary's symbol table (present/absent).
	VerdictSourceSymbolTable VerdictSource = "symbol-table"
	// VerdictSourceGovulncheck means the verdict was taken from the stored
	// govulncheck reachability result (reachable/unreachable) because the
	// finding had no AffectedSymbols to probe.
	VerdictSourceGovulncheck VerdictSource = "govulncheck"
	// VerdictSourceNone means no signal was available (unknown verdict).
	VerdictSourceNone VerdictSource = ""
)

// SymbolProbeFinding is the per-CVE result of a symbol table probe.
type SymbolProbeFinding struct {
	// CVEID is the OSV/CVE/GHSA identifier.
	CVEID string
	// Aliases contains alternate identifiers (CVE-..., GHSA-...).
	Aliases []string
	// Summary is a short human-readable description.
	Summary string
	// Verdict is the probe outcome for this finding.
	Verdict SymbolProbeVerdict
	// VerdictSource records which signal produced Verdict.
	VerdictSource VerdictSource
	// Reason explains an unknown verdict (empty otherwise).
	Reason string
	// MatchedSymbols lists the affected symbols that were found in the binary.
	// Populated only when Verdict == SymbolProbePresent.
	MatchedSymbols []string
}

// ModuleProbeResult is the reachability verdict for one dependency module.
type ModuleProbeResult struct {
	// Path is the module path (e.g. "golang.org/x/text").
	Path string
	// Version is the module version.
	Version string
	// Findings is the per-CVE symbol probe results.
	Findings []SymbolProbeFinding
}

// LocalReachabilityResult is the full output of a local workspace symbol probe.
type LocalReachabilityResult struct {
	// Root is the absolute workspace directory path.
	Root string
	// ModulePath is the Go module path from go.mod.
	ModulePath string
	// VersionID is the deterministic snapshot version (local-<sha256>).
	VersionID string
	// ProbeKind is "binary" when a main package was built directly,
	// "library" when a synthetic harness was generated, or "skipped" when no
	// matched finding had AffectedSymbols so the probe build was elided.
	ProbeKind string
	// Modules contains one entry per dependency module that had stored CVE
	// findings. Modules with no stored findings are omitted — Coverage says how
	// many were omitted and why, so the omission is stated rather than inferred.
	Modules []ModuleProbeResult
	// Coverage states what this answer was drawn from and what it left out.
	Coverage ProbeCoverage
	// Notice is a human-readable explanation when the result is empty or
	// degraded (no stored findings for any dependency, or the probe was
	// skipped). Empty when a full symbol table probe ran.
	Notice string
}

// SortProbeModules sorts mods in place by Path for deterministic output.
func SortProbeModules(mods []ModuleProbeResult) {
	sort.Slice(mods, func(i, j int) bool {
		return mods[i].Path < mods[j].Path
	})
}
