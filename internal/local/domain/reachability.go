package domain

import "sort"

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
	// findings. Modules with no stored findings are omitted.
	Modules []ModuleProbeResult
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
