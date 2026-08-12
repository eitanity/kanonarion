package ports

import (
	"time"

	"context"

	"github.com/eitanity/kanonarion/internal/coordinate"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"

	"github.com/eitanity/kanonarion/internal/local/domain"
)

// VulnFinding is the minimal CVE finding representation the local context
// needs for symbol probing. It mirrors vuln/domain.VulnerabilityFinding without
// depending on that package, keeping the cross-context boundary clean.
type VulnFinding struct {
	ID              string
	Aliases         []string
	Summary         string
	AffectedSymbols []string // govulncheck-style: "FuncName" or "(*Type).Method"
	// Reachable is govulncheck's own call-graph reachability verdict for this
	// finding, as captured by the stored scan. nil means the scan did not
	// determine reachability (e.g. a module/binary-mode scan), so the symbol
	// table probe is the only available signal.
	Reachable *bool
	// AdvisoryNamesNoSymbols reports that the advisory entry matching this
	// finding's module path names no symbols at all, so there was never a symbol
	// to probe for. It is why AffectedSymbols is empty, and it must be carried:
	// without it an empty symbol list falls through to the stored govulncheck
	// verdict and reports "unreachable", which claims a search that could not
	// have been run.
	AdvisoryNamesNoSymbols bool
	// ReachableBasis states how the stored Reachable verdict was derived and in
	// which analysis frame — the record's own derivation, rendered. It is empty
	// when Reachable is nil.
	//
	// It is carried because Reachable is a bool and a bool cannot say whose build
	// it is about. A verdict seeded from a stored scan is reported with its basis
	// so a reader can tell it from one this probe measured.
	ReachableBasis string
	// ReachableSoundness and ReachableSoundnessReason state how thorough the
	// search behind a stored NEGATIVE was, and why that rung. They are carried as
	// strings for the same reason ReachableBasis is: the loader that reads the
	// stored finding is the only place that holds the producing analyser and its
	// fidelity, so the rung is derived there and travels with the verdict rather
	// than being guessed at further down.
	//
	// Empty when the stored answer states no rung — a positive, or no answer at
	// all. A probe that carries a stored negative through to its own output must
	// carry these with it, or it republishes someone else's negative stripped of
	// what was searched to reach it.
	ReachableSoundness       string
	ReachableSoundnessReason string
}

// Clock supplies the current time. The local probe stamps when its answer was
// computed, and a stamp read straight off the wall clock is untestable — the
// architecture rule that forbids time.Now below the adapter layer exists so the
// stamp can be pinned.
type Clock interface {
	// Now returns the current time.
	Now() time.Time
}

// FindingSet is what the store held for the coordinates a local run asked
// about.
//
// Scanned is carried alongside Findings because "no findings" and "no record"
// are different facts that the findings map alone renders identically. A
// coordinate the store has never seen is unknown; a coordinate with a record and
// an empty finding set is clean. Reporting the first as the second is the
// mistake this type exists to make impossible.
type FindingSet struct {
	// Findings holds the stored findings for each coordinate that had at least
	// one. Coordinates with none are absent.
	Findings map[coordinate.ModuleCoordinate][]VulnFinding
	// Scanned is every coordinate the store held a vulnerability record for,
	// with or without findings.
	Scanned map[coordinate.ModuleCoordinate]struct{}
	// OtherFrameOnly is every coordinate the store held records for that were
	// all measured in some other build's frame. They are not scanned — nothing
	// measured THIS build — but they are not unknown to the store either, and
	// the two absences take different remedies.
	OtherFrameOnly map[coordinate.ModuleCoordinate]struct{}
	// SupersededOnly is every coordinate the store holds records for at some
	// other pipeline version only. The loader reads at one version, so a bump
	// empties it for them; they are not scanned for this build's purposes, and
	// they are emphatically not unscanned. Reporting a superseded record as a
	// coverage gap is how a stale cache comes to read as a dependency nobody
	// has ever checked.
	SupersededOnly map[coordinate.ModuleCoordinate]struct{}
	// Restriction states, in one line, which records the loader was willing to
	// draw this seed from. It is reported with the answer: a store holding
	// several projects' scans holds several answers per coordinate, and which of
	// them a probe was seeded from is not a detail the tool may settle silently.
	Restriction string
}

// VulnFindingLoader loads stored CVE findings for a set of module coordinates,
// as measured for one consumer. It is the read-only bridge between the global
// vuln store and a local reachability analysis run.
type VulnFindingLoader interface {
	// LoadFindings returns the stored findings for each coordinate that has at
	// least one, and the set of coordinates a record was held for at all.
	// Errors for individual modules are surfaced in the error return.
	//
	// consumerModulePath is the module path of the tree being probed, and it is
	// what the seed is anchored to: a record measured in another consumer's build
	// answers a question about that build, and must not seed this one. A
	// coordinate with no acceptable record simply seeds nothing — the probe
	// measures, and an empty seed is an absence rather than an error.
	LoadFindings(ctx context.Context, coords []coordinate.ModuleCoordinate, consumerModulePath string) (FindingSet, error)
}

// BuildModuleLister enumerates every module the local build resolves.
//
// It is separate from ImportAnalyser because the two answer different questions.
// ImportAnalyser answers "which dependencies does this workspace's own code
// reach for", which is what a context report is about. This answers "which
// modules go into the artefact", which is what anything measuring the built
// binary must be scoped to.
type BuildModuleLister interface {
	// BuildModules returns one entry per non-main module in the build, sorted by
	// path. Modules the build resolves without a version carry an empty Version
	// rather than being dropped.
	BuildModules(ctx context.Context, root string) ([]domain.BuildModule, error)
}

// ProbedBinary is one main package the probe enumerated: its symbol table, or
// the error that stopped it being built.
//
// A project with more than one main ships more than one artefact, and a symbol
// linked into only one of them is present in the product. Attribution is kept
// per binary rather than collapsed into the union alone so the answer can name
// which binary carries the symbol.
type ProbedBinary struct {
	// ImportPath is the main package's import path.
	ImportPath string
	// Symbols is the set of fully-qualified Go symbol names present in this
	// binary (as reported by go tool nm). Nil when BuildError is set.
	Symbols map[string]struct{}
	// BuildError is the build or symbol-read failure for this main, empty when
	// the binary was probed. A main that fails to build does not fail the probe;
	// it is carried here so the answer can say which binary it cannot speak
	// about, and why.
	BuildError string
}

// SymbolProbeResult is returned by SymbolTableProber.Probe.
type SymbolProbeResult struct {
	// BinarySymbols is the union of the symbol names present in every probe
	// binary that built (as reported by go tool nm).
	BinarySymbols map[string]struct{}
	// Kind is "binary" when main package binaries were built directly, or
	// "library" when a synthetic reference harness was compiled.
	Kind string
	// Binaries is one entry per main package the enumeration found, built or
	// failed, sorted by import path. Empty for a library probe, which has no
	// main package to attribute a symbol to.
	Binaries []ProbedBinary
}

// SymbolTableProber builds a probe binary from a local workspace with inlining
// disabled (-gcflags='all=-l') and reads the resulting symbol table.
type SymbolTableProber interface {
	// Probe builds the probe binary for the workspace rooted at root and
	// returns its full symbol table. The binary is discarded after reading.
	Probe(ctx context.Context, root string) (SymbolProbeResult, error)
}

// SnapshotBuilder captures a local Go workspace into a frozen Snapshot.
type SnapshotBuilder interface {
	// Build walks root and reads all.go, go.mod, and go.sum files into a
	// Snapshot. Absolute file paths are used as map keys so the result is
	// ready for use as go/packages.Config.Overlay.
	Build(ctx context.Context, root string) (domain.Snapshot, error)
}

// DependencyLoader loads callgraph records from the global store for a given
// set of module coordinates. It is the read-only bridge between the global
// persistent store and an ephemeral AnalysisSession.
type DependencyLoader interface {
	// LoadCallGraphRecords fetches the callgraph record for each coordinate
	// from the global store at the given pipeline version. Coordinates that
	// have no stored record are silently omitted from the result — the caller
	// decides how to handle gaps in coverage.
	LoadCallGraphRecords(ctx context.Context, coords []coordinate.ModuleCoordinate, pipelineVersion string) ([]callgraphdomain.CallGraphRecord, error)
}

// ImportAnalyser identifies which packages from dependency modules are
// actually imported by the local workspace. Implementations run go list -json.
type ImportAnalyser interface {
	// AnalyseImports returns one ImportedModule per external dependency module
	// that the workspace imports at least one package from. Modules are sorted
	// by path; packages within each module are sorted by import path.
	AnalyseImports(ctx context.Context, root string) ([]domain.ImportedModule, error)
}

// SymbolAnalyser identifies which exported symbols from dependency packages are
// referenced by the local workspace. Implementations use go/packages
// type-checking (~2-5s). The result includes ImportedPackages (same scope as
// ImportAnalyser) plus UsedSymbols per module.
type SymbolAnalyser interface {
	// AnalyseSymbols returns one ImportedModule per external dependency module.
	// Both ImportedPackages and UsedSymbols are populated.
	AnalyseSymbols(ctx context.Context, root string) ([]domain.ImportedModule, error)
}
