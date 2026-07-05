package ports

import (
	"context"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
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
}

// VulnFindingLoader loads stored CVE findings for a set of module coordinates.
// It is the read-only bridge between the global vuln store and a local
// reachability analysis run.
type VulnFindingLoader interface {
	// LoadFindings returns all stored CVE findings for each coordinate that has
	// at least one finding. Coordinates with no findings are omitted from the
	// result; errors for individual modules are surfaced in the error return.
	LoadFindings(ctx context.Context, coords []fetchdomain.ModuleCoordinate) (map[fetchdomain.ModuleCoordinate][]VulnFinding, error)
}

// SymbolProbeResult is returned by SymbolTableProber.Probe.
type SymbolProbeResult struct {
	// BinarySymbols is the complete set of fully-qualified Go symbol names
	// present in the probe binary (as reported by go tool nm).
	BinarySymbols map[string]struct{}
	// Kind is "binary" when a main package binary was built directly, or
	// "library" when a synthetic reference harness was compiled.
	Kind string
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
	LoadCallGraphRecords(ctx context.Context, coords []fetchdomain.ModuleCoordinate, pipelineVersion string) ([]callgraphdomain.CallGraphRecord, error)
}

// WorkspaceInfo carries the parsed metadata extracted from a Snapshot.
// It is the input to scope auto-detection and root selection.
type WorkspaceInfo struct {
	// Kind classifies the workspace for scope auto-detection.
	Kind domain.WorkspaceKind
	// Funcs contains all function and method declarations found in the snapshot.
	Funcs []domain.FuncDecl
}

// WorkspaceAnalyser parses a Snapshot and extracts the function declarations
// needed for dynamic callgraph root selection. Implementations may use
// go/ast or go/packages; the interface is intentionally narrow.
type WorkspaceAnalyser interface {
	// Analyse parses the Go source files in snap and returns the workspace
	// metadata needed to select callgraph roots. Files in the snapshot are
	// read from snap.Files; no disk access is performed.
	Analyse(ctx context.Context, snap domain.Snapshot) (WorkspaceInfo, error)
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
