package ports

import (
	"context"
	"errors"
	"io"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/audit"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// AuditSink appends an audit event to the assurance log. The shared JSONL
// AuditLog satisfies this; the application depends only on this narrow port,
// not on the factstore adapter that persists it.
type AuditSink interface {
	RecordEvent(audit.Event) error
}

// ErrCallGraphNotFound is returned by CallGraphLoader when no record exists for the
// requested coordinate. Callers can use errors.Is to distinguish absence from
// integrity failures.
var ErrCallGraphNotFound = errors.New("call graph record not found")

// VulnerabilityStore defines the port for persisting vulnerability records.
type VulnerabilityStore interface {
	// PutVulnerabilityRecord persists a vulnerability record for a module.
	// Idempotent on (coordinate, pipelineVersion, snapshotIdentity).
	PutVulnerabilityRecord(ctx context.Context, record domain.VulnerabilityRecord) error

	// GetVulnerabilityRecord retrieves a record by coordinate, pipeline version, and snapshot.
	GetVulnerabilityRecord(
		ctx context.Context,
		coord coordinate.ModuleCoordinate,
		pipelineVersion string,
		snapshot domain.DatabaseSnapshot,
	) (domain.VulnerabilityRecord, bool, error)

	// GetLatestVulnerabilityRecord returns the most recently scanned record for a
	// coordinate and pipeline version, regardless of snapshot or walk ID.
	// Returns (zero, false, nil) if no record exists.
	GetLatestVulnerabilityRecord(
		ctx context.Context,
		coord coordinate.ModuleCoordinate,
		pipelineVersion string,
	) (domain.VulnerabilityRecord, bool, error)

	// GetLatestVulnerabilityRecordForWalk returns the most recently scanned record
	// for a coordinate, pipeline version, and walk ID, regardless of snapshot.
	// Returns (zero, false, nil) if no record exists for that walk.
	GetLatestVulnerabilityRecordForWalk(
		ctx context.Context,
		coord coordinate.ModuleCoordinate,
		pipelineVersion string,
		walkID string,
	) (domain.VulnerabilityRecord, bool, error)

	// PutWalkScanRun persists the aggregate result of a walk scan.
	PutWalkScanRun(ctx context.Context, run domain.WalkScanRun) error

	// GetWalkScanRun retrieves a walk scan run by its ID.
	GetWalkScanRun(ctx context.Context, id string) (domain.WalkScanRun, bool, error)

	// ListWalkScanRuns lists all scan runs for a specific walk.
	ListWalkScanRuns(ctx context.Context, walkID string) ([]domain.WalkScanRun, error)

	// ListAllWalkScanRuns lists all scan runs across all walks, most recent first.
	ListAllWalkScanRuns(ctx context.Context) ([]domain.WalkScanRun, error)

	// PutDatabaseSnapshot persists a vulnerability database snapshot blob.
	PutDatabaseSnapshot(ctx context.Context, snapshot domain.DatabaseSnapshot, content io.Reader) error

	// GetDatabaseSnapshot retrieves the blob content for a pinned snapshot.
	GetDatabaseSnapshot(ctx context.Context, snapshot domain.DatabaseSnapshot) (io.ReadCloser, error)

	// GetLatestDatabaseSnapshot returns the most recently stored snapshot metadata.
	// Returns (zero, false, nil) if no snapshot has been stored yet.
	GetLatestDatabaseSnapshot(ctx context.Context) (domain.DatabaseSnapshot, bool, error)

	// ListDatabaseSnapshots returns all stored snapshot metadata, most recent first.
	ListDatabaseSnapshots(ctx context.Context) ([]domain.DatabaseSnapshot, error)

	// ListVulnerabilityRecordsByFindingID returns all vulnerability records across
	// the store that contain a finding with the given OSV/CVE/GHSA identifier.
	ListVulnerabilityRecordsByFindingID(ctx context.Context, findingID string) ([]domain.VulnerabilityRecord, error)

	// ListVulnerabilityRecords returns all vulnerability records for a walk scan run.
	ListVulnerabilityRecords(ctx context.Context, walkScanRunID string) ([]domain.VulnerabilityRecord, error)

	// ListVulnerabilityRecordsForModule returns all stored scan records for a
	// coordinate and pipeline version across all walks and snapshots, ordered
	// by scanned_at descending (most recent first).
	ListVulnerabilityRecordsForModule(
		ctx context.Context,
		coord coordinate.ModuleCoordinate,
		pipelineVersion string,
	) ([]domain.VulnerabilityRecord, error)
}

// VulnerabilityScanner defines the port for a vulnerability scanner implementation.
type VulnerabilityScanner interface {
	// Preflight verifies the scanner's external prerequisites are available
	// (e.g. the govulncheck binary on PATH) so callers can fail fast with an
	// actionable error before any expensive scan setup. It returns nil when
	// the scanner is ready to run.
	Preflight(ctx context.Context) error
	Scan(
		ctx context.Context,
		coord coordinate.ModuleCoordinate,
		moduleSource io.Reader,
		snapshot domain.DatabaseSnapshot,
		goModCache string, // pre-populated GOMODCACHE dir; empty = govulncheck downloads as needed
		dbDir string, // pre-extracted vuln DB dir; empty = extract from store on each call
		scanMode domain.ScanMode, // source or binary; empty defaults to source
	) (domain.VulnerabilityRecord, error)
	// ScanProject runs one project-rooted scan over the project's live working
	// tree (the local main module a project walk is rooted at) and returns every
	// reachable finding grouped by the module that owns the vulnerable symbol.
	// It is how a project walk derives a per-module verdict for the whole build
	// from a single analysis the project actually produces, instead of scanning
	// each dependency in isolation. The working tree resolves its own build, so
	// the scan is live and uncached. A genuine fault is carried in the result's
	// Status; the error return is reserved for infrastructure failures.
	ScanProject(
		ctx context.Context,
		projectDir string, // the project's working-tree directory (contains go.mod)
		snapshot domain.DatabaseSnapshot,
		dbDir string, // pre-extracted vuln DB dir; empty = extract from store on each call
	) (domain.ProjectScanResult, error)
	ScannerMetadata() ScannerMetadata
}

// ScannerMetadata provides identity and version information for a scanner.
type ScannerMetadata struct {
	Name    string
	Version string
}

// VulnerabilityDatabase defines the port for managing vulnerability database snapshots.
type VulnerabilityDatabase interface {
	// Snapshot returns a pinned snapshot of the database at this point.
	// Subsequent calls may return different snapshots; the snapshot
	// itself is immutable.
	Snapshot(ctx context.Context) (domain.DatabaseSnapshot, io.ReadCloser, error)

	// GetSnapshot retrieves a previously-pinned snapshot by identity,
	// for replay or re-scanning.
	GetSnapshot(ctx context.Context, identity domain.DatabaseSnapshot) (io.ReadCloser, error)

	// CheckVulnerable checks if the given modules at specific versions have any known
	// vulnerabilities in the database. This is a lightweight metadata check.
	CheckVulnerable(ctx context.Context, modules []coordinate.ModuleCoordinate) (map[coordinate.ModuleCoordinate][]string, error)

	// LookupFindings returns enriched advisory metadata for every known
	// vulnerability affecting coord, sourced from the per-advisory OSV records:
	// summary, affected range, fixed version, affected symbols, and timestamps.
	// It is the metadata-path equivalent of source-mode findings — used when a
	// module cannot be scanned from source so each finding still answers "will a
	// version bump fix it?" and "which symbol is at risk?" without the user
	// leaving the tool to query the advisory database directly.
	LookupFindings(ctx context.Context, coord coordinate.ModuleCoordinate) ([]domain.VulnerabilityFinding, error)
}

// ModuleFetcher is a narrow port used by ScanWalkUseCase to pre-fetch modules
// that are missing from the fact store before populating the GOMODCACHE.
type ModuleFetcher interface {
	FetchModule(ctx context.Context, coord coordinate.ModuleCoordinate) error
}

// ReachabilityAnalyser defines the port for call-graph-based reachability analysis.
type ReachabilityAnalyser interface {
	Analyse(
		ctx context.Context,
		targetCoord coordinate.ModuleCoordinate,
		targetSymbols []SymbolReference,
		callGraphLoader CallGraphLoader,
	) (domain.ReachabilityResult, error)
}

// SymbolReference uniquely identifies a symbol in the fact base.
type SymbolReference struct {
	Module  string
	Package string
	Symbol  string
}

// CallGraphLoader loads a vuln-local projection of a module's call graph.
// It returns CallGraphProjection rather than callgraph/domain.CallGraphRecord
// so a callgraph schema change does not ripple into this port; the mapping
// lives in the reachability adapter.
type CallGraphLoader interface {
	Load(ctx context.Context, coord coordinate.ModuleCoordinate) (CallGraphProjection, error)
}

// CallGraphProjection is the minimal view of a call graph the reachability
// analyser consumes: the nodes and the directed call edges between them, plus
// the fidelity signature that backed them.
type CallGraphProjection struct {
	Nodes []CallGraphNode
	Edges []CallGraphEdge
	// Completeness and Algorithm carry the per-module fidelity level and the
	// algorithm/devirt tier the graph was built at, as opaque strings so this
	// port stays free of the callgraph domain. A reachability determination is
	// only as sound as this fidelity, so a diff records it on the resulting
	// verdict and checks completeness parity before trusting a green result.
	Completeness string
	Algorithm    string
	// ArtifactKind is what the analysed module is (application or library), as an
	// opaque string for the same reason. Reachability roots are conditioned on
	// it: an application's own code is all reachable, because functions the
	// runtime dispatches to dynamically are still shipped code.
	ArtifactKind string
}

// CallGraphNode is the subset of a call graph node the analyser needs.
type CallGraphNode struct {
	ID            string
	Module        string
	Package       string
	Symbol        string
	Receiver      string
	IsExternal    bool
	IsExportedAPI bool
}

// CallGraphEdge is a directed call edge between two node IDs.
type CallGraphEdge struct {
	FromID string
	ToID   string
}

// CallGraphSpawner runs a callgraph extraction subprocess for a module so that
// a vuln-scan can populate the callgraph store on demand for findings-only
// modules. On exit 0 the record is persisted in the store and available via
// the CallGraphLoader. The raw stderr and any exec error are returned so the
// caller can compose an actionable ReachabilityNote.
type CallGraphSpawner interface {
	Spawn(ctx context.Context, coord coordinate.ModuleCoordinate, force bool) (stderr []byte, err error)
}
