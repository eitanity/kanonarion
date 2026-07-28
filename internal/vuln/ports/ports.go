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

// ErrVulnIntegrity is returned by the vulnerability store's read paths when a
// stored record's content hash does not describe its contents, and by the write
// path when asked to persist a record whose hash does not describe what it is
// about to store.
//
// A read reports it instead of absence deliberately: a detected tamper reported
// as "nothing here" becomes a silent re-scan that overwrites the evidence of the
// tamper. It lives here rather than in the adapter so a caller can match the
// failure without importing the store.
var ErrVulnIntegrity = errors.New("vulnerability record integrity check failed")

// ErrSnapshotIntegrity is returned by the vulnerability store when the advisory
// database snapshot itself fails its integrity check: on write when the
// caller-declared hash contradicts the bytes handed over, and on read when the
// stored blob no longer matches its stored hash or is not the snapshot the caller
// asked for.
//
// It is separate from ErrVulnIntegrity because the two failures have
// incomparable blast radius. A corrupt record invalidates one module's verdict; a
// corrupt snapshot invalidates every verdict derived from it, and the records in
// a working store reference a handful of snapshots between them. A caller that
// would fail the module on one and abort the run and re-fetch the database on the
// other could not tell them apart while both answered to one sentinel.
//
// It deliberately does not wrap ErrVulnIntegrity. Wrapping would make
// errors.Is(err, ErrVulnIntegrity) true for a snapshot failure — the exact
// conflation this removes — and would keep every existing broad match working
// while making the narrow one impossible to write.
//
// A snapshot that is absent is not an integrity failure and matches neither
// sentinel; nor is a snapshot stored before hashing existed, which reads back as
// unverifiable rather than as corrupt.
var ErrSnapshotIntegrity = errors.New("vulnerability database snapshot integrity check failed")

// VulnerabilityStore defines the port for persisting vulnerability records.
//
// The zero coordinate is the one value the signatures cannot exclude: Go
// always permits coordinate.ModuleCoordinate{}, and it names no module.
// Implementations MUST refuse it with coordinate.ErrZeroCoordinate — on a
// write because it would key a row on the empty path at the empty version,
// which every later read treats as a genuine measurement, and on a read
// because absence is the wrong answer to a question about no module.
// coordinatetest.AssertRefusesZeroCoordinate pins the rule for every store.
type VulnerabilityStore interface {
	// PutVulnerabilityRecord appends a scan to the ledger. It never updates a
	// record: two distinct scans of one coordinate — under two snapshots, in two
	// analysis frames, or simply repeated — are always two records, and only a
	// byte-identical re-write is idempotent.
	PutVulnerabilityRecord(ctx context.Context, record domain.VulnerabilityRecord) error

	// GetVulnerabilityRecord returns the composed record for a coordinate,
	// pipeline version and snapshot, across every analysis frame the ledger holds.
	// It is the read for a caller that has declined to name a frame; see
	// domain.Compose for the ladder it serves on.
	GetVulnerabilityRecord(
		ctx context.Context,
		coord coordinate.ModuleCoordinate,
		pipelineVersion string,
		snapshot domain.DatabaseSnapshot,
	) (domain.VulnerabilityRecord, bool, error)

	// GetVulnerabilityRecordAt returns the composed record within one analysis
	// frame, and (zero, false, nil) when the ledger holds none reached in it.
	//
	// A caller that has a frame — a scan deciding whether an earlier record may
	// be reused, a run reading back what it wrote — MUST use this rather than
	// GetVulnerabilityRecord. An isolated scan and a target-rooted scan answer
	// different questions, so serving one for the other attributes a reachability
	// finding to a build it was never computed against.
	GetVulnerabilityRecordAt(
		ctx context.Context,
		coord coordinate.ModuleCoordinate,
		pipelineVersion string,
		snapshot domain.DatabaseSnapshot,
		rooting domain.Rooting,
	) (domain.VulnerabilityRecord, bool, error)

	// HasVulnerabilityRecord reports whether the ledger holds the exact
	// generation named by contentHash. It answers "was this measurement kept",
	// which composition cannot: the record a read serves is not necessarily the
	// one a given run wrote, because an earlier generation may outrank it.
	HasVulnerabilityRecord(
		ctx context.Context,
		coord coordinate.ModuleCoordinate,
		pipelineVersion string,
		snapshot domain.DatabaseSnapshot,
		contentHash string,
	) (bool, error)

	// GetLatestVulnerabilityRecord returns the composed record for a coordinate
	// and pipeline version across every snapshot and frame the ledger holds.
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

	// ListVulnerabilityRecordsByFindingID returns the vulnerability records that
	// contain a finding with the given OSV/CVE/GHSA identifier.
	//
	// An empty walkID answers across the whole store — every module version,
	// pipeline version and snapshot generation it holds, including versions no
	// current build contains. A non-empty walkID restricts the answer to the
	// modules a scan run of that walk covered, and an unknown walkID is an
	// error rather than an empty result.
	ListVulnerabilityRecordsByFindingID(ctx context.Context, findingID, walkID string) ([]domain.VulnerabilityRecord, error)

	// ListVulnerabilityRecords returns all vulnerability records for a walk scan run.
	ListVulnerabilityRecords(ctx context.Context, walkScanRunID string) ([]domain.VulnerabilityRecord, error)

	// ListVulnerabilityRecordsForModule returns every generation the ledger holds
	// for a coordinate and pipeline version, across all walks, snapshots and
	// analysis frames, ordered by scanned_at descending (most recent first). It
	// is the history read: the superseded records are still here, each stating
	// the evidence it rested on.
	ListVulnerabilityRecordsForModule(
		ctx context.Context,
		coord coordinate.ModuleCoordinate,
		pipelineVersion string,
	) ([]domain.VulnerabilityRecord, error)
}

// ScanRequest carries the inputs for one isolated per-module scan.
type ScanRequest struct {
	Coordinate   coordinate.ModuleCoordinate
	ModuleSource io.Reader
	Snapshot     domain.DatabaseSnapshot
	// GoModCache is a pre-populated GOMODCACHE dir; empty lets govulncheck
	// download as needed.
	GoModCache string
	// DBDir is a pre-extracted vuln DB dir; empty extracts from the store on
	// each call.
	DBDir string
	// ScanMode selects source or binary analysis; empty defaults to source.
	ScanMode domain.ScanMode
	// BuildList is the set of module versions the walk resolved and supplies as
	// source. A module zip published before Go modules carries no go.mod, so one
	// is synthesised in the scan's scratch directory and these become its
	// require directives — letting the isolated scan resolve the versions the
	// project actually built instead of whatever a network tidy would pick.
	// Empty means the module is scanned against its own zip alone, which is
	// sufficient whenever it imports nothing outside the standard library.
	BuildList map[coordinate.ModuleCoordinate]struct{}
}

// TargetScanRequest carries the inputs for one target-rooted scan of a walk
// whose root is a published module rather than a local project. The target's
// own zip is the main module of the analysis, and every dependency is reached
// through the target's import graph rather than scanned in isolation.
type TargetScanRequest struct {
	// Coordinate is the walk target: the module the analysis is rooted at.
	Coordinate   coordinate.ModuleCoordinate
	ModuleSource io.Reader
	Snapshot     domain.DatabaseSnapshot
	// GoModCache is the walk's pre-populated GOMODCACHE, holding the versions the
	// target's build selects, so the scan resolves them offline rather than
	// re-resolving against the network.
	GoModCache string
	// DBDir is a pre-extracted vuln DB dir; empty extracts from the store.
	DBDir string
	// BuildList is the set of module versions the walk resolved, used only to
	// synthesise a go.mod when the target's own zip predates Go modules.
	BuildList map[coordinate.ModuleCoordinate]struct{}
}

// VulnerabilityScanner defines the port for a vulnerability scanner implementation.
type VulnerabilityScanner interface {
	// Preflight verifies the scanner's external prerequisites are available
	// (e.g. the govulncheck binary on PATH) so callers can fail fast with an
	// actionable error before any expensive scan setup. It returns nil when
	// the scanner is ready to run.
	Preflight(ctx context.Context) error
	Scan(ctx context.Context, req ScanRequest) (domain.VulnerabilityRecord, error)
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
	// ScanTargetModule runs one target-rooted scan for a walk whose root is a
	// published module, returning every finding grouped by the module that owns
	// the vulnerable symbol. It is the coordinate-keyed counterpart of
	// ScanProject: the target's zip stands in for the project working tree, so
	// each dependency contributes the packages the target's build imports instead
	// of every package it contains. A genuine fault is carried in the result's
	// Status so the caller can fall back to isolated per-module scanning; the
	// error return is reserved for infrastructure failures.
	ScanTargetModule(ctx context.Context, req TargetScanRequest) (domain.ProjectScanResult, error)
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
	// FetchModule acquires the full module artefact (zip + go.mod), the source a
	// scan analyses.
	FetchModule(ctx context.Context, coord coordinate.ModuleCoordinate) error
	// FetchModuleGoMod acquires only the module's go.mod, persisting a go.mod-only
	// record (see fetch domain FactRecord.IsGoModOnly). It is used to populate the
	// go.mod closure a pre-pruning module reads while rebuilding its module graph:
	// those versions are never compiled, so downloading their zips is discarded
	// work.
	FetchModuleGoMod(ctx context.Context, coord coordinate.ModuleCoordinate) error
}

// HostMemory reports how much memory the host can hand to new work right now.
// It exists so the module-scan worker pool can size itself against a real
// budget instead of against the CPU count alone: each govulncheck source-mode
// scan of a cloud-SDK-heavy module holds multiple GB, so a pool sized purely by
// cores can exhaust the host and be OOM-killed, which reports every module as
// unanalysed rather than as scanned.
//
// It is a port rather than a direct /proc read so the cap is injectable in
// tests, and so a host that cannot answer degrades to the CPU-only cap instead
// of failing the scan.
type HostMemory interface {
	// AvailableBytes returns the memory available for new allocations without
	// swapping. An error means the reading could not be taken — never that the
	// host has no memory — and callers MUST treat it as "unknown" and fall back
	// to their CPU-derived cap rather than refusing to run.
	AvailableBytes() (uint64, error)
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
