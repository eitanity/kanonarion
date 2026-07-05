package ports

import (
	"context"
	"errors"
	"time"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// ErrModuleNotFetched is returned when extraction is attempted for a module
// that has no FactRecord in the store.
var ErrModuleNotFetched = errors.New("module not fetched: run 'kanonarion fetch' first")

// ErrCallGraphNotFound is returned by CallGraphStore.GetCallGraphRecord when
// no record exists for the given coordinate and pipeline version.
var ErrCallGraphNotFound = errors.New("call graph record not found")

// ErrCallGraphIntegrity is returned when the stored record's content hash does
// not match the recomputed hash.
var ErrCallGraphIntegrity = errors.New("call graph record integrity check failed")

// AnalyserMetadata describes the algorithm and version of a CallGraphAnalyser
// implementation.
type AnalyserMetadata struct {
	Algorithm domain.CallGraphAlgorithm
	Version   string
}

// CallGraphAnalyser performs static call graph analysis on a module's source.
type CallGraphAnalyser interface {
	// Analyse extracts the call graph from a module zip.
	// The zip is in the Go module proxy format (entries prefixed by
	// "module@version/").
	//
	// zipPath is the local filesystem path to the module zip file.
	//
	// Failures that are a property of the module (load errors, partial parse)
	// are returned in the record's OverallStatus; only infrastructure errors
	// return a non-nil error.
	Analyse(ctx context.Context, zipPath string, coord fetchdomain.ModuleCoordinate) (domain.CallGraphRecord, error)

	// AnalyserMetadata returns the algorithm and version of this implementation.
	AnalyserMetadata() AnalyserMetadata
}

// LocalCallGraphAnalyser performs static call graph analysis on a Go module
// working tree on disk (no zip), used for local-analysis ingestion so
// kanonarion can resolve callers/callees of its own internal packages
type LocalCallGraphAnalyser interface {
	// AnalyseDir analyses the module rooted at dir. coord.Path must be the
	// module path from the directory's go.mod. Module-property failures are
	// reported via the record's OverallStatus; only infrastructure errors
	// return a non-nil error.
	AnalyseDir(ctx context.Context, dir string, coord fetchdomain.ModuleCoordinate) (domain.CallGraphRecord, error)

	// AnalyserMetadata returns the algorithm and version of this implementation.
	AnalyserMetadata() AnalyserMetadata
}

// CallGraphStore persists CallGraphRecords and supports caller/callee queries.
type CallGraphStore interface {
	// PutCallGraphRecord persists a call graph record. Idempotent on
	// (module_path, module_version, pipeline_version).
	PutCallGraphRecord(ctx context.Context, record domain.CallGraphRecord) error

	// GetCallGraphRecord retrieves the record for the given coordinate and
	// pipeline version. Returns (zero, false, nil) if not found.
	// Returns ErrCallGraphIntegrity if the stored hash does not verify.
	GetCallGraphRecord(ctx context.Context, coord fetchdomain.ModuleCoordinate, pipelineVersion string) (domain.CallGraphRecord, bool, error)

	// ListCallGraphRecords returns summaries matching the filter, ordered by
	// extracted_at descending.
	ListCallGraphRecords(ctx context.Context, filter CallGraphFilter) ([]CallGraphSummary, error)

	// FindCallers returns all edges in the store where the callee node ID
	// matches symbolID, for the given pipeline version.
	FindCallers(ctx context.Context, symbolID string, pipelineVersion string) ([]CallEdgeRef, error)

	// FindCallees returns all edges in the store where the caller node ID
	// matches symbolID, for the given pipeline version.
	FindCallees(ctx context.Context, symbolID string, pipelineVersion string) ([]CallEdgeRef, error)
}

// CallGraphFilter constrains ListCallGraphRecords results.
type CallGraphFilter struct {
	ModulePath      string // optional; empty means all modules
	PipelineVersion string // optional; empty means all versions
	Limit           int    // 0: no limit
	Offset          int
}

// CallGraphSummary is a lightweight projection of a CallGraphRecord for list
// views.
type CallGraphSummary struct {
	ModulePath      string
	ModuleVersion   string
	PipelineVersion string
	Algorithm       domain.CallGraphAlgorithm
	OverallStatus   domain.CallGraphStatus
	NodeCount       int
	EdgeCount       int
	ExtractedAt     time.Time
	ContentHash     string
}

// CallEdgeRef identifies a single call edge in the store, returned by
// FindCallers/FindCallees.
type CallEdgeRef struct {
	ModulePath      string
	ModuleVersion   string
	PipelineVersion string
	FromID          string
	ToID            string
	Confidence      domain.EdgeConfidence
}

// CallEdgeRefLess is the canonical ordering for CallEdgeRef slices produced by
// transitive caller/callee queries. It deliberately diverges from
// domain.CallGraphRecord.Sort: that comparator sorts edges within a single
// module record and tiebreaks on CallSite (File then Line), but a query result
// spans multiple modules and CallEdgeRef carries no CallSite, so ModulePath is
// the meaningful final tiebreak at query scope.
func CallEdgeRefLess(a, b CallEdgeRef) bool {
	if a.FromID != b.FromID {
		return a.FromID < b.FromID
	}
	if a.ToID != b.ToID {
		return a.ToID < b.ToID
	}
	return a.ModulePath < b.ModulePath
}
