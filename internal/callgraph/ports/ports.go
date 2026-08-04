package ports

import (
	"context"
	"errors"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// AuditSink appends an audit event to the assurance log. The shared JSONL
// AuditLog satisfies this; the application depends only on this narrow port,
// not on the factstore adapter that persists it.
type AuditSink interface {
	RecordEvent(audit.Event) error
}

// ErrModuleNotFetched is returned when extraction is attempted for a module
// that has no FactRecord in the store.
var ErrModuleNotFetched = errors.New("module not fetched: run 'kanonarion fetch' first")

// ErrCallGraphNotFound is returned by CallGraphStore.GetCallGraphRecord when
// no record exists for the given coordinate and pipeline version.
var ErrCallGraphNotFound = errors.New("call graph record not found")

// ErrCallGraphIntegrity is returned when the stored record's content hash does
// not match the recomputed hash.
var ErrCallGraphIntegrity = errors.New("call graph record integrity check failed")

// ErrCallGraphConflict wraps a domain.CallGraphConflict surfaced through the
// store. It marks the answers composition refuses to produce by picking: two
// analyses of one coordinate that name different artefacts, that came from
// different KINDS of source, or that agree on completeness and disagree on the
// graph. Callers route on it rather than on the concrete type so a partial
// answer can be returned alongside it.
var ErrCallGraphConflict = errors.New("conflicting call graph records")

// ErrUnidentifiedWorktree is returned when a record says it was built from a
// working tree but carries no digest of that tree.
//
// It is the worktree counterpart of the zero artefact identity. A fetched
// artefact is named by its hash; a working tree has none, so the digest is the
// only thing that tells one checkout of a module path from another. Without it
// two different trees are one row, and the ledger composes two bodies of code
// into a single answer.
var ErrUnidentifiedWorktree = errors.New("worktree call graph record identifies no tree")

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
	// inputs carries what the requesting build already resolved. A module
	// published before Go modules ships no go.mod, and the require directives that
	// make it loadable are a property of the build asking, not of the artefact;
	// the zero value offers none and synthesis refuses such a module exactly as it
	// did before the parameter existed.
	//
	// Failures that are a property of the module (load errors, partial parse)
	// are returned in the record's OverallStatus; only infrastructure errors
	// return a non-nil error.
	Analyse(ctx context.Context, zipPath string, coord coordinate.ModuleCoordinate, inputs domain.AnalysisInputs) (domain.CallGraphRecord, error)

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
	AnalyseDir(ctx context.Context, dir string, coord coordinate.ModuleCoordinate) (domain.CallGraphRecord, error)

	// AnalyserMetadata returns the algorithm and version of this implementation.
	AnalyserMetadata() AnalyserMetadata
}

// CallGraphStore persists CallGraphRecords and supports caller/callee queries.
//
// The zero coordinate is the one value the signatures cannot exclude: Go
// always permits coordinate.ModuleCoordinate{}, and it names no module.
// Implementations MUST refuse it with coordinate.ErrZeroCoordinate — on a
// write because it would key a row on the empty path at the empty version,
// which every later read treats as a genuine measurement, and on a read
// because absence is the wrong answer to a question about no module.
// coordinatetest.AssertRefusesZeroCoordinate pins the rule for every store.
type CallGraphStore interface {
	// PutCallGraphRecord APPENDS a call graph record. It never updates: the
	// ledger key carries the time of measurement and the record's own content
	// hash, so two distinct analyses are two rows. Writing the same record twice
	// is a no-op rather than an error, because a retried write must not fail a run
	// that already succeeded.
	//
	// A record analysed from a fetched artefact must name that artefact; a
	// worktree record must carry its tree digest instead. Both refusals are on the
	// write leg only — see the sqlite implementation for why the read leg must not
	// inherit them.
	PutCallGraphRecord(ctx context.Context, record domain.CallGraphRecord) error

	// GetCallGraphRecord returns the COMPOSED record for the given coordinate and
	// pipeline version: the highest completeness, then the most recent, within the
	// analysis source composition defaults to. Returns (zero, false, nil) if the
	// ledger holds none.
	//
	// Returns ErrCallGraphIntegrity if a stored hash does not verify, and
	// ErrCallGraphConflict for a disagreement composition must not resolve by
	// picking.
	GetCallGraphRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain.CallGraphRecord, bool, error)

	// ListCallGraphRecords returns summaries matching the filter, ordered by
	// extracted_at descending.
	ListCallGraphRecords(ctx context.Context, filter CallGraphFilter) ([]CallGraphSummary, error)

	// FindCallers returns all edges in the store where the callee node ID
	// matches symbolID, for the given pipeline version.
	//
	// scope restricts the result to edges owned by a module in that build's
	// resolved version set; the zero ModuleSet imposes no restriction and
	// returns matches across every stored version, which is what a query that
	// names no build means.
	//
	// opts is the caller's choice about the test surface; the zero value
	// includes it, because omitting a caller is the more damaging error.
	FindCallers(ctx context.Context, symbolID string, pipelineVersion string, scope coordinate.ModuleSet, opts EdgeQueryOptions) ([]CallEdgeRef, error)

	// FindCallees returns all edges in the store where the caller node ID
	// matches symbolID, for the given pipeline version. scope and opts behave as
	// in FindCallers.
	FindCallees(ctx context.Context, symbolID string, pipelineVersion string, scope coordinate.ModuleSet, opts EdgeQueryOptions) ([]CallEdgeRef, error)
}

// EdgeQueryOptions narrows a caller/callee query. The zero value is the
// unrestricted query.
type EdgeQueryOptions struct {
	// ExcludeTests drops every edge with a test-scope endpoint. It is opt-in:
	// the default answer covers the whole graph, because a hidden test caller is
	// a false negative — the failure the three-valued verdict exists to prevent
	// — while an unwanted one is merely noise the reader can see and discount.
	ExcludeTests bool
}

// CallGraphRecordLister is the optional history read a store may offer: every
// generation the ledger holds for one coordinate, in the order they were
// appended.
//
// It is separate from CallGraphStore because it is what makes the ledger
// OBSERVABLE rather than what makes it work — no analysis path needs it, and a
// store that cannot answer it is still a usable call graph store. Callers type-
// assert for it.
type CallGraphRecordLister interface {
	// ListCallGraphRecordsFor returns every generation for the coordinate and
	// pipeline version, oldest first, each with its edges reconstructed and its
	// content hash verified.
	ListCallGraphRecordsFor(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]domain.CallGraphRecord, error)
}

// CallGraphSourceReader is the optional source-scoped read: the same question
// GetCallGraphRecord answers, restricted to one kind of analysis source.
//
// It exists because the source is a dimension rather than a ladder position, so
// "zip or working tree" is a real question that a coordinate cannot answer.
// GetCallGraphRecord applies a stated default; this is how a caller asks for the
// other one.
type CallGraphSourceReader interface {
	GetCallGraphRecordFrom(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string, source domain.AnalysisSource) (domain.CallGraphRecord, bool, error)
}

// CallGraphFilter constrains ListCallGraphRecords results.
type CallGraphFilter struct {
	ModulePath      string // optional; empty means all modules
	PipelineVersion string // optional; empty means all versions
	// AnalysisSource restricts the listing to records built from one kind of
	// source. The zero value imposes no restriction, which is what a listing that
	// names no source means.
	AnalysisSource domain.AnalysisSource
	Limit          int // 0: no limit
	Offset         int
}

// CallGraphSummary is a lightweight projection of a CallGraphRecord for list
// views. One summary describes the generation composition serves for a module,
// not one row of the ledger.
type CallGraphSummary struct {
	ModulePath      string
	ModuleVersion   string
	PipelineVersion string
	Algorithm       domain.CallGraphAlgorithm
	OverallStatus   domain.CallGraphStatus
	// Completeness is the fidelity the served generation was analysed at, and
	// AnalysisSource what it read. Both are on the summary because both decide
	// which question the row answers, and a list that omits them shows two
	// generations of one module as interchangeable.
	Completeness   domain.CompletenessLevel
	AnalysisSource domain.AnalysisSource
	NodeCount      int
	EdgeCount      int
	ExtractedAt    time.Time
	ContentHash    string
	// Conflict is non-nil when the ledger holds records for this module that
	// composition refuses to resolve by picking. It is reported on the row rather
	// than as the listing's error: a listing spans every module in the store, so
	// one disputed module must not delete every correct row. The other fields are
	// zero when it is set — there is no served generation to describe.
	Conflict error
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
	// IsTest is true when either endpoint is a test-scope node, so a reader can
	// see which part of an answer is the test surface without a second query.
	IsTest bool
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
