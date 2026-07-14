// Package ports defines the interfaces the walk application layer requires
// from the outside world. GoModParser abstracts go.mod parsing; ModuleFetcher
// abstracts single-module fetch (implemented by the fetch bounded context).
//
// The walk context also reuses BlobStore and Clock from the fetch ports package.
// Those are not re-declared here; the application layer imports them directly.
package ports

import (
	"context"
	"errors"
	"time"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	domain2 "github.com/eitanity/kanonarion/internal/walk/domain"
)

// AuditSink appends an audit event to the assurance log. The shared JSONL
// AuditLog satisfies this; the application depends only on this narrow port,
// not on the factstore adapter that persists it.
type AuditSink interface {
	RecordEvent(audit.Event) error
}

// ErrWalkNotFound is returned by WalkStore.GetWalk when the requested ID does
// not exist in the store.
var ErrWalkNotFound = errors.New("walk record not found")

// ErrWalkIntegrity is returned by WalkStore.GetWalk when the stored record's
// content hash does not match the recomputed hash, indicating tampering or
// corruption.
var ErrWalkIntegrity = errors.New("walk record integrity check failed")

// GoModParser parses go.mod file bytes into a structured representation.
// The filename parameter is used only for error message context.
// Adapter: adapters/gomod/xmod using golang.org/x/mod/modfile.
type GoModParser interface {
	Parse(filename string, data []byte) (domain2.ParsedGoMod, error)
}

// ModuleFetchResult is the result of a ModuleFetcher.EnsureFetched call.
type ModuleFetchResult struct {
	Record    domain.FactRecord
	FromCache bool
}

// ModuleFetcher fetches a single module, returning the cached FactRecord if
// one already exists for the given coordinate and pipeline version.
// It abstracts the fetch bounded context's FetchModuleUseCase so that the
// walk application layer does not depend on fetch/application directly.
type ModuleFetcher interface {
	EnsureFetched(ctx context.Context, coord domain.ModuleCoordinate) (ModuleFetchResult, error)
}

// StdlibAcquirer establishes the standard library's chain of custody: it
// acquires and verifies the canonical Go source tarball for a toolchain version
// and returns the facts (digests, verification status, licence, VCS anchor) the
// resolver attaches to the synthetic stdlib node. It abstracts the stdlib
// bounded context so the walk application layer does not depend on it directly;
// a nil acquirer (offline / --from-modcache) simply leaves the node bare.
type StdlibAcquirer interface {
	// AcquireStdlib returns the chain-of-custody facts for the standard library
	// at goVersion (any toolchain form). force re-acquires past the cache;
	// skipVCS skips the googlesource commit anchor. The digests are returned
	// separately so the resolver can set them on the node alongside every other
	// node's digests, uniform with the module SBOM hash path.
	AcquireStdlib(ctx context.Context, goVersion string, force, skipVCS bool) (domain2.StdlibFacts, domain.ArtifactDigests, error)
}

// ProgressReporter receives walk fetch-phase progress so a long, otherwise
// silent run can show proof of life. The walker calls Advance once per distinct
// module as it is fetched (cache hits included), passing the running total. The
// walk does not know the final module count during sequential resolution, so no
// denominator is reported. Implementations decide whether and how to surface the
// signal (e.g. a throttled stderr line); a nil reporter disables reporting.
//
// Advance may be called concurrently; implementations must be safe for that.
type ProgressReporter interface {
	// Advance reports that the number of distinct modules fetched so far is done.
	Advance(done int)
}

// BuildListModule is one module in a project's authoritative build list, as
// reported by `go list -m -json all`. Path and Version are the original require
// coordinate (the module's own identity), even when Replace redirects the
// content that actually compiles.
type BuildListModule struct {
	// Path is the module path as it appears in the build list.
	Path string
	// Version is the selected version. Empty for the main module.
	Version string
	// Main is true for the project's own main module.
	Main bool
	// Indirect is true when the module is an indirect (transitive) requirement.
	Indirect bool
	// Replace is non-nil when a replace directive redirects this module. A
	// filesystem replacement has an empty Version and a Path that is a directory
	// (the LocalReplace case); a module replacement has both Path and Version.
	Replace *BuildListReplace
}

// BuildListReplace is the right-hand side of a replace directive as reported by
// `go list -m -json all`.
type BuildListReplace struct {
	// Path is the replacement module path, or a filesystem directory for a
	// local-path replacement.
	Path string
	// Version is the replacement version. Empty for a filesystem replacement.
	Version string
}

// BuildListEdge is a directed requirement edge from `go mod graph`. From and To
// are "path@version" tokens (the main module appears without "@version"); the
// "go" and "toolchain" pseudo-nodes are excluded by the resolver, not here.
type BuildListEdge struct {
	From string
	To   string
}

// BuildList is the authoritative build-input set for a project, derived from the
// Go toolchain: the selected module set (`go list -m all`) plus the requirement
// edges (`go mod graph`). It is a pure, deterministic function of the
// go.mod/go.sum the project already verifies — the toolchain decides the SET,
// never content trust; every listed module is still fetched and verified through
// kanonarion's pipeline.
type BuildList struct {
	Modules []BuildListModule
	Edges   []BuildListEdge
	// GoVersion is the effective Go toolchain version that computed this build
	// list, as reported by `go env GOVERSION` (e.g. "go1.26.4") — the version that
	// actually compiles the project, not the go.mod `go` directive minimum. It
	// pins the synthetic standard-library node so vuln-scan matches stdlib
	// advisories against the toolchain the build really uses. Empty when the
	// toolchain did not report a version.
	GoVersion string
	// GOOS and GOARCH are the target platform the build list was resolved for
	// (`go env GOOS`/`GOARCH`). Build constraints select files per platform, so
	// the resolved module set is platform-specific; these are recorded so a
	// downstream SBOM states the platform its components are valid for. Empty when
	// the toolchain did not report them.
	GOOS   string
	GOARCH string
}

// BuildListResolver computes the authoritative build list for a project from the
// Go toolchain, run in the project's working directory. It is used only for the
// project walk (`--project`), where go.mod/go.sum are present locally; the custom
// MVS resolver remains the fallback when the toolchain is unavailable and the
// only path for published single-module walks.
// Adapter: adapters/buildlist/gotoolchain.
type BuildListResolver interface {
	Resolve(ctx context.Context, projectDir string) (BuildList, error)
}

// LocalModuleFetchResult is the result of a LocalModuleFetcher.EnsureFetchedFromPath call.
type LocalModuleFetchResult struct {
	Record    domain.FactRecord
	FromCache bool
}

// LocalModuleFetcher creates a FactRecord from a local filesystem path instead
// of fetching from a module proxy. Used when a go.mod replace directive points
// to an on-disk source tree and local analysis is enabled.
type LocalModuleFetcher interface {
	EnsureFetchedFromPath(ctx context.Context, coord domain.ModuleCoordinate, absPath string) (LocalModuleFetchResult, error)
}

// PolicyLoadResult is the output of PolicyStore.LoadPolicy.
type PolicyLoadResult struct {
	Policy      domain2.DepthPolicy
	ContentHash string // "sha256:<hex>" of the raw source bytes
	Source      string // human-readable identifier: file path or "defaults"
}

// PolicyStore loads a DepthPolicy from a versioned source.
// The built-in default implementation is adapters/policy/localfile.
// Future implementations may load from OCI registries or remote endpoints.
type PolicyStore interface {
	LoadPolicy(ctx context.Context) (PolicyLoadResult, error)
}

// WalkStore persists WalkRecords durably and structurally.
// Adapters: adapters/walks/sqlite.
type WalkStore interface {
	// PutWalk persists a walk record. The record's ContentHash is verified
	// before storage; a mismatch returns an error. Idempotent on ID.
	PutWalk(ctx context.Context, rec domain2.WalkRecord) error

	// GetWalk retrieves the walk record with the given ID. Returns
	// ErrWalkNotFound if not found, ErrWalkIntegrity if the stored hash
	// does not match.
	GetWalk(ctx context.Context, id string) (domain2.WalkRecord, error)

	// ListWalks returns summaries matching the filter, ordered by started_at
	// descending. Pagination is via Limit and Offset.
	ListWalks(ctx context.Context, filter WalkFilter) ([]WalkSummary, error)
}

// WalkFilter constrains ListWalks results.
type WalkFilter struct {
	Target        *domain.ModuleCoordinate // nil = any target
	Since         *time.Time               // nil = no lower bound on started_at
	Until         *time.Time               // nil = no upper bound on started_at
	OverallStatus *domain2.WalkStatus      // nil = any status
	Scope         *domain2.WalkScope       // nil = any scope
	Depth         *domain2.WalkDepth       // nil = any depth
	Limit         int                      // 0 = no limit
	Offset        int
	LatestOnly    bool // true: return only the latest unique (target, scope) combination
}

// WalkSummary is a lightweight projection of a WalkRecord for list views.
type WalkSummary struct {
	ID            string                  `json:"id"`
	Target        domain.ModuleCoordinate `json:"target"`
	Scope         domain2.WalkScope       `json:"scope"`
	Depth         domain2.WalkDepth       `json:"depth"`
	StartedAt     time.Time               `json:"started_at"`
	CompletedAt   time.Time               `json:"completed_at,omitzero"`
	OverallStatus domain2.WalkStatus      `json:"overall_status"`
	NodeCount     int                     `json:"node_count"`
	FailureCount  int                     `json:"failure_count"`
}
