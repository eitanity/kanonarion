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
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
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
	Parse(filename string, data []byte) (walkdomain.ParsedGoMod, error)
}

// ModuleFetchResult is the result of a ModuleFetcher.EnsureFetched call.
type ModuleFetchResult struct {
	// Record is the artefact as the ledger knows it: the composed view of every
	// measurement of it, not any single row.
	Record    domain.CompositeRecord
	FromCache bool
}

// ModuleFetcher fetches a single module, returning the cached FactRecord if
// one already exists for the given coordinate and pipeline version.
// It abstracts the fetch bounded context's FetchModuleUseCase so that the
// walk application layer does not depend on fetch/application directly.
type ModuleFetcher interface {
	EnsureFetched(ctx context.Context, coord coordinate.ModuleCoordinate) (ModuleFetchResult, error)

	// EnsureFetchedReplacing fetches coord, which a replace directive put in
	// place of original. Both identities travel because the module has two, and
	// different questions want different ones: the fetch, the module zip and
	// the go.sum entry are all the REPLACEMENT's, while the require entry, the
	// vendored directory and everything a reader calls the dependency are the
	// ORIGINAL's.
	//
	// Passing only one of them is what lets a fork be reported as anchored
	// without a reader ever seeing under which name — or, worse, be reported
	// against a coordinate go.sum was never going to record.
	EnsureFetchedReplacing(ctx context.Context, coord, original coordinate.ModuleCoordinate) (ModuleFetchResult, error)
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
	AcquireStdlib(ctx context.Context, goVersion string, force, skipVCS bool) (walkdomain.StdlibFacts, domain.ArtifactDigests, error)
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
	// Record is the artefact as the ledger knows it: the composed view of every
	// measurement of it, not any single row.
	Record    domain.CompositeRecord
	FromCache bool
}

// LocalModuleFetcher creates a FactRecord from a local filesystem path instead
// of fetching from a module proxy. Used when a go.mod replace directive points
// to an on-disk source tree and local analysis is enabled.
type LocalModuleFetcher interface {
	EnsureFetchedFromPath(ctx context.Context, coord coordinate.ModuleCoordinate, absPath string) (LocalModuleFetchResult, error)
}

// PolicyLoadResult is the output of PolicyStore.LoadPolicy.
type PolicyLoadResult struct {
	Policy      walkdomain.DepthPolicy
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
//
// The zero coordinate is the one value the signatures cannot exclude: Go
// always permits coordinate.ModuleCoordinate{}, and it names no module.
// Implementations MUST refuse it with coordinate.ErrZeroCoordinate — on a
// write because it would key a row on the empty path at the empty version,
// which every later read treats as a genuine measurement, and on a read
// because absence is the wrong answer to a question about no module.
// coordinatetest.AssertRefusesZeroCoordinate pins the rule for every store.
type WalkStore interface {
	// PutWalk persists a walk record. The record's ContentHash is verified
	// before storage; a mismatch returns an error. Idempotent on ID.
	PutWalk(ctx context.Context, rec walkdomain.WalkRecord) error

	// GetWalk retrieves the walk record with the given ID. Returns
	// ErrWalkNotFound if not found, ErrWalkIntegrity if the stored hash
	// does not match.
	GetWalk(ctx context.Context, id string) (walkdomain.WalkRecord, error)

	// ListWalks returns summaries matching the filter, ordered by started_at
	// descending. Pagination is via Limit and Offset.
	ListWalks(ctx context.Context, filter WalkFilter) ([]WalkSummary, error)
}

// WalkFilter constrains ListWalks results.
type WalkFilter struct {
	Target        *coordinate.ModuleCoordinate // nil = any target
	Since         *time.Time                   // nil = no lower bound on started_at
	Until         *time.Time                   // nil = no upper bound on started_at
	OverallStatus *walkdomain.WalkStatus       // nil = any status
	Scope         *walkdomain.WalkScope        // nil = any scope
	Depth         *walkdomain.WalkDepth        // nil = any depth
	// IdentityHash restricts results to walks that performed the same analysis
	// (see walkdomain.WalkRecord.IdentityHash). nil = any identity. The empty
	// string is a legitimate filter value only in the sense that it selects the
	// rows written before identities were recorded; callers looking for a reusable
	// walk must never pass it, because an absent identity matches nothing.
	IdentityHash *string
	// BuildEnv restricts results to walks resolved for one target platform.
	// nil = any platform, and it is the ONLY way to say "any": within a non-nil
	// filter each field is matched exactly, so the empty string selects the
	// unrecorded frame rather than widening the match. A caller asking for
	// linux/amd64 therefore never receives a walk written before the platform was
	// projected into its own columns, and a caller asking for those rows has to
	// say so with an explicitly empty filter.
	BuildEnv   *BuildEnvFilter
	Limit      int // 0 = no limit
	Offset     int
	LatestOnly bool // true: return only the latest unique (target, scope) combination
}

// BuildEnvFilter names the target platform a walk was resolved for, as
// WalkFilter.BuildEnv matches it. Both fields are matched exactly; see
// WalkFilter.BuildEnv for what the empty string means.
//
// It is deliberately not walkdomain.BuildEnv: that type also carries GoVersion,
// which the store does not project into a column and therefore cannot filter on.
// A filter type that accepted a field it silently ignored would be worse than
// one that cannot express it.
type BuildEnvFilter struct {
	// GOOS is the target operating system (e.g. "linux"), as `go env GOOS`
	// reports it for the project the walk resolved.
	GOOS string
	// GOARCH is the target architecture (e.g. "amd64"), as `go env GOARCH`
	// reports it for the project the walk resolved.
	GOARCH string
}

// String renders the platform the way output and refusals name it. A filter is
// not a walk: an empty filter selects the rows that stored no platform, and it
// says so without claiming why any particular row is one of them.
func (f BuildEnvFilter) String() string {
	if f.GOOS == "" && f.GOARCH == "" {
		return "unrecorded"
	}
	return f.GOOS + "/" + f.GOARCH
}

// WalkSummary is a lightweight projection of a WalkRecord for list views.
type WalkSummary struct {
	ID        string                      `json:"id"`
	Target    coordinate.ModuleCoordinate `json:"target"`
	Scope     walkdomain.WalkScope        `json:"scope"`
	Depth     walkdomain.WalkDepth        `json:"depth"`
	StartedAt time.Time                   `json:"started_at"`
	// omitzero is deliberate and valid in stdlib encoding/json as of Go 1.24;
	// AI code-quality flagged it as invalid — that is a false positive.
	CompletedAt   time.Time             `json:"completed_at,omitzero"`
	OverallStatus walkdomain.WalkStatus `json:"overall_status"`
	NodeCount     int                   `json:"node_count"`
	FailureCount  int                   `json:"failure_count"`
	// IdentityHash names the analysis this walk performed. Empty for a walk
	// written before identities were recorded.
	IdentityHash string `json:"identity_hash,omitempty"`
	// GOOS and GOARCH are the target platform this walk resolved for. Both are
	// empty when the walk recorded no build environment at all; the pair is
	// written together, so one empty means both are.
	GOOS   string `json:"goos,omitempty"`
	GOARCH string `json:"goarch,omitempty"`
}

// Frame is the frame this walk answers in, derived over its own target so a
// module-rooted walk (no platform applies) is never confused with a project
// walk whose platform was not recorded.
func (s WalkSummary) Frame() walkdomain.WalkFrame {
	return walkdomain.FrameOf(s.Target, walkdomain.BuildEnv{GOOS: s.GOOS, GOARCH: s.GOARCH})
}

// BuildFrame renders the target platform a walk answers in, for output that
// names the walk it answered from. A walk that resolved no platform says so
// rather than rendering an empty pair or omitting the statement: a reader
// cannot tell a missing frame from an unstated one.
func (s WalkSummary) BuildFrame() string {
	return s.Frame().Text
}
