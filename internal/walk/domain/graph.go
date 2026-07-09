package domain

import (
	"sort"
	"strings"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// ResolutionSource describes how a node's version was selected during MVS resolution.
type ResolutionSource string

const (
	// ResolutionTarget marks the root of the graph — the module being resolved.
	ResolutionTarget ResolutionSource = "target"
	// ResolutionLocalMainModule marks the root of a project walk: the local
	// main module at synthetic version "local". Unlike ResolutionTarget it is
	// never fetched — its go.mod is read from the working tree — so it carries
	// no fetch record. It anchors the require closure and serves as the SBOM
	// subject (metadata.component).
	ResolutionLocalMainModule ResolutionSource = "local_main_module"
	// ResolutionMVS marks a node whose version was selected by minimum version selection.
	ResolutionMVS ResolutionSource = "mvs"
	// ResolutionReplace marks a node whose coordinate was changed by a replace
	// directive pointing at a different module path/version. The node's
	// Coordinate is the replacement (what compiles); OriginalCoordinate carries
	// the require entry that the replace acted on.
	ResolutionReplace ResolutionSource = "replace"
	// ResolutionLocalReplace marks a require redirected to a local filesystem
	// path. The node's Coordinate is the original require (no fetchable
	// replacement coordinate exists); LocalPath records the on-disk target so
	// downstream stages can identify and skip-with-reason instead of failing
	// silently.
	ResolutionLocalReplace ResolutionSource = "local_replace"
	// ResolutionFetchFailed marks a node that could not be fetched. Its transitive
	// dependencies are unknown and the graph is partial.
	ResolutionFetchFailed ResolutionSource = "fetch_failed"
	// ResolutionParseFailed marks a node whose go.mod could not be parsed. Its
	// transitive dependencies are unknown and the graph is partial.
	ResolutionParseFailed ResolutionSource = "parse_failed"
	// ResolutionLocalAnalysed marks a node that was originally a local-path replace
	// directive and has been successfully ingested from the on-disk source tree by
	// the local-FS fetcher. Downstream stages (extract, vuln-scan) treat these
	// nodes the same as ResolutionMVS nodes.
	ResolutionLocalAnalysed ResolutionSource = "local_analysed"
	// ResolutionStdlib marks the synthetic Go standard-library node injected into a
	// project walk. The standard library is a genuine build dependency — the code
	// links against it — but it ships with the toolchain rather than as a fetchable
	// module, so `go list -m all` never lists it. The node's Coordinate is
	// {StdlibModulePath, v<toolchain-version>}; it is never fetched or extracted
	// (like ResolutionLocalMainModule) and vuln-scan resolves its advisories from
	// OSV metadata by coordinate. Without it, stdlib advisories for the build
	// toolchain are invisible to both vuln-scan and the SBOM.
	ResolutionStdlib ResolutionSource = "stdlib"
)

// StdlibModulePath is the module path used for the synthetic standard-library
// node. It matches govulncheck's / the Go vulnerability database's pseudo-module
// path for standard-library advisories, so an OSV coordinate lookup for this path
// resolves the stdlib advisory set directly.
const StdlibModulePath = "stdlib"

// NormaliseStdlibVersion converts a Go toolchain version string into the
// v-prefixed semver form the module coordinate and the OSV version comparison
// both require. It accepts the forms the toolchain and go.mod directives produce:
// "go1.26.4" (go env GOVERSION / a `toolchain` directive) and "1.26.4" (a `go`
// directive). A leading "go" is stripped and a leading "v" ensured, yielding
// "v1.26.4". An input that is already v-prefixed is returned unchanged, and an
// empty input yields "" so callers can detect an undeterminable toolchain.
func NormaliseStdlibVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	v = strings.TrimPrefix(v, "go")
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

// StdlibNode builds the synthetic standard-library graph node for a build
// toolchain at goVersion (any form NormaliseStdlibVersion accepts). The returned
// node is a direct dependency of the project root with ResolutionStdlib. The bool
// is false when goVersion does not yield a usable version, so the caller can skip
// injection rather than emit a node with an empty coordinate.
func StdlibNode(goVersion string) (GraphNode, bool) {
	version := NormaliseStdlibVersion(goVersion)
	if version == "" {
		return GraphNode{}, false
	}
	return GraphNode{
		Coordinate:       fetchdomain.ModuleCoordinate{Path: StdlibModulePath, Version: version},
		DirectDependency: true,
		ResolutionSource: ResolutionStdlib,
	}, true
}

// Graph is the resolved transitive dependency closure for a target module.
// It is produced by GraphResolver and immutable once Sort has been called.
//
// Identified by (Target, PipelineVersion, ResolvedAt).
type Graph struct {
	// Target is the module whose dependency closure this graph represents.
	Target fetchdomain.ModuleCoordinate
	// Nodes contains every module in the closure, including the target itself.
	// Sorted lexicographically by (Path, Version) after Sort.
	Nodes []GraphNode
	// Edges records directed dependency relationships.
	// Sorted lexicographically by (From.Path, From.Version, To.Path, To.Version) after Sort.
	Edges []GraphEdge
	// ResolvedAt is the wall-clock time at which resolution completed, from injected Clock.
	ResolvedAt time.Time
	// PipelineVersion is the pipeline constant at the time of resolution.
	PipelineVersion string
	// Partial is true when one or more nodes could not be fully resolved.
	// GraphResolver never returns an error for per-node failures; instead it
	// sets Partial and records the reason in the relevant node's ErrorDetail.
	Partial bool
	// PartialReason is a machine-readable summary of why the graph is partial:
	// "fetch_failed", "parse_failed", "cancelled", or a combination.
	PartialReason string
	// HasLocalReplace is true when the target's go.mod contains at least one
	// replace directive pointing to a local filesystem path. Such replacements
	// are recorded but not followed, since local paths have no standalone fetch
	// semantics.
	HasLocalReplace bool
	// BuildEnv records the Go toolchain environment that resolved this graph:
	// GOOS/GOARCH/GOVERSION. The target platform is not incidental — build
	// constraints select which files (and therefore which imports and modules)
	// compile, so the same go.mod can resolve a different graph per platform. It
	// is captured so a downstream SBOM states the platform its component set is
	// valid for. Zero value for records created before the field existed.
	BuildEnv BuildEnv
}

// BuildEnv is the Go build environment a project walk was resolved under. It is
// a property of the whole graph, not any single node, because GOOS/GOARCH gate
// build-constraint file selection across every module in the closure.
type BuildEnv struct {
	// GOOS is the target operating system (e.g. "linux"), from `go env GOOS`.
	GOOS string
	// GOARCH is the target architecture (e.g. "amd64"), from `go env GOARCH`.
	GOARCH string
	// GoVersion is the effective toolchain version (e.g. "go1.26.4"), from
	// `go env GOVERSION` — the version that actually compiles the project.
	GoVersion string
}

// IsZero reports whether no build environment was captured, so serialisers can
// omit an empty BuildEnv and keep hashes stable for pre-BuildEnv records.
func (e BuildEnv) IsZero() bool {
	return e.GOOS == "" && e.GOARCH == "" && e.GoVersion == ""
}

// GraphNode is a single module in the dependency graph.
type GraphNode struct {
	// Coordinate is the module path and MVS-selected version.
	Coordinate fetchdomain.ModuleCoordinate
	// DirectDependency is true when this module appears directly in the target's
	// go.mod (as opposed to being a transitive dependency).
	DirectDependency bool
	// ResolutionSource describes how this node's version was selected.
	ResolutionSource ResolutionSource
	// ErrorDetail carries a human-readable description of the failure when
	// ResolutionSource is fetch_failed or parse_failed.
	ErrorDetail string
	// Retracted is true when the module version carries a retract directive
	// covering this version in its own go.mod.
	Retracted bool
	// OriginalCoordinate is the require entry that produced this node before
	// a replace directive rewrote it. Zero value when ResolutionSource is not
	// ResolutionReplace or ResolutionLocalReplace.
	OriginalCoordinate fetchdomain.ModuleCoordinate
	// LocalPath is the filesystem target of a local-path replace directive.
	// Non-empty only when ResolutionSource is ResolutionLocalReplace.
	LocalPath string
}

// GraphEdge is a directed dependency relationship between two modules.
type GraphEdge struct {
	// From is the module that declares the dependency.
	From fetchdomain.ModuleCoordinate
	// To is the dependency at its MVS-selected version.
	To fetchdomain.ModuleCoordinate
	// ConstraintVersion is the version string appearing in From's go.mod before
	// MVS resolution. It may differ from To.Version when MVS selects a higher version.
	ConstraintVersion string
}

// Sort sorts Nodes and Edges in place, establishing the deterministic ordering
// required for canonical serialisation. Must be called after graph construction.
func (g *Graph) Sort() {
	sort.Slice(g.Nodes, func(i, j int) bool {
		a, b := g.Nodes[i].Coordinate, g.Nodes[j].Coordinate
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Version < b.Version
	})
	sort.Slice(g.Edges, func(i, j int) bool {
		a, b := g.Edges[i], g.Edges[j]
		if a.From.Path != b.From.Path {
			return a.From.Path < b.From.Path
		}
		if a.From.Version != b.From.Version {
			return a.From.Version < b.From.Version
		}
		if a.To.Path != b.To.Path {
			return a.To.Path < b.To.Path
		}
		return a.To.Version < b.To.Version
	})
}

// SupersededRequirements returns the intermediate module versions named by a
// requirement edge that MVS did not select — the versions a lower requirement
// asked for before a higher one won. Each is (edge.To.Path, edge.ConstraintVersion)
// where the constraint differs from the selected version the edge resolved to.
//
// These versions never appear as graph nodes (a node carries the selected
// version), but the Go toolchain still reads their go.mod when it rebuilds the
// module graph offline for a graph containing a pre-pruning (go<1.17) module.
// The selected-version cache omits them, so an offline resolution needs them
// supplied separately. The result is deduplicated and deterministically sorted;
// the empty constraint (a main-module edge) is skipped.
func (g Graph) SupersededRequirements() []fetchdomain.ModuleCoordinate {
	seen := make(map[fetchdomain.ModuleCoordinate]struct{})
	for _, e := range g.Edges {
		if e.ConstraintVersion == "" || e.ConstraintVersion == e.To.Version {
			continue
		}
		coord := fetchdomain.ModuleCoordinate{Path: e.To.Path, Version: e.ConstraintVersion}
		seen[coord] = struct{}{}
	}
	out := make([]fetchdomain.ModuleCoordinate, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// ReachableFrom returns the set of module coordinates transitively reachable
// from origin by following directed edges — origin's full dependency closure.
// The origin itself is never included in the result. The traversal is purely
// structural over the stored graph, so it needs no live fetch or probe.
//
// A coordinate absent from the graph's edges yields an empty set; callers
// distinguish "no dependencies" from "module not in this graph" via the node
// list, not this result.
func (g Graph) ReachableFrom(origin fetchdomain.ModuleCoordinate) map[fetchdomain.ModuleCoordinate]struct{} {
	// Adjacency: From → its direct dependencies.
	adj := make(map[fetchdomain.ModuleCoordinate][]fetchdomain.ModuleCoordinate)
	for _, e := range g.Edges {
		adj[e.From] = append(adj[e.From], e.To)
	}

	reached := make(map[fetchdomain.ModuleCoordinate]struct{})
	stack := append([]fetchdomain.ModuleCoordinate(nil), adj[origin]...)
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if cur == origin {
			// A self-edge (or a cycle back to origin) never adds origin itself.
			continue
		}
		if _, seen := reached[cur]; seen {
			continue
		}
		reached[cur] = struct{}{}
		stack = append(stack, adj[cur]...)
	}
	return reached
}
