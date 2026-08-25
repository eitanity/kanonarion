package domain

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// DepthBoundedReason is the PartialReason token recorded when a coordinate-rooted
// walk truncates its dependency closure at max_depth. It is distinct from the
// failure reasons (fetch_failed, parse_failed, cancelled) so a deliberately
// bounded graph is never conflated with one that failed to resolve, while still
// marking the closure incomplete — a truncated graph is incomplete for
// audit/vuln/licence/sbom purposes regardless of why. maxDepth is embedded so the
// bound is recoverable from the reason string alone.
func DepthBoundedReason(maxDepth int) string {
	return fmt.Sprintf("depth_bounded: max_depth=%d", maxDepth)
}

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

// HasFetchedArtefact reports whether a node resolved this way names a module
// the fetch pipeline could ever have acquired bytes for.
//
// Three resolution sources never do. A project walk's local main module is the
// caller's own checkout; a local replace redirects a require at a directory on
// disk, so the node keeps the original require coordinate that nothing
// published; and the standard library ships with the toolchain. None of the
// three has a module zip in the blob store, none ever will, and a fetch-record
// lookup for one can only miss. A consumer that treats that miss as a failure
// reports an absence that is there by construction as something that went
// wrong, and cannot then tell it from bytes that should be in the store and are
// not.
//
// A source this build does not recognise answers true: an unknown resolution is
// assumed to owe an artefact, so a genuine miss is reported rather than hidden.
func (s ResolutionSource) HasFetchedArtefact() bool {
	switch s {
	case ResolutionLocalMainModule, ResolutionLocalReplace, ResolutionStdlib:
		return false
	default:
		return true
	}
}

// ArtefactAbsenceNoun names, in a few words, what kind of thing a node with no
// fetched artefact is, for output that states how many of a selection had
// nothing to copy and what they were. It returns "" for a source that does own
// an artefact.
func (s ResolutionSource) ArtefactAbsenceNoun() string {
	switch s {
	case ResolutionLocalMainModule:
		return "local main module"
	case ResolutionLocalReplace:
		return "local replace"
	case ResolutionStdlib:
		return "Go standard library"
	default:
		return ""
	}
}

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
	coord, err := coordinate.NewStdlibCoordinateAt(version)
	if err != nil {
		// NormaliseStdlibVersion produced something that is not a version, so
		// there is no usable stdlib node — the same outcome, and the same false,
		// as the empty result it already guards against above.
		return GraphNode{}, false
	}
	return GraphNode{
		Coordinate:       coord,
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
	Target coordinate.ModuleCoordinate
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

// FrameBasis names why a walk's frame reads the way it does. It is the machine
// half of the frame: the text is written for a reader, and the basis is what a
// caller keys on, so nobody has to recognise a sentinel string.
//
// The three values are three different facts and are never collapsed. A walk
// rooted at a published coordinate resolves no platform at all, and re-walking
// it will never produce one; a project walk with no stored platform is a fact
// that is genuinely missing, and re-walking it does produce one.
type FrameBasis string

const (
	// FrameBasisPlatform: the walk resolved a target platform, and the token is
	// that platform as "goos/goarch".
	FrameBasisPlatform FrameBasis = "platform"
	// FrameBasisNotPlatformScoped: the walk is rooted at a published module
	// coordinate rather than a project, so no platform applies to it.
	FrameBasisNotPlatformScoped FrameBasis = "not_platform_scoped"
	// FrameBasisUnrecorded: the platform is not known — a project walk that
	// stored none, or a walk whose target is not known either.
	FrameBasisUnrecorded FrameBasis = "unrecorded"
)

// Frame text, as every surface renders it.
const (
	frameTextNotPlatformScoped = "not-platform-scoped"
	frameTextUnrecorded        = "unrecorded"
)

// WalkFrame is how one walk names the platform it answers in, together with why
// it names it that way. Text and JSON surfaces both render from this one value
// so they cannot disagree about which of the three situations a walk is in.
type WalkFrame struct {
	// Text is the frame as output names it: "linux/amd64", or a word standing for
	// the reason there is no platform.
	Text string
	// Basis is the machine-readable reason Text reads as it does.
	Basis FrameBasis
}

// String renders the frame the way output names it, so a format verb on the
// value cannot print something a reader has never seen.
func (f WalkFrame) String() string { return f.Text }

// FrameOf derives the frame of a walk over the target it was rooted at and the
// build environment it resolved. The target is required: without it an absent
// platform cannot be told apart from a platform that was never applicable, and
// those are opposite claims about whether re-walking would recover it.
func FrameOf(target coordinate.ModuleCoordinate, env BuildEnv) WalkFrame {
	if env.GOOS != "" || env.GOARCH != "" {
		return WalkFrame{Text: env.GOOS + "/" + env.GOARCH, Basis: FrameBasisPlatform}
	}
	if !target.IsZero() && !target.IsLocal() {
		return WalkFrame{Text: frameTextNotPlatformScoped, Basis: FrameBasisNotPlatformScoped}
	}
	return WalkFrame{Text: frameTextUnrecorded, Basis: FrameBasisUnrecorded}
}

// Frame renders the frame this graph answers in, over its own target.
func (g Graph) Frame() WalkFrame {
	return FrameOf(g.Target, g.BuildEnv)
}

// GraphNode is a single module in the dependency graph.
type GraphNode struct {
	// Coordinate is the module path and MVS-selected version.
	Coordinate coordinate.ModuleCoordinate
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
	OriginalCoordinate coordinate.ModuleCoordinate
	// LocalPath is the filesystem target of a local-path replace directive.
	// Non-empty only when ResolutionSource is ResolutionLocalReplace.
	LocalPath string
	// Digests are the raw SHA-256/384/512 hashes of the module zip (or, for the
	// stdlib node, the source tarball), carried from the fetch fact record or the
	// stdlib acquirer so the SBOM can emit component <hashes>. Zero value for the
	// local main module and nodes that could not be fetched — the SBOM omits
	// <hashes> rather than fabricating.
	Digests fetchdomain.ArtifactDigests
	// Stdlib is the standard library's chain-of-custody evidence, set only on the
	// synthetic stdlib node (ResolutionStdlib) when acquisition succeeded. Nil on
	// every other node, and nil on a stdlib node whose facts could not be
	// acquired (an offline run) — a best-effort coverage gap, not an error.
	Stdlib *StdlibFacts
}

// GraphEdge is a directed dependency relationship between two modules.
type GraphEdge struct {
	// From is the module that declares the dependency.
	From coordinate.ModuleCoordinate
	// To is the dependency at its MVS-selected version.
	To coordinate.ModuleCoordinate
	// ConstraintVersion is the version string appearing in From's go.mod before
	// MVS resolution. It may differ from To.Version when MVS selects a higher version.
	ConstraintVersion string
}

// Sort sorts Nodes and Edges in place, establishing the deterministic ordering
// required for canonical serialisation. Must be called after graph construction.
func (g *Graph) Sort() {
	sort.Slice(g.Nodes, func(i, j int) bool {
		a, b := g.Nodes[i].Coordinate, g.Nodes[j].Coordinate
		if a.Path() != b.Path() {
			return a.Path() < b.Path()
		}
		return a.Version() < b.Version()
	})
	sort.Slice(g.Edges, func(i, j int) bool {
		a, b := g.Edges[i], g.Edges[j]
		if a.From.Path() != b.From.Path() {
			return a.From.Path() < b.From.Path()
		}
		if a.From.Version() != b.From.Version() {
			return a.From.Version() < b.From.Version()
		}
		if a.To.Path() != b.To.Path() {
			return a.To.Path() < b.To.Path()
		}
		return a.To.Version() < b.To.Version()
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
//
// Edges whose target is a module-replace node are skipped: there, To.Path is the
// replacement path but ConstraintVersion is the ORIGINAL required module's
// version, so pairing them fabricates a coordinate that never existed (e.g.
// rqlite/go-sqlite3 at the mattn/go-sqlite3 version). A replaced module is pinned
// by its replace directive and has no superseded intermediate version to read.
func (g Graph) SupersededRequirements() []coordinate.ModuleCoordinate {
	return g.supersededRequirements(nil)
}

// SupersededRequirementsFrom is SupersededRequirements restricted to edges
// originating at one of the given modules. Only a pre-pruning main module makes
// the toolchain read a superseded go.mod, so a caller supplying those versions
// to an offline cache needs the ones those modules require — not every
// superseded version in the walk, most of which belong to modules that load a
// pruned graph and never read them.
func (g Graph) SupersededRequirementsFrom(from map[coordinate.ModuleCoordinate]struct{}) []coordinate.ModuleCoordinate {
	return g.supersededRequirements(from)
}

// supersededRequirements collects the superseded constraint versions on the
// graph's edges. A nil from-set means every edge qualifies.
func (g Graph) supersededRequirements(from map[coordinate.ModuleCoordinate]struct{}) []coordinate.ModuleCoordinate {
	// Keyed by the full replacement COORDINATE, not its path: the same path can
	// carry both a replaced entry and an independent requirement at another
	// version, and keying by path would suppress the independent one's genuine
	// superseded versions along with the replaced one's fabricated pairing.
	replaced := make(map[string]bool)
	for _, n := range g.Nodes {
		if n.OriginalCoordinate.Path() != "" {
			replaced[n.Coordinate.String()] = true
		}
	}
	seen := make(map[coordinate.ModuleCoordinate]struct{})
	for _, e := range g.Edges {
		if from != nil {
			if _, ok := from[e.From]; !ok {
				continue
			}
		}
		if e.ConstraintVersion == "" || e.ConstraintVersion == e.To.Version() {
			continue
		}
		if replaced[e.To.String()] {
			continue
		}
		coord, err := coordinate.NewModuleCoordinate(e.To.Path(), e.ConstraintVersion)
		if err != nil {
			// A constraint that is not a version names no module that was demoted,
			// so there is nothing to report for this edge.
			continue
		}
		seen[coord] = struct{}{}
	}
	out := make([]coordinate.ModuleCoordinate, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path() != out[j].Path() {
			return out[i].Path() < out[j].Path()
		}
		return out[i].Version() < out[j].Version()
	})
	return out
}

// KnownVersions returns the module versions this walk resolved and supplies as
// source: its nodes, plus the coordinate a replaced node stands in for.
//
// Superseded requirement versions are deliberately excluded even though the
// graph records them. The walk knows such a version exists as a fact about some
// module's go.mod, but the project never builds it, so its source is not
// fetched and not meant to be. A module scanned in isolation that re-selects one
// is reaching outside the project's toolchain — the expected consequence of
// hermetic per-module scanning — whereas failing to resolve a SELECTED version
// means the scan cache is missing something the walk undertook to supply. Only
// the latter is a fault, so only the latter belongs here.
func (g Graph) KnownVersions() map[coordinate.ModuleCoordinate]struct{} {
	known := make(map[coordinate.ModuleCoordinate]struct{}, len(g.Nodes))
	for _, n := range g.Nodes {
		known[n.Coordinate] = struct{}{}
		// A replaced node is also referred to by the coordinate it replaced.
		if n.OriginalCoordinate.Path() != "" {
			known[n.OriginalCoordinate] = struct{}{}
		}
	}
	return known
}

// SelectedVersions returns the module versions this walk actually fetched: one
// coordinate per node, always the version the project's build selected.
//
// It is deliberately narrower than KnownVersions, which also carries the
// coordinate a replaced node stands in for. That extra coordinate is a name the
// walk recognises, not a module with source behind it — when a replace
// redirects to a different module, only the replacement is fetched. So the two
// answer different questions: KnownVersions asks "did we undertake to supply
// this version?", which is about classifying a resolution failure, while this
// asks "which versions can actually be resolved offline?", which is what a
// synthesised go.mod's require directives must name. Requiring a replaced-from
// coordinate would demand source that was never fetched and fail every scan
// that depends on it.
// The synthetic standard-library node and a project walk's local root are
// excluded for the same reason: neither has a proxy artefact behind it, so
// neither can be resolved from the store — matching the set the scan's
// GOMODCACHE is populated from.
func (g Graph) SelectedVersions() map[coordinate.ModuleCoordinate]struct{} {
	selected := make(map[coordinate.ModuleCoordinate]struct{}, len(g.Nodes))
	for _, n := range g.Nodes {
		if n.ResolutionSource == ResolutionStdlib || n.Coordinate.IsLocal() {
			continue
		}
		selected[n.Coordinate] = struct{}{}
	}
	return selected
}

// ReachableFrom returns the set of module coordinates transitively reachable
// from origin by following directed edges — origin's full dependency closure.
// The origin itself is never included in the result. The traversal is purely
// structural over the stored graph, so it needs no live fetch or probe.
//
// A coordinate absent from the graph's edges yields an empty set; callers
// distinguish "no dependencies" from "module not in this graph" via the node
// list, not this result.
func (g Graph) ReachableFrom(origin coordinate.ModuleCoordinate) map[coordinate.ModuleCoordinate]struct{} {
	// Adjacency: From → its direct dependencies.
	adj := make(map[coordinate.ModuleCoordinate][]coordinate.ModuleCoordinate)
	for _, e := range g.Edges {
		adj[e.From] = append(adj[e.From], e.To)
	}

	reached := make(map[coordinate.ModuleCoordinate]struct{})
	stack := append([]coordinate.ModuleCoordinate(nil), adj[origin]...)
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

// DirectDependenciesOf returns the modules m depends on directly in this graph,
// and whether the graph holds m at all. The order is the graph's own: sorted by
// (Path, Version) after Sort.
//
// For any module other than the root the answer is m's outgoing edges.
// GraphNode.DirectDependency is a fact about the ROOT's manifest, so reading it
// for a dependency reports the root's direct dependencies as that dependency's —
// 76 against the queried module's 4, measured on a project walk.
//
// For the root itself the flag is what answers, and the edges are not: a main
// module's go.mod requires its whole build list, so the root's outgoing edges
// are that list (127 of 128 nodes on the same walk) while the flag records the
// half the manifest did not mark indirect.
func (g Graph) DirectDependenciesOf(m coordinate.ModuleCoordinate) ([]coordinate.ModuleCoordinate, bool) {
	// The root is in its own closure whether or not a node row was materialised
	// for it, so containment is never decided by the node list for the root.
	if m == g.Target {
		var out []coordinate.ModuleCoordinate
		for _, n := range g.Nodes {
			if n.DirectDependency {
				out = append(out, n.Coordinate)
			}
		}
		return out, true
	}
	held := false
	for _, n := range g.Nodes {
		if n.Coordinate == m {
			held = true
			break
		}
	}
	if !held {
		return nil, false
	}
	var out []coordinate.ModuleCoordinate
	seen := make(map[coordinate.ModuleCoordinate]struct{})
	for _, e := range g.Edges {
		if e.From != m {
			continue
		}
		if _, dup := seen[e.To]; dup {
			continue
		}
		seen[e.To] = struct{}{}
		out = append(out, e.To)
	}
	return out, true
}
