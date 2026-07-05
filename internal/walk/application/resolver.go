package application

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/eitanity/kanonarion/internal/adapters/ziparchive"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	domain3 "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
	"golang.org/x/mod/semver"
	"golang.org/x/sync/errgroup"
)

// PipelineVersion identifies this release of the walk pipeline.
// Bump whenever graph resolution logic changes.
//
// 1.1.0: local-replace requires now produce GraphNodes with
// ResolutionLocalReplace + LocalPath instead of being silently dropped, and
// every replaced node carries OriginalCoordinate.
//
// 1.2.0: graph resolution applies Go 1.17+ module-graph pruning. A module's
// requirements are expanded only when it is the target, a root (a direct or
// indirect requirement of the target, so it provides an imported package), or
// it predates pruning (go < 1.17). Deeper requirements of a pruned go 1.17+
// module are not real build inputs and are dropped, matching `go mod graph`.
//
// 1.3.0: pruning is context-dependent, threaded as expansion propagation
// through the BFS rather than a per-module predicate. The target expands; a
// requirement reached while expanding a parent expands itself only if it is a
// root (a direct/indirect require of the target) or its parent is an expanded
// pre-pruning (go < 1.17) module. A pre-pruning module reached below a go 1.17+
// boundary is therefore a node but its deep requirements are pruned — the
// 1.2.0 predicate over-expanded these, pulling phantom subtrees absent from
// `go mod graph`. Expansion propagates if any qualifying path exists, so a
// module first seen as non-expanding is re-expanded when later reached via a
// qualifying path.
//
// 1.4.0: the project walk derives its module set from the Go toolchain build
// list (`go list -m all` + `go mod graph`) when a BuildListResolver is wired,
// instead of the internal MVS+pruning approximation. The toolchain performs the
// exact lazy-loading arithmetic; kanonarion still fetches and verifies every
// listed module. The internal resolver remains the fallback (with a Partial
// caveat) when the toolchain is unavailable, and the only path for published
// single-module walks.
//
// 1.5.0: a tool-scoped project walk (WalkScopeTool) is now the build list
// restricted to the tooling supply chain — the main anchor plus every module
// reachable from the go.mod tool-directive roots over the dependency graph —
// rather than an independent unpruned walk per tool directive. The default
// (production) project walk is unchanged: the whole build list.
const PipelineVersion = "1.5.0"

// GraphResolver resolves the transitive dependency graph for a target module.
// It is safe for concurrent use once constructed.
type GraphResolver struct {
	parser          walkports.GoModParser
	fetcher         walkports.ModuleFetcher
	blobs           fetchports.BlobStore
	clock           fetchports.Clock
	buildList       walkports.BuildListResolver // nil = internal resolver only
	pipelineVersion string
	workerCount     int // bounded fetch concurrency; ≤0 = defaultWorkerCount
	logger          *slog.Logger
}

// NewGraphResolver constructs a GraphResolver. pipelineVersion defaults to
// PipelineVersion if empty.
func NewGraphResolver(
	parser walkports.GoModParser,
	fetcher walkports.ModuleFetcher,
	blobs fetchports.BlobStore,
	clock fetchports.Clock,
	pipelineVersion string,
	logger *slog.Logger,
) *GraphResolver {
	if pipelineVersion == "" {
		pipelineVersion = PipelineVersion
	}
	return &GraphResolver{
		parser:          parser,
		fetcher:         fetcher,
		blobs:           blobs,
		clock:           clock,
		pipelineVersion: pipelineVersion,
		logger:          logger,
	}
}

// WithBuildListResolver returns a shallow copy of the resolver with a
// BuildListResolver attached, so project walks derive their module set from the
// Go toolchain. The original resolver is unmodified. A subsequent WithFetcher
// clone preserves the attached resolver.
func (r *GraphResolver) WithBuildListResolver(bl walkports.BuildListResolver) *GraphResolver {
	clone := *r
	clone.buildList = bl
	return &clone
}

// WithFetcher returns a shallow copy of the resolver with its fetcher replaced.
// Used by the walker to inject a per-walk recording fetcher so that transitive
// fetch outcomes (FromCache, duration) are observable in WalkOutcome.PerNodeResults
// without re-fetching after resolution. The original resolver is unmodified.
func (r *GraphResolver) WithFetcher(fetcher walkports.ModuleFetcher) *GraphResolver {
	clone := *r
	clone.fetcher = fetcher
	return &clone
}

// WithWorkers returns a shallow copy of the resolver bounded to n concurrent
// fetch workers. The walker sets this from the per-walk WorkerCount so a level's
// independent modules are fetched in parallel; n≤0 restores the default bound.
// The original resolver is unmodified.
func (r *GraphResolver) WithWorkers(n int) *GraphResolver {
	clone := *r
	clone.workerCount = n
	return &clone
}

// workers returns the effective fetch concurrency bound, defaulting an unset
// (≤0) count to defaultWorkerCount. A bound of 1 reproduces sequential fetching.
func (r *GraphResolver) workers() int {
	if r.workerCount <= 0 {
		return defaultWorkerCount
	}
	return r.workerCount
}

// Resolve resolves the full transitive dependency closure for target under MVS.
//
// depth controls traversal: MaxDepth limits hops from the target (0 = unlimited),
// FollowIndirect skips // indirect requirements when false, and FollowReplace
// skips replace directives when false. FollowTest has no effect in the current
// implementation (go.mod carries no test-only signal).
//
// A non-nil error is returned only when the target itself cannot be fetched or
// its go.mod cannot be extracted and parsed. Per-dependency failures produce a
// partial graph; the failed nodes carry ErrorDetail and the graph's Partial flag
// is set.
func (r *GraphResolver) Resolve(ctx context.Context, target domain2.ModuleCoordinate, depth domain3.StageDepth) (domain3.Graph, error) {
	r.logger.InfoContext(ctx, "walk.resolve.start",
		slog.String("module.path", target.Path),
		slog.String("module.version", target.Version),
		slog.String("pipeline_version", r.pipelineVersion),
	)

	// Step 1: fetch target — fatal if this fails.
	targetResult, err := r.fetcher.EnsureFetched(ctx, target)
	if err != nil {
		return domain3.Graph{}, fmt.Errorf("fetching target %s: %w", target, err)
	}

	// Step 2: extract and parse target's go.mod — fatal if this fails.
	targetGoModBytes, err := r.extractGoMod(ctx, targetResult.Record)
	if err != nil {
		return domain3.Graph{}, fmt.Errorf("extracting go.mod for target %s: %w", target, err)
	}
	targetParsed, err := r.parser.Parse("go.mod", targetGoModBytes)
	if err != nil {
		return domain3.Graph{}, fmt.Errorf("parsing go.mod for target %s: %w", target, err)
	}

	return r.resolveFromParsed(ctx, target, targetParsed, domain3.ResolutionTarget, targetResult.Record.Retracted, depth), nil
}

// ResolveProject resolves the transitive closure rooted at the local main
// module, whose go.mod is read from the working tree rather than fetched. The
// main module is added as an unfetched anchor node (ResolutionLocalMainModule)
// at coordinate target (path = the module directive, version = LocalVersion);
// the closure is the union of all its require directives, resolved exactly as
// in Resolve. This produces a single walk record whose subject is the project
// itself rather than one arbitrary dependency.
//
// goModBytes is the raw go.mod content; projectDir is the working-tree directory
// holding go.mod/go.sum (the directory the toolchain is invoked in). When a
// BuildListResolver is wired and projectDir is non-empty, the authoritative module
// set comes from the Go toolchain build list; otherwise (or on toolchain failure)
// the internal MVS resolver runs over goModBytes — on toolchain failure the graph
// is marked Partial so the approximate set is never presented as authoritative.
//
// A non-nil error is returned only when goModBytes cannot be parsed (and the
// build list is unavailable); per-dependency failures produce a partial graph.
// scopeModules restricts the resolved graph to a specific dependency scope: it is
// the set of module paths (the build-list subset the caller computed via the Go
// toolchain — code or tool scope) to retain, alongside the main anchor. A nil
// scopeModules keeps the whole build list (the complete scope).
func (r *GraphResolver) ResolveProject(ctx context.Context, target domain2.ModuleCoordinate, goModBytes []byte, projectDir string, depth domain3.StageDepth, scopeModules []string) (domain3.Graph, error) {
	r.logger.InfoContext(ctx, "walk.resolve_project.start",
		slog.String("module.path", target.Path),
		slog.String("module.version", target.Version),
		slog.Bool("scoped", scopeModules != nil),
		slog.String("pipeline_version", r.pipelineVersion),
	)

	var g domain3.Graph
	if r.buildList != nil && projectDir != "" {
		bl, err := r.buildList.Resolve(ctx, projectDir)
		if err != nil {
			r.logger.WarnContext(ctx, "walk.build_list.unavailable",
				slog.String("project_dir", projectDir),
				slog.String("error", err.Error()),
			)
			g, err = r.resolveProjectFallback(ctx, target, goModBytes, depth)
			if err != nil {
				return domain3.Graph{}, err
			}
		} else {
			g = r.resolveFromBuildList(ctx, target, bl)
		}
	} else {
		var err error
		g, err = r.resolveProjectFallback(ctx, target, goModBytes, depth)
		if err != nil {
			return domain3.Graph{}, err
		}
	}

	// A scoped walk (code or tool) restricts the build-list graph to the caller's
	// module set plus the project anchor; the complete scope (nil) keeps it whole.
	if scopeModules != nil {
		g = domain3.FilterGraphToScope(g, target.Path, scopeModules)
		r.logger.InfoContext(ctx, "walk.scope.complete",
			slog.String("module.path", target.Path),
			slog.Int("node_count", len(g.Nodes)),
		)
	}
	return g, nil
}

// buildListApproxReason is recorded on a project graph whose module set was
// derived by the internal resolver because the Go toolchain was unavailable.
const buildListApproxReason = "build_list_approximate: go toolchain unavailable, module set derived by internal resolver"

// resolveProjectFallback resolves a project walk via the internal MVS resolver.
// When the fallback was reached because the toolchain was unavailable (the only
// caller that hits it with a BuildListResolver wired), the graph is marked
// Partial with buildListApproxReason so the approximate set is never presented as
// authoritative. When no BuildListResolver is configured at all, this is simply
// the legacy resolution path and no caveat is added.
func (r *GraphResolver) resolveProjectFallback(ctx context.Context, target domain2.ModuleCoordinate, goModBytes []byte, depth domain3.StageDepth) (domain3.Graph, error) {
	parsed, err := r.parser.Parse("go.mod", goModBytes)
	if err != nil {
		return domain3.Graph{}, fmt.Errorf("parsing project go.mod for %s: %w", target, err)
	}

	// The main module is local and unpublished, so it is never retracted and
	// carries no fetch record.
	g := r.resolveFromParsed(ctx, target, parsed, domain3.ResolutionLocalMainModule, false, depth)

	if r.buildList != nil {
		g.Partial = true
		if g.PartialReason == "" {
			g.PartialReason = buildListApproxReason
		} else {
			g.PartialReason = buildListApproxReason + "; " + g.PartialReason
		}
	}
	return g, nil
}

// resolveFromBuildList builds the project graph from the Go toolchain build list.
// The main module is the local anchor (ResolutionLocalMainModule, unfetched); every
// other listed module is fetched and verified through the walk fetcher, and its
// resolution source is derived from the toolchain's replace information. Edges come
// from `go mod graph`, with endpoints normalised to the selected (build-list)
// coordinates and the go/toolchain pseudo-nodes excluded.
func (r *GraphResolver) resolveFromBuildList(ctx context.Context, target domain2.ModuleCoordinate, bl walkports.BuildList) domain3.Graph {
	st := &resolveState{
		selected: map[string]string{target.Path: target.Version},
		nodes:    map[string]domain3.GraphNode{},
	}

	// nodeByPath maps a build-list module's own path to the coordinate of the node
	// representing it (the replacement coordinate when a module replace applies, the
	// anchor for the main module). Used to normalise `go mod graph` endpoints.
	nodeByPath := map[string]domain2.ModuleCoordinate{target.Path: target}

	st.nodes[target.Path] = domain3.GraphNode{
		Coordinate:       target,
		DirectDependency: false,
		ResolutionSource: domain3.ResolutionLocalMainModule,
	}

	// Phase 1 (sequential): build every node skeleton and settle selection, then
	// collect the modules that still need a remote fetch. The build list is fully
	// known up front (no BFS discovery), so all fetches are independent.
	type blFetch struct {
		path  string // the module's own (pre-replace) path, for nodeByPath
		coord domain2.ModuleCoordinate
	}
	var fetchTasks []blFetch
	for _, m := range bl.Modules {
		if m.Main {
			// The toolchain main module is the project itself; the anchor above
			// already represents it at the synthetic LocalVersion. Map its path so
			// edges rooted at the main module normalise to the anchor.
			nodeByPath[m.Path] = target
			continue
		}
		node, needFetch := r.buildListNodeSkeleton(m, st)
		st.nodes[node.Coordinate.Path] = node
		nodeByPath[m.Path] = node.Coordinate
		if needFetch {
			fetchTasks = append(fetchTasks, blFetch{path: m.Path, coord: node.Coordinate})
		}
	}

	// Phase 2 (concurrent): fetch the listed modules under a bounded worker pool.
	coords := make([]domain2.ModuleCoordinate, len(fetchTasks))
	for i, t := range fetchTasks {
		coords[i] = t.coord
	}
	results := r.fetchLevel(ctx, coords, r.workers())

	// Phase 3 (sequential): fold each fetch result into its node, in task order.
	for i, t := range fetchTasks {
		node := st.nodes[t.coord.Path]
		if err := results[i].err; err != nil {
			r.logger.WarnContext(ctx, "walk.fetch.failed",
				slog.String("module.path", t.coord.Path),
				slog.String("module.version", t.coord.Version),
				slog.String("error.type", "fetch_failed"),
				slog.String("error", err.Error()),
			)
			st.markPartial("fetch_failed")
			node.ResolutionSource = domain3.ResolutionFetchFailed
			node.ErrorDetail = err.Error()
		} else {
			node.Retracted = results[i].record.Retracted
		}
		st.nodes[t.coord.Path] = node
	}

	// Edges: normalise endpoints, drop pseudo-nodes, dedupe.
	seen := make(map[string]bool, len(bl.Edges))
	for _, e := range bl.Edges {
		from := normaliseEndpoint(e.From, nodeByPath)
		toRaw := parseGraphToken(e.To)
		if isPseudoNode(from.Path) || isPseudoNode(toRaw.Path) {
			continue
		}
		to := toRaw
		if c, ok := nodeByPath[toRaw.Path]; ok {
			to = c
		}
		edge := domain3.GraphEdge{From: from, To: to, ConstraintVersion: toRaw.Version}
		key := edge.From.String() + " -> " + edge.To.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		st.edges = append(st.edges, edge)
	}

	g := domain3.Graph{
		Target:          target,
		PipelineVersion: r.pipelineVersion,
		ResolvedAt:      r.clock.Now().UTC(),
		Partial:         st.partial,
		PartialReason:   st.partialReason,
		HasLocalReplace: st.hasLocalReplace,
	}
	for _, node := range st.nodes {
		g.Nodes = append(g.Nodes, node)
	}
	g.Edges = st.edges
	g.Sort()

	r.logger.InfoContext(ctx, "walk.resolve_project.complete",
		slog.String("module.path", target.Path),
		slog.Int("node_count", len(g.Nodes)),
		slog.Int("edge_count", len(g.Edges)),
		slog.Bool("partial", g.Partial),
	)
	return g
}

// buildListNodeSkeleton turns one (non-main) build-list module into a GraphNode
// and settles its selection against the shared state, returning whether the node
// still needs a remote fetch. A filesystem replacement yields an unfetched
// ResolutionLocalReplace node (needFetch=false); a module replacement yields a
// ResolutionReplace node to be fetched at the replacement coordinate; otherwise a
// ResolutionMVS node fetched at its selected version. The fetch itself and the
// retraction/failure folding are done by the caller so all fetches in a build
// list can run concurrently. Must run sequentially (mutates st.selected).
func (r *GraphResolver) buildListNodeSkeleton(m walkports.BuildListModule, st *resolveState) (domain3.GraphNode, bool) {
	direct := !m.Indirect
	orig := domain2.ModuleCoordinate{Path: m.Path, Version: m.Version}

	// Filesystem replacement: a directory target with no version. Not fetchable —
	// recorded as a local-replace node for downstream skip-with-reason.
	if m.Replace != nil && m.Replace.Version == "" {
		st.hasLocalReplace = true
		st.selected[orig.Path] = orig.Version
		return domain3.GraphNode{
			Coordinate:         orig,
			DirectDependency:   direct,
			ResolutionSource:   domain3.ResolutionLocalReplace,
			OriginalCoordinate: orig,
			LocalPath:          m.Replace.Path,
		}, false
	}

	effective := orig
	source := domain3.ResolutionMVS
	var original domain2.ModuleCoordinate
	if m.Replace != nil {
		effective = domain2.ModuleCoordinate{Path: m.Replace.Path, Version: m.Replace.Version}
		source = domain3.ResolutionReplace
		original = orig
	}
	st.selected[effective.Path] = effective.Version

	return domain3.GraphNode{
		Coordinate:         effective,
		DirectDependency:   direct,
		ResolutionSource:   source,
		OriginalCoordinate: original,
	}, true
}

// fetchResult pairs a fetched fact record with any per-coordinate fetch error.
type fetchResult struct {
	record domain2.FactRecord
	err    error
}

// fetchLevel fetches every coordinate concurrently under a bounded worker pool,
// returning results in the same order as coords so the sequential apply phase
// stays deterministic. It touches no shared state; per-coordinate errors are
// captured in the result rather than returned, so the group only unwinds on
// context cancellation. workers≤0 falls back to sequential processing.
func (r *GraphResolver) fetchLevel(ctx context.Context, coords []domain2.ModuleCoordinate, workers int) []fetchResult {
	results := make([]fetchResult, len(coords))
	if len(coords) == 0 {
		return results
	}
	g, gctx := errgroup.WithContext(ctx)
	if workers > 0 {
		g.SetLimit(workers)
	}
	for i, c := range coords {
		g.Go(func() error {
			fr, err := r.fetcher.EnsureFetched(gctx, c)
			results[i] = fetchResult{record: fr.Record, err: err}
			return nil
		})
	}
	_ = g.Wait()
	return results
}

// parseGraphToken parses a `go mod graph` endpoint token into a coordinate.
// "path@version" splits on the last "@"; a bare "path" (the main module) yields an
// empty version.
func parseGraphToken(tok string) domain2.ModuleCoordinate {
	if i := strings.LastIndex(tok, "@"); i >= 0 {
		return domain2.ModuleCoordinate{Path: tok[:i], Version: tok[i+1:]}
	}
	return domain2.ModuleCoordinate{Path: tok}
}

// normaliseEndpoint parses a graph endpoint token and, when its path is a known
// build-list module, rewrites it to that module's selected coordinate so edges
// connect the same nodes the build list produced.
func normaliseEndpoint(tok string, nodeByPath map[string]domain2.ModuleCoordinate) domain2.ModuleCoordinate {
	raw := parseGraphToken(tok)
	if c, ok := nodeByPath[raw.Path]; ok {
		return c
	}
	return raw
}

// isPseudoNode reports whether path is one of the synthetic graph nodes the Go
// toolchain emits for the language and toolchain version, which are not modules.
func isPseudoNode(path string) bool {
	return path == "go" || path == "toolchain"
}

// resolveFromParsed runs MVS resolution over targetParsed's directives, rooted
// at target. targetSource is the ResolutionSource recorded for the root node
// (ResolutionTarget for a fetched module, ResolutionLocalMainModule for a
// project walk); targetRetracted records whether the root itself is retracted.
// It never returns an error: per-dependency failures set the graph's Partial
// flag with the reason recorded on the relevant node.
func (r *GraphResolver) resolveFromParsed(
	ctx context.Context,
	target domain2.ModuleCoordinate,
	targetParsed domain3.ParsedGoMod,
	targetSource domain3.ResolutionSource,
	targetRetracted bool,
	depth domain3.StageDepth,
) domain3.Graph {
	// Step 3: build replace/exclude lookup from target's directives only.
	// In Go's module system, only the main module's replace/exclude apply to the graph.
	// When depth.FollowReplace is false, replace directives are ignored.
	// A fetched target's filesystem replaces are dropped (see effectiveReplaces):
	// they cannot be satisfied from a module zip and would strand fetchable deps
	// as unresolvable local-replace nodes.
	replaces := effectiveReplaces(targetParsed.Replace, targetSource)
	var replaceMap map[replaceKey]domain3.Replacement
	if depth.FollowReplace {
		replaceMap = buildReplaceMap(replaces)
	} else {
		replaceMap = make(map[replaceKey]domain3.Replacement)
	}
	excludeSet := buildExcludeSet(targetParsed.Exclude)

	// Root set for Go 1.17+ module-graph pruning: the module paths the target
	// itself requires (direct and indirect). A requirement always expands when
	// it is a root — it provides a package the target imports — regardless of
	// the path by which the BFS first reaches it. Non-root expansion propagates
	// only down pre-pruning (go < 1.17) chains.
	roots := make(map[string]bool, len(targetParsed.Require))
	for _, req := range targetParsed.Require {
		roots[req.Coordinate.Path] = true
	}

	st := &resolveState{
		selected:     map[string]string{target.Path: target.Version},
		processed:    map[string]bool{target.String(): true},
		nodes:        map[string]domain3.GraphNode{},
		parsed:       map[string]parsedRequires{},
		expandedKeys: map[string]bool{},
	}
	if depth.FollowReplace {
		st.hasLocalReplace = anyLocalReplace(replaces)
	}

	// Add target node.
	st.nodes[target.Path] = domain3.GraphNode{
		Coordinate:       target,
		DirectDependency: false,
		ResolutionSource: targetSource,
		Retracted:        targetRetracted,
	}

	// Step 4: seed queue with target's direct dependencies.
	queue := r.seedDirectDeps(target, filterRequires(targetParsed.Require, depth.FollowIndirect), replaceMap, excludeSet, st)

	// Seeded coordinates are the target's own requirements, i.e. roots, so each
	// expands. Deeper expansion is decided per child during the BFS.
	depthQueue := make([]queueItem, len(queue))
	for i, c := range queue {
		depthQueue[i] = queueItem{coord: c, depth: 1, expand: true}
	}

	// Step 5: BFS over transitive dependencies, one level at a time. Within a
	// level every module is independent — a module's go.mod parse only gates the
	// *next* level's discovery — so a whole level is fetched+parsed concurrently
	// under a bounded worker pool, then folded back into the (single-threaded)
	// resolve state and expanded to seed the next level. Level N+1 is gated on
	// level N's parses, preserving MVS selection and expansion-propagation order.
	workers := r.workers()
	for len(depthQueue) > 0 {
		if err := ctx.Err(); err != nil {
			st.markPartial("cancelled")
			r.logger.InfoContext(ctx, "walk.resolve.cancelled",
				slog.Int("nodes_resolved", len(st.nodes)),
			)
			break
		}

		wave := depthQueue
		depthQueue = nil

		// Phase 1 (sequential): MVS-coerce each queued item and decide, against
		// the shared state, which need a fetch+parse and which need expansion.
		// Marking st.processed here dedupes fetches within the wave; a local set
		// dedupes expansion tasks the same way the old in-loop expandedKeys guard
		// did. No network or parse work happens here.
		var toFetch []bfsItem
		var toExpand []bfsItem
		expandQueued := make(map[string]bool)
		for _, item := range wave {
			coord := item.coord
			if sel := st.selected[coord.Path]; sel != coord.Version {
				coord = domain2.ModuleCoordinate{Path: coord.Path, Version: sel}
			}
			key := coord.String()

			alreadyProcessed := st.processed[key]
			if alreadyProcessed && (!item.expand || st.expandedKeys[key]) {
				continue
			}
			atMaxDepth := depth.MaxDepth > 0 && item.depth >= depth.MaxDepth
			bi := bfsItem{coord: coord, key: key, depth: item.depth, atMaxDepth: atMaxDepth}

			if !alreadyProcessed {
				st.processed[key] = true
				toFetch = append(toFetch, bi)
			}
			if item.expand && !st.expandedKeys[key] && !expandQueued[key] {
				expandQueued[key] = true
				toExpand = append(toExpand, bi)
			}
		}

		// Phase 2 (concurrent): fetch+parse the level's new modules off the shared
		// state, bounded by the worker pool. Per-module failures are captured in
		// the outcome, not returned, so the group only ends on context cancel.
		outcomes := r.fetchParseLevel(ctx, toFetch, workers)

		// Phase 3 (sequential): fold each outcome back into the resolve state in a
		// fixed order (toFetch order), so node/edge/partial mutations stay
		// deterministic regardless of fetch completion order.
		for _, out := range outcomes {
			r.applyFetchParse(ctx, out, depth.FollowIndirect, st)
		}

		// Phase 4 (sequential): expand each qualifying module's requirements once,
		// seeding the next level. A child expands iff it is a root or this parent
		// is a pre-pruning (go < 1.17) module — applyFetchParse only records
		// st.parsed for modules with a real go.mod, so failures and leaves expand
		// to nothing.
		for _, bi := range toExpand {
			if st.expandedKeys[bi.key] {
				continue
			}
			st.expandedKeys[bi.key] = true
			pr, ok := st.parsed[bi.key]
			if !ok {
				continue
			}
			parentPrePruning := domain3.PrePruning(pr.goVersion)
			for _, req := range pr.requires {
				depthQueue = enqueueTransitive(
					req, bi.coord, bi.depth, bi.atMaxDepth,
					parentPrePruning, roots,
					replaceMap, excludeSet, depth.FollowReplace,
					st, depthQueue,
				)
			}
		}
	}

	// Step 6: post-process edges — update To.Version to MVS-selected version.
	for i := range st.edges {
		if sel, ok := st.selected[st.edges[i].To.Path]; ok {
			st.edges[i].To.Version = sel
		}
	}

	// Step 7: build and return the final graph.
	g := domain3.Graph{
		Target:          target,
		PipelineVersion: r.pipelineVersion,
		ResolvedAt:      r.clock.Now().UTC(),
		Partial:         st.partial,
		PartialReason:   st.partialReason,
		HasLocalReplace: st.hasLocalReplace,
	}
	for _, node := range st.nodes {
		g.Nodes = append(g.Nodes, node)
	}
	g.Edges = st.edges
	g.Sort()

	r.logger.InfoContext(ctx, "walk.resolve.complete",
		slog.String("module.path", target.Path),
		slog.String("module.version", target.Version),
		slog.Int("node_count", len(g.Nodes)),
		slog.Int("edge_count", len(g.Edges)),
		slog.Bool("partial", g.Partial),
	)

	return g
}

// ResolveShallow fetches only the target module, parses its go.mod require
// entries, and builds a flat graph without fetching any of the listed deps.
// The returned graph has Partial=true and PartialReason="shallow" to signal
// that transitive deps are absent. Only the target node is fetched; dep nodes
// carry ResolutionSource=ResolutionMVS with no fetch record.
func (r *GraphResolver) ResolveShallow(ctx context.Context, target domain2.ModuleCoordinate) (domain3.Graph, error) {
	r.logger.InfoContext(ctx, "walk.resolve_shallow.start",
		slog.String("module.path", target.Path),
		slog.String("module.version", target.Version),
	)

	targetResult, err := r.fetcher.EnsureFetched(ctx, target)
	if err != nil {
		return domain3.Graph{}, fmt.Errorf("fetching target %s: %w", target, err)
	}

	targetGoModBytes, err := r.extractGoMod(ctx, targetResult.Record)
	if err != nil {
		return domain3.Graph{}, fmt.Errorf("extracting go.mod for target %s: %w", target, err)
	}
	targetParsed, err := r.parser.Parse("go.mod", targetGoModBytes)
	if err != nil {
		return domain3.Graph{}, fmt.Errorf("parsing go.mod for target %s: %w", target, err)
	}

	// A shallow walk is always rooted at a fetched module, so its filesystem
	// replaces are dropped (see effectiveReplaces).
	replaces := effectiveReplaces(targetParsed.Replace, domain3.ResolutionTarget)
	replaceMap := buildReplaceMap(replaces)
	excludeSet := buildExcludeSet(targetParsed.Exclude)

	st := &resolveState{
		selected:        map[string]string{target.Path: target.Version},
		processed:       map[string]bool{target.String(): true},
		nodes:           map[string]domain3.GraphNode{},
		hasLocalReplace: anyLocalReplace(replaces),
	}

	st.nodes[target.Path] = domain3.GraphNode{
		Coordinate:       target,
		DirectDependency: false,
		ResolutionSource: domain3.ResolutionTarget,
		Retracted:        targetResult.Record.Retracted,
	}

	// Seed all require entries (direct and indirect) as unlisted nodes without
	// fetching them. We return the queue but intentionally do not process it.
	_ = r.seedDirectDeps(target, filterRequires(targetParsed.Require, true), replaceMap, excludeSet, st)

	g := domain3.Graph{
		Target:          target,
		PipelineVersion: r.pipelineVersion,
		ResolvedAt:      r.clock.Now().UTC(),
		Partial:         true,
		PartialReason:   "shallow",
		HasLocalReplace: st.hasLocalReplace,
	}
	for _, node := range st.nodes {
		g.Nodes = append(g.Nodes, node)
	}
	g.Edges = st.edges
	g.Sort()

	r.logger.InfoContext(ctx, "walk.resolve_shallow.complete",
		slog.String("module.path", target.Path),
		slog.String("module.version", target.Version),
		slog.Int("node_count", len(g.Nodes)),
	)
	return g, nil
}

// seedDirectDeps enqueues the direct dependencies of the target and adds their
// initial GraphNode entries. It returns the initial work queue.
func (r *GraphResolver) seedDirectDeps(
	target domain2.ModuleCoordinate,
	requires []domain3.Requirement,
	replaceMap map[replaceKey]domain3.Replacement,
	excludeSet map[excludeKey]bool,
	st *resolveState,
) []domain2.ModuleCoordinate {
	queue := make([]domain2.ModuleCoordinate, 0, len(requires))
	for _, req := range requires {
		out := applyReplace(req.Coordinate, replaceMap)
		if out.localReplace {
			st.hasLocalReplace = true
			st.edges = append(st.edges, domain3.GraphEdge{
				From:              target,
				To:                out.effective,
				ConstraintVersion: req.Coordinate.Version,
			})
			if _, exists := st.nodes[out.effective.Path]; !exists {
				st.selected[out.effective.Path] = out.effective.Version
				st.nodes[out.effective.Path] = domain3.GraphNode{
					Coordinate:         out.effective,
					DirectDependency:   true,
					ResolutionSource:   domain3.ResolutionLocalReplace,
					OriginalCoordinate: req.Coordinate,
					LocalPath:          out.localPath,
				}
			}
			continue
		}
		effective := out.effective
		if isExcluded(effective, excludeSet) {
			continue
		}

		source := domain3.ResolutionMVS
		if out.replaced {
			source = domain3.ResolutionReplace
		}

		st.edges = append(st.edges, domain3.GraphEdge{
			From:              target,
			To:                effective,
			ConstraintVersion: req.Coordinate.Version,
		})

		var original domain2.ModuleCoordinate
		if out.replaced {
			original = req.Coordinate
		}

		currentSel := st.selected[effective.Path]
		switch {
		case currentSel == "":
			st.selected[effective.Path] = effective.Version
			st.nodes[effective.Path] = domain3.GraphNode{
				Coordinate:         effective,
				DirectDependency:   true,
				ResolutionSource:   source,
				OriginalCoordinate: original,
			}
			queue = append(queue, effective)
		case versionGT(effective.Version, currentSel):
			st.selected[effective.Path] = effective.Version
			newCoord := domain2.ModuleCoordinate{Path: effective.Path, Version: effective.Version}
			prev := st.nodes[effective.Path]
			st.nodes[effective.Path] = domain3.GraphNode{
				Coordinate:         newCoord,
				DirectDependency:   prev.DirectDependency || true,
				ResolutionSource:   source,
				OriginalCoordinate: original,
			}
			queue = append(queue, newCoord)
		default:
			// currentSel >= effective.Version — mark as direct dep but keep higher version.
			prev := st.nodes[effective.Path]
			st.nodes[effective.Path] = domain3.GraphNode{
				Coordinate:         prev.Coordinate,
				DirectDependency:   true,
				ResolutionSource:   prev.ResolutionSource,
				ErrorDetail:        prev.ErrorDetail,
				Retracted:          prev.Retracted,
				OriginalCoordinate: prev.OriginalCoordinate,
				LocalPath:          prev.LocalPath,
			}
		}
	}
	return queue
}

// bfsItem is a wave entry whose MVS-selected coordinate and BFS metadata have
// already been resolved against the shared state, so fetch+parse and expansion
// can be split across the concurrent and sequential phases of a level.
type bfsItem struct {
	coord      domain2.ModuleCoordinate
	key        string // coord.String() (the selected coordinate)
	depth      int
	atMaxDepth bool
}

// fetchParseOutcome carries the result of fetching+parsing one module off the
// shared resolve state, so applyFetchParse can fold it back in sequentially.
// Exactly one of the error fields is set on failure; on success goModBytes is
// nil for a pre-modules leaf and parsed holds the requirements otherwise.
type fetchParseOutcome struct {
	coord      domain2.ModuleCoordinate
	key        string
	record     domain2.FactRecord
	fetchErr   error
	extractErr error
	parseErr   error
	hasGoMod   bool
	parsed     domain3.ParsedGoMod
}

// fetchParseLevel fetches+parses every item in a BFS level concurrently under a
// bounded worker pool, returning outcomes in the same order as items so the
// sequential apply phase stays deterministic. It touches no shared resolve
// state; per-module failures are recorded in the outcome rather than returned,
// so the group only unwinds on context cancellation. workers≤0 falls back to
// sequential processing.
func (r *GraphResolver) fetchParseLevel(ctx context.Context, items []bfsItem, workers int) []fetchParseOutcome {
	outcomes := make([]fetchParseOutcome, len(items))
	if len(items) == 0 {
		return outcomes
	}
	g, gctx := errgroup.WithContext(ctx)
	if workers > 0 {
		g.SetLimit(workers)
	}
	for i, item := range items {
		g.Go(func() error {
			outcomes[i] = r.fetchAndParseModule(gctx, item.coord, item.key)
			return nil
		})
	}
	// Workers never return an error; Wait only surfaces context cancellation,
	// which is already reflected in each cancelled outcome's fetchErr.
	_ = g.Wait()
	return outcomes
}

// fetchAndParseModule fetches coord and parses its go.mod without touching the
// shared resolve state, so it is safe to run concurrently across a BFS level.
// The returned outcome is folded into the state by applyFetchParse.
func (r *GraphResolver) fetchAndParseModule(ctx context.Context, coord domain2.ModuleCoordinate, key string) fetchParseOutcome {
	out := fetchParseOutcome{coord: coord, key: key}

	fetchResult, fetchErr := r.fetcher.EnsureFetched(ctx, coord)
	if fetchErr != nil {
		out.fetchErr = fetchErr
		return out
	}
	out.record = fetchResult.Record

	// nil bytes means the zip has no go.mod — module predates Go modules, so
	// treat it as a leaf with no dependencies.
	goModBytes, extractErr := r.extractGoMod(ctx, fetchResult.Record)
	if extractErr != nil {
		out.extractErr = extractErr
		return out
	}
	if goModBytes == nil {
		return out
	}
	out.hasGoMod = true

	parsed, parseErr := r.parser.Parse("go.mod", goModBytes)
	if parseErr != nil {
		out.parseErr = parseErr
		return out
	}
	out.parsed = parsed
	return out
}

// applyFetchParse folds a concurrent fetchParseOutcome back into the resolve
// state: it updates the node (retraction, resolution source, error detail), and
// on success caches the module's depth-filtered requirements and declared go
// version in st.parsed[out.key]. Fetch, extract, and parse failures set the
// node's failure state and mark the graph partial; they leave st.parsed unset,
// so the expansion step finds no requirements to enqueue. Must run sequentially.
func (r *GraphResolver) applyFetchParse(ctx context.Context, out fetchParseOutcome, followIndirect bool, st *resolveState) {
	coord := out.coord

	if out.fetchErr != nil {
		r.logger.WarnContext(ctx, "walk.fetch.failed",
			slog.String("module.path", coord.Path),
			slog.String("module.version", coord.Version),
			slog.String("error.type", "fetch_failed"),
			slog.String("error", out.fetchErr.Error()),
		)
		st.markPartial("fetch_failed")
		existing := st.nodes[coord.Path]
		st.nodes[coord.Path] = domain3.GraphNode{
			Coordinate:         coord,
			DirectDependency:   existing.DirectDependency,
			ResolutionSource:   domain3.ResolutionFetchFailed,
			ErrorDetail:        out.fetchErr.Error(),
			OriginalCoordinate: existing.OriginalCoordinate,
		}
		return
	}

	// Update node with retraction info; preserve the ResolutionSource set when the
	// node was first enqueued (which already accounts for replace directives).
	existing := st.nodes[coord.Path]
	st.nodes[coord.Path] = domain3.GraphNode{
		Coordinate:         coord,
		DirectDependency:   existing.DirectDependency,
		ResolutionSource:   existing.ResolutionSource,
		Retracted:          out.record.Retracted,
		OriginalCoordinate: existing.OriginalCoordinate,
	}

	if out.extractErr != nil {
		r.logger.WarnContext(ctx, "walk.gomod.extract.failed",
			slog.String("module.path", coord.Path),
			slog.String("module.version", coord.Version),
			slog.String("error", out.extractErr.Error()),
		)
		st.markPartial("parse_failed")
		prev := st.nodes[coord.Path]
		st.nodes[coord.Path] = domain3.GraphNode{
			Coordinate:         coord,
			DirectDependency:   prev.DirectDependency,
			ResolutionSource:   domain3.ResolutionParseFailed,
			ErrorDetail:        fmt.Sprintf("extracting go.mod: %v", out.extractErr),
			OriginalCoordinate: prev.OriginalCoordinate,
		}
		return
	}
	if !out.hasGoMod {
		r.logger.InfoContext(ctx, "walk.gomod.absent",
			slog.String("module.path", coord.Path),
			slog.String("module.version", coord.Version),
		)
		prev := st.nodes[coord.Path]
		st.nodes[coord.Path] = domain3.GraphNode{
			Coordinate:         coord,
			DirectDependency:   prev.DirectDependency,
			ResolutionSource:   prev.ResolutionSource,
			Retracted:          prev.Retracted,
			OriginalCoordinate: prev.OriginalCoordinate,
		}
		return
	}

	if out.parseErr != nil {
		r.logger.WarnContext(ctx, "walk.gomod.parse.failed",
			slog.String("module.path", coord.Path),
			slog.String("module.version", coord.Version),
			slog.String("error", out.parseErr.Error()),
		)
		st.markPartial("parse_failed")
		st.nodes[coord.Path] = domain3.GraphNode{
			Coordinate:       coord,
			DirectDependency: st.nodes[coord.Path].DirectDependency,
			ResolutionSource: domain3.ResolutionParseFailed,
			ErrorDetail:      out.parseErr.Error(),
		}
		return
	}

	st.parsed[out.key] = parsedRequires{
		requires:  filterRequires(out.parsed.Require, followIndirect),
		goVersion: out.parsed.GoVersion,
	}
}

// extractGoMod returns the go.mod bytes for fact. The fetch context stores the
// go.mod as its own content-addressed blob (GoModLocation) and verifies it
// against the zip-embedded copy, so reading that blob directly is equivalent
// to scanning the module archive while avoiding a full-zip read + decompress
// for every node on every walk — the dominant redundant cost across
// overlapping/partial walks. Falls back to the zip scan for older
// fact records that predate standalone go.mod storage. nil bytes means the
// module has no go.mod (pre-modules); callers treat it as a leaf.
func (r *GraphResolver) extractGoMod(ctx context.Context, fact domain2.FactRecord) ([]byte, error) {
	if fact.GoModLocation != "" {
		data, err := r.readBlob(ctx, fact.GoModLocation)
		if err != nil {
			return nil, fmt.Errorf("reading go.mod blob for %s@%s: %w", fact.ModulePath, fact.ModuleVersion, err)
		}
		// An empty standalone go.mod is equivalent to "no go.mod" — preserve
		// the leaf-node semantics of the zip-scan path.
		if len(data) == 0 {
			return nil, nil
		}
		return data, nil
	}

	// Fallback: older fact records without a standalone go.mod blob — scan the
	// module zip for the go.mod entry.
	zipData, err := r.readBlob(ctx, fact.ContentLocation)
	if err != nil {
		return nil, fmt.Errorf("reading blob for %s@%s: %w", fact.ModulePath, fact.ModuleVersion, err)
	}

	archive, err := ziparchive.New(zipData)
	if err != nil {
		return nil, fmt.Errorf("opening zip for %s@%s: %w", fact.ModulePath, fact.ModuleVersion, err)
	}

	// Match the entry name exactly — no path traversal. A missing go.mod means
	// the module predates Go modules and has no declared dependencies; return
	// nil bytes so callers treat it as a leaf node.
	target := fact.ModulePath + "@" + fact.ModuleVersion + "/go.mod"
	data, found, err := archive.ReadFile(target)
	if err != nil {
		return nil, fmt.Errorf("reading go.mod from zip for %s@%s: %w", fact.ModulePath, fact.ModuleVersion, err)
	}
	if !found {
		return nil, nil
	}
	return data, nil
}

// readBlob reads the full contents of the blob identified by handle, ensuring
// the reader is closed.
func (r *GraphResolver) readBlob(ctx context.Context, handle string) (_ []byte, retErr error) {
	rc, err := r.blobs.Get(ctx, fetchports.BlobHandle(handle))
	if err != nil {
		return nil, fmt.Errorf("getting blob %s: %w", handle, err)
	}
	defer func() {
		if cerr := rc.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("closing blob reader for %s: %w", handle, cerr)
		}
	}()

	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("reading blob %s: %w", handle, err)
	}
	return data, nil
}

// queueItem pairs a coordinate with its BFS depth from the target and whether
// its own requirements should be expanded (enqueued). A module reached via
// several paths is expanded if any path sets expand; a non-expanding visit
// still contributes the node, only its deeper requirements are withheld.
type queueItem struct {
	coord  domain2.ModuleCoordinate
	depth  int
	expand bool
}

// filterRequires returns reqs filtered to only direct requirements when
// followIndirect is false.
func filterRequires(reqs []domain3.Requirement, followIndirect bool) []domain3.Requirement {
	if followIndirect {
		return reqs
	}
	out := make([]domain3.Requirement, 0, len(reqs))
	for _, req := range reqs {
		if !req.Indirect {
			out = append(out, req)
		}
	}
	return out
}

// enqueueTransitive processes one requirement from a transitive dependency's
// go.mod: applies replace/exclude, records the edge, and enqueues the
// requirement unless atMaxDepth. Returns the (possibly updated) depthQueue.
//
// The enqueued item's expand flag follows the propagation rule: the requirement
// expands its own requirements iff it is a root (roots[effective.Path]) or its
// parent is an expanded pre-pruning module (parentPrePruning). A requirement
// already seen on a non-expanding path is re-enqueued for expansion when this
// path qualifies it, so an expand-worthy path is never lost to discovery order.
func enqueueTransitive(
	req domain3.Requirement,
	fromCoord domain2.ModuleCoordinate,
	currentDepth int,
	atMaxDepth bool,
	parentPrePruning bool,
	roots map[string]bool,
	replaceMap map[replaceKey]domain3.Replacement,
	excludeSet map[excludeKey]bool,
	followReplace bool,
	st *resolveState,
	depthQueue []queueItem,
) []queueItem {
	out := applyReplace(req.Coordinate, replaceMap)
	if out.localReplace {
		if followReplace {
			st.hasLocalReplace = true
			st.edges = append(st.edges, domain3.GraphEdge{
				From:              fromCoord,
				To:                out.effective,
				ConstraintVersion: req.Coordinate.Version,
			})
			if _, exists := st.nodes[out.effective.Path]; !exists {
				st.selected[out.effective.Path] = out.effective.Version
				st.nodes[out.effective.Path] = domain3.GraphNode{
					Coordinate:         out.effective,
					DirectDependency:   false,
					ResolutionSource:   domain3.ResolutionLocalReplace,
					OriginalCoordinate: req.Coordinate,
					LocalPath:          out.localPath,
				}
			}
		}
		return depthQueue
	}
	effective := out.effective
	if isExcluded(effective, excludeSet) {
		return depthQueue
	}

	// A requirement expands its own requirements iff it is a root or its parent
	// is an expanded pre-pruning module.
	expand := roots[effective.Path] || parentPrePruning

	source := domain3.ResolutionMVS
	if out.replaced {
		source = domain3.ResolutionReplace
	}
	var original domain2.ModuleCoordinate
	if out.replaced {
		original = req.Coordinate
	}

	st.edges = append(st.edges, domain3.GraphEdge{
		From:              fromCoord,
		To:                effective,
		ConstraintVersion: req.Coordinate.Version,
	})

	if atMaxDepth {
		if st.selected[effective.Path] == "" {
			st.selected[effective.Path] = effective.Version
			st.nodes[effective.Path] = domain3.GraphNode{
				Coordinate:         effective,
				DirectDependency:   false,
				ResolutionSource:   source,
				OriginalCoordinate: original,
			}
		}
		return depthQueue
	}

	currentSel := st.selected[effective.Path]
	switch {
	case currentSel == "":
		st.selected[effective.Path] = effective.Version
		st.nodes[effective.Path] = domain3.GraphNode{
			Coordinate:         effective,
			DirectDependency:   false,
			ResolutionSource:   source,
			OriginalCoordinate: original,
		}
		depthQueue = append(depthQueue, queueItem{coord: effective, depth: currentDepth + 1, expand: expand})
	case versionGT(effective.Version, currentSel):
		st.selected[effective.Path] = effective.Version
		newCoord := domain2.ModuleCoordinate{Path: effective.Path, Version: effective.Version}
		prev := st.nodes[effective.Path]
		st.nodes[effective.Path] = domain3.GraphNode{
			Coordinate:         newCoord,
			DirectDependency:   prev.DirectDependency,
			ResolutionSource:   source,
			OriginalCoordinate: original,
		}
		depthQueue = append(depthQueue, queueItem{coord: newCoord, depth: currentDepth + 1, expand: expand})
	default:
		// Already selected at this version or higher, so the node and its MVS
		// version stand. But if this path qualifies the module for expansion and
		// it has not yet expanded, re-enqueue the selected coordinate so its
		// requirements are followed — discovery order must not strand an
		// expand-worthy path.
		if expand {
			selCoord := domain2.ModuleCoordinate{Path: effective.Path, Version: currentSel}
			if !st.expandedKeys[selCoord.String()] {
				depthQueue = append(depthQueue, queueItem{coord: selCoord, depth: currentDepth + 1, expand: true})
			}
		}
	}
	return depthQueue
}

// resolveState holds mutable BFS state. It is not safe for concurrent use.
type resolveState struct {
	selected  map[string]string
	processed map[string]bool
	nodes     map[string]domain3.GraphNode
	// parsed caches a successfully fetched module's filtered requirements and
	// declared go version, keyed by selected coordinate, so a module first
	// reached as non-expanding can be expanded later without a second fetch.
	parsed map[string]parsedRequires
	// expandedKeys records the selected coordinates whose requirements have
	// already been enqueued, so expansion happens at most once per module.
	expandedKeys    map[string]bool
	edges           []domain3.GraphEdge
	partial         bool
	partialReason   string
	hasLocalReplace bool
}

// parsedRequires is the cached parse outcome needed to expand a module's
// requirements on a later visit: the depth-filtered requires and the parent's
// declared go version (which decides whether expansion propagates to children).
type parsedRequires struct {
	requires  []domain3.Requirement
	goVersion string
}

func (s *resolveState) markPartial(reason string) {
	s.partial = true
	if s.partialReason == "" {
		s.partialReason = reason
	} else if !strings.Contains(s.partialReason, reason) {
		s.partialReason = s.partialReason + "," + reason
	}
}

// replaceKey identifies a replace directive's Old side. Version may be empty
// for wildcard replacements (all versions of a path).
type replaceKey struct {
	path    string
	version string
}

// excludeKey identifies a specific version to exclude.
type excludeKey struct {
	path    string
	version string
}

// buildReplaceMap builds a fast lookup from the target's replace directives.
func buildReplaceMap(replacements []domain3.Replacement) map[replaceKey]domain3.Replacement {
	m := make(map[replaceKey]domain3.Replacement, len(replacements))
	for _, r := range replacements {
		m[replaceKey{r.OldPath, r.OldVersion}] = r
	}
	return m
}

// buildExcludeSet builds a fast lookup from the target's exclude directives.
func buildExcludeSet(exclusions []domain3.Exclusion) map[excludeKey]bool {
	m := make(map[excludeKey]bool, len(exclusions))
	for _, e := range exclusions {
		m[excludeKey{e.Coordinate.Path, e.Coordinate.Version}] = true
	}
	return m
}

// anyLocalReplace reports whether any replacement is a local path.
func anyLocalReplace(replacements []domain3.Replacement) bool {
	for _, r := range replacements {
		if r.IsLocal {
			return true
		}
	}
	return false
}

// effectiveReplaces returns the replace directives that apply to a graph rooted
// at a module with the given resolution source.
//
// A proxy-fetched module (ResolutionTarget) is analysed as the published
// artefact a consumer would import. Go ignores a dependency module's own replace
// directives, and a filesystem (local-path) replace can never be satisfied from
// the module zip because its on-disk target is absent from the published
// content. Honouring such a replace strands a real, fetchable dependency as an
// unresolvable local-replace node — the dependency then reads as unanalysable
// when it is in fact scannable. So local-path replaces are dropped for a fetched
// target; module-version replaces (which still name a fetchable coordinate) are
// kept.
//
// A local main module (ResolutionLocalMainModule) is resolved against a present
// working tree, so its filesystem replaces point at real directories and remain
// authoritative — they are returned unchanged.
func effectiveReplaces(replacements []domain3.Replacement, targetSource domain3.ResolutionSource) []domain3.Replacement {
	if targetSource != domain3.ResolutionTarget {
		return replacements
	}
	out := make([]domain3.Replacement, 0, len(replacements))
	for _, r := range replacements {
		if r.IsLocal {
			continue
		}
		out = append(out, r)
	}
	return out
}

// replaceOutcome is the result of applying replace directives to a require.
type replaceOutcome struct {
	// effective is the coordinate to insert in the graph.
	// For non-local replaces, it is the replacement coordinate.
	// For local replaces, it is the original require coordinate (no fetchable
	// version exists; the local path is recorded separately).
	// For no replace, it is the original require coordinate.
	effective domain2.ModuleCoordinate
	// replaced is true when a non-local replace rewrote the coordinate.
	replaced bool
	// localReplace is true when a local-path replace applies.
	localReplace bool
	// localPath is the local-path replacement target (set iff localReplace).
	localPath string
}

// applyReplace applies the target's replace directives to coord. Local-path
// replacements now produce a graph node rather than being silently dropped
// the caller checks o.localReplace to give them their own resolution
// source and to skip fetch.
func applyReplace(coord domain2.ModuleCoordinate, replaceMap map[replaceKey]domain3.Replacement) replaceOutcome {
	// Check version-specific replacement first (higher priority).
	if r, ok := replaceMap[replaceKey{coord.Path, coord.Version}]; ok {
		if r.IsLocal {
			return replaceOutcome{effective: coord, localReplace: true, localPath: r.LocalPath}
		}
		return replaceOutcome{effective: r.NewCoordinate, replaced: true}
	}
	// Check wildcard replacement (all versions of this path).
	if r, ok := replaceMap[replaceKey{coord.Path, ""}]; ok {
		if r.IsLocal {
			return replaceOutcome{effective: coord, localReplace: true, localPath: r.LocalPath}
		}
		return replaceOutcome{effective: r.NewCoordinate, replaced: true}
	}
	return replaceOutcome{effective: coord}
}

// isExcluded reports whether coord is covered by an exclude directive.
func isExcluded(coord domain2.ModuleCoordinate, excludeSet map[excludeKey]bool) bool {
	return excludeSet[excludeKey{coord.Path, coord.Version}]
}

// versionGT reports whether a is strictly greater than b under semver ordering.
func versionGT(a, b string) bool {
	return semver.Compare(a, b) > 0
}
