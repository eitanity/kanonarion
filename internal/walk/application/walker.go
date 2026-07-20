package application

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	domain2 "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

const defaultWorkerCount = 16

// forceCapable is implemented by ModuleFetcher adapters that can produce a
// "force mode" clone bypassing the persistent fact-store cache. The walker
// type-asserts against this interface when WalkRequest.Force is true so a
// forced walk genuinely re-downloads every module. Adapters that
// don't implement it cause --force to log a warning and behave as a no-op
// rather than silently mis-reporting cached fetches as fresh.
type forceCapable interface {
	WithForce(bool) walkports.ModuleFetcher
}

// Walker orchestrates dependency graph resolution and concurrent module fetching.
// It resolves the full transitive closure via GraphResolver, then fetches every
// module in the graph concurrently subject to a worker-pool bound.
//
// Cache coherence: the same ModuleFetcher instance should be passed to both
// NewGraphResolver and NewWalker so that modules fetched during graph resolution
// are cache hits in the subsequent concurrent fetch phase.
//
// Walker is safe for concurrent use once constructed.
type Walker struct {
	resolver     *GraphResolver
	fetcher      walkports.ModuleFetcher
	localFetcher walkports.LocalModuleFetcher // nil = skip local-replace analysis
	clock        fetchports.Clock
	stopwatch    fetchports.Stopwatch
	workerCount  int
	logger       *slog.Logger
}

// NewWalker constructs a Walker. workerCount defaults to defaultWorkerCount if
// ≤0. localFetcher may be nil; when nil, local-replace nodes are always skipped
// regardless of WalkRequest.LocalReplaceBase.
func NewWalker(
	resolver *GraphResolver,
	fetcher walkports.ModuleFetcher,
	localFetcher walkports.LocalModuleFetcher,
	clock fetchports.Clock,
	stopwatch fetchports.Stopwatch,
	workerCount int,
	logger *slog.Logger,
) *Walker {
	if workerCount <= 0 {
		workerCount = defaultWorkerCount
	}
	return &Walker{
		resolver:     resolver,
		fetcher:      fetcher,
		localFetcher: localFetcher,
		clock:        clock,
		stopwatch:    stopwatch,
		workerCount:  workerCount,
		logger:       logger,
	}
}

// WalkRequest is the input to Walk.
type WalkRequest struct {
	Target      coordinate.ModuleCoordinate
	Force       bool // re-fetch every module, ignoring the cache
	WorkerCount int  // 0 = use the Walker's default
	// SkipVCSVerify skips git cross-verification for every module in the walk.
	// sumdb verification still runs. Useful when GitHub rate limits block git.
	SkipVCSVerify bool
	// Policy controls depth and filtering for this walk. nil uses DefaultDepthPolicy.
	Policy     *domain2.DepthPolicy
	PolicyHash string // content hash of the policy source; empty when using defaults
	// Scope tags the resulting WalkRecord. Defaults to WalkScopeCode when empty.
	Scope domain2.WalkScope
	// ScopeModules restricts a project walk's build-list graph to a dependency
	// scope: the module paths to retain (the caller's toolchain-derived set for
	// the code or tool scope), alongside the main anchor. nil keeps the whole
	// build list (the complete scope). Only honoured in ProjectMode.
	ScopeModules []string
	// Depth controls graph resolution. Defaults to WalkDepthFull when empty.
	// WalkDepthShallow fetches only the target, lists its go.mod require entries
	// as unresolved nodes, and marks the resulting graph partial.
	Depth domain2.WalkDepth
	// LocalReplaceBase is the directory used to resolve local-path replace
	// targets found in the graph (e.g. "../sibling"). When non-empty and the
	// Walker has a LocalModuleFetcher wired, local-replace nodes are ingested
	// from disk instead of being marked Skipped. Paths in GraphNode.LocalPath
	// are joined with this base to form the absolute filesystem location.
	LocalReplaceBase string
	// ProjectMode roots the walk at the local main module rather than fetching
	// Target. Target carries the main module path at coordinate.LocalVersion,
	// and MainModuleGoMod holds the working tree's go.mod. The resulting record
	// has a single root whose closure is the union of all require directives, so
	// downstream consumers (notably SBOM metadata.component) describe the project
	// itself rather than one arbitrary dependency.
	ProjectMode bool
	// MainModuleGoMod is the raw go.mod content of the local main module. Read
	// only when ProjectMode is true.
	MainModuleGoMod []byte
	// AnalyseLocalRoot ingests the project root's own working tree so the
	// extraction stages analyse the project's OWN packages, not just its
	// dependencies. The root graph node is promoted to
	// ResolutionLocalAnalysed with a fresh FactRecord built from ProjectDir.
	// Only honoured in ProjectMode. Freshness: the working tree is re-read on
	// every walk — a local version does not pin content, so no cached record
	// is ever served for the root.
	AnalyseLocalRoot bool
	// ProjectDir is the absolute path of the local working tree rooting a
	// project walk (the directory holding go.mod/go.sum). It is the directory the
	// Go toolchain is invoked in to derive the authoritative build list, and is
	// also where AnalyseLocalRoot reads the project's own packages. Set whenever
	// ProjectMode is true.
	ProjectDir string
	// StdlibFromGoMod pins the synthetic standard-library node to the project
	// go.mod's `toolchain`/`go` directive instead of the effective build toolchain
	// (`go env GOVERSION`, the default). Only honoured in ProjectMode.
	StdlibFromGoMod bool
	// Progress receives fetch-phase progress so a long, otherwise silent walk can
	// show proof of life. nil disables reporting. The reporter is invoked once per
	// distinct module fetched during resolution.
	Progress walkports.ProgressReporter
}

// Walk resolves the dependency graph for req.Target and fetches every module in
// the closure concurrently.
//
// Walk only returns a non-nil error when the provided context is already
// cancelled on entry. All per-module failures are captured as NodeResults
// within the returned WalkOutcome; they do not surface as an error here.
func (w *Walker) Walk(ctx context.Context, req WalkRequest) (domain2.WalkOutcome, error) {
	if err := ctx.Err(); err != nil {
		return domain2.WalkOutcome{}, fmt.Errorf("walk: %w", err)
	}

	workers := w.workerCount
	if req.WorkerCount > 0 {
		workers = req.WorkerCount
	}

	startedAt := w.clock.Now()
	outcome := domain2.WalkOutcome{
		Target: req.Target,
		// Seed the graph target so a walk that fails before the graph is
		// resolved (e.g. target fetch 404) still round-trips: the read path
		// requires a non-empty Graph.Target. Overwritten wholesale by the
		// resolver's graph on the success paths.
		Graph:          domain2.Graph{Target: req.Target},
		PerNodeResults: make(map[coordinate.ModuleCoordinate]domain2.NodeResult),
		StartedAt:      startedAt,
	}

	log := w.logger.With(
		slog.String("walk.target", req.Target.String()),
		slog.Bool("force", req.Force),
		slog.Int("workers", workers),
	)
	log.InfoContext(ctx, "walker.start")

	// Resolve the per-walk fetcher. When req.Force is set, swap to a force-mode
	// clone if the underlying adapter supports it — otherwise the
	// fact-store cache short-circuits the fetch and --force is a no-op.
	innerFetcher := w.fetcher
	if req.Force {
		if ff, ok := innerFetcher.(forceCapable); ok {
			innerFetcher = ff.WithForce(true)
		} else {
			log.WarnContext(ctx, "walker.force.unsupported",
				slog.String("reason", "underlying fetcher does not implement WithForce; --force has no effect"),
			)
		}
	}

	// All fetches in this walk go through a recorder so per-node FromCache and
	// duration_ms reflect the *first* fetch of each coordinate during the walk,
	// not a redundant post-resolution re-fetch. Before the walker
	// re-fetched every transitive after resolution to observe FromCache; by then
	// the resolver had already populated the cache, so transitives were always
	// reported as cache hits with duration 0. The recorder captures the
	// resolver's first call instead.
	recorder := newRecordingFetcher(innerFetcher, w.stopwatch, log, req.Target, req.Progress)
	// Bind the per-walk worker count so the resolver fetches each BFS level (or
	// build list) concurrently under that bound; --workers 1 reproduces
	// sequential fetching.
	resolver := w.resolver.WithFetcher(recorder).WithWorkers(workers)

	// Shallow walk: fetch only the target and build a flat graph from its go.mod.
	if req.Depth == domain2.WalkDepthShallow {
		targetResult := w.fetchOne(ctx, recorder, req.Target, req.Force, log)
		outcome.PerNodeResults[req.Target] = targetResult
		if targetResult.Status != domain2.NodeSucceeded {
			outcome.OverallStatus = domain2.WalkFailed
		} else {
			graph, err := resolver.ResolveShallow(ctx, req.Target)
			if err != nil {
				outcome.OverallStatus = domain2.WalkFailed
			} else {
				outcome.Graph = graph
				outcome.OverallStatus = domain2.WalkSucceeded
			}
		}
		outcome.CompletedAt = w.clock.Now()
		log.InfoContext(ctx, "walker.end",
			slog.String("status", outcome.OverallStatus.String()),
			slog.Int("nodes", len(outcome.Graph.Nodes)),
		)
		return outcome, nil
	}

	// Resolve the dependency graph. The resolver shares the recording fetcher
	// with the walker, so every fetch is observed exactly once with accurate
	// FromCache and duration_ms.
	policy := domain2.DefaultDepthPolicy()
	if req.Policy != nil {
		policy = *req.Policy
	}

	var graph domain2.Graph
	if req.ProjectMode {
		// Project mode: root at the local main module. Its go.mod is read from
		// the working tree, not fetched, so the closure is the union of all
		// require directives rooted at the project itself.
		g, perr := resolver.ResolveProject(ctx, req.Target, req.MainModuleGoMod, req.ProjectDir, policy.FetchStage(), req.ScopeModules, req.StdlibFromGoMod, req.Force)
		if perr != nil {
			// The local go.mod could not be parsed — terminal, like a target
			// fetch failure.
			outcome.OverallStatus = domain2.WalkFailed
			outcome.CompletedAt = w.clock.Now()
			log.InfoContext(ctx, "walker.end",
				slog.String("status", outcome.OverallStatus.String()),
				slog.String("error", perr.Error()),
			)
			return outcome, nil
		}
		graph = g
		// The main module is local and unfetched; synthesise a succeeded node
		// result so it anchors the graph (and satisfies the target-succeeded
		// invariant) without a fetch record.
		outcome.PerNodeResults[req.Target] = domain2.NodeResult{
			Coordinate: req.Target,
			Status:     domain2.NodeSucceeded,
		}
	} else {
		// Step 1: fetch the target. Failure here is terminal — without the
		// target's go.mod we cannot resolve the graph.
		targetResult := w.fetchOne(ctx, recorder, req.Target, req.Force, log)
		outcome.PerNodeResults[req.Target] = targetResult
		if targetResult.Status != domain2.NodeSucceeded {
			outcome.OverallStatus = domain2.WalkFailed
			outcome.CompletedAt = w.clock.Now()
			log.InfoContext(ctx, "walker.end",
				slog.String("status", outcome.OverallStatus.String()),
				slog.Int("nodes", len(outcome.PerNodeResults)),
			)
			return outcome, nil
		}

		// Step 2: resolve the full transitive graph.
		g, rerr := resolver.Resolve(ctx, req.Target, policy.FetchStage())
		if rerr != nil {
			// Resolve returns an error only on context cancellation or target
			// failure. Target was already fetched successfully above, so this
			// is cancellation.
			outcome.OverallStatus = domain2.WalkCancelled
			outcome.Graph = g
			outcome.CompletedAt = w.clock.Now()
			log.InfoContext(ctx, "walker.end",
				slog.String("status", outcome.OverallStatus.String()),
				slog.String("error", rerr.Error()),
			)
			return outcome, nil
		}
		graph = g
	}
	outcome.Graph = graph
	log.InfoContext(ctx, "walker.resolve.complete",
		slog.Int("nodes", len(graph.Nodes)),
		slog.Bool("partial", graph.Partial),
	)

	// Step 3: classify graph nodes and populate PerNodeResults from the
	// recorder. The resolver has already fetched every successful node by this
	// point; the walker no longer re-fetches — it just reads back what
	// the recorder captured.
	toFetchLocal := make([]domain2.GraphNode, 0)
	for _, node := range graph.Nodes {
		if node.Coordinate == req.Target {
			continue
		}
		switch node.ResolutionSource {
		case domain2.ResolutionStdlib:
			// The synthetic standard-library node has no fetchable artefact — it
			// ships with the toolchain. Record it as succeeded (no fetch record) so
			// it anchors the graph for the SBOM and vuln-scan without a spurious
			// fetch-failure that would partial-ise the walk.
			outcome.PerNodeResults[node.Coordinate] = domain2.NodeResult{
				Coordinate: node.Coordinate,
				Status:     domain2.NodeSucceeded,
			}
		case domain2.ResolutionFetchFailed, domain2.ResolutionParseFailed:
			// Preserve panic-vs-regular-failure distinction: a transitive that
			// panicked during fetch is recorded by the recorder with panicked=true
			// (the resolver saw it as a fetch error and marked the graph node as
			// ResolutionFetchFailed). Upgrade those to NodeInternalPanic so the
			// stored record reflects what actually happened.
			out, ok := recorder.outcomeFor(node.Coordinate)
			if ok && out.panicked {
				outcome.PerNodeResults[node.Coordinate] = domain2.NodeResult{
					Coordinate: node.Coordinate,
					Status:     domain2.NodeInternalPanic,
					DurationMs: out.durationMs,
					Error: &domain2.StoredError{
						Type:    "internal_panic",
						Message: out.err.Error(),
					},
				}
				continue
			}
			result := domain2.NodeResult{
				Coordinate: node.Coordinate,
				Status:     domain2.NodeFetchFailed,
				Error: &domain2.StoredError{
					Type:    string(node.ResolutionSource),
					Message: node.ErrorDetail,
				},
			}
			if ok {
				result.DurationMs = out.durationMs
			}
			outcome.PerNodeResults[node.Coordinate] = result
		case domain2.ResolutionLocalReplace:
			if w.localFetcher != nil && req.LocalReplaceBase != "" {
				// local analysis enabled — queue for local ingestion.
				toFetchLocal = append(toFetchLocal, node)
			} else {
				// local-path replacements have no remote artefact. Record
				// a deterministic NodeLocalReplace result so downstream stages
				// (extract, vuln-scan) can recognise and skip-with-reason instead
				// of treating the missing fetch as an error.
				outcome.PerNodeResults[node.Coordinate] = domain2.NodeResult{
					Coordinate: node.Coordinate,
					Status:     domain2.NodeLocalReplace,
					Error: &domain2.StoredError{
						Type:    string(domain2.ResolutionLocalReplace),
						Message: "local replace at " + node.LocalPath,
					},
				}
			}
		default:
			// Successful resolver fetch: read the recorded outcome and build
			// the NodeResult. FromCache and duration_ms reflect the first (and
			// only) call to the underlying fetcher, fixing.
			out, ok := recorder.outcomeFor(node.Coordinate)
			if !ok {
				// Defensive: the resolver should have fetched every graph node
				// with a non-failure resolution source. If not, record a
				// degenerate result rather than silently dropping the node.
				outcome.PerNodeResults[node.Coordinate] = domain2.NodeResult{
					Coordinate: node.Coordinate,
					Status:     domain2.NodeFetchFailed,
					Error: &domain2.StoredError{
						Type:    "fetch_failed",
						Message: "resolver did not fetch this coordinate",
					},
				}
				continue
			}
			rec := out.record
			outcome.PerNodeResults[node.Coordinate] = domain2.NodeResult{
				Coordinate:  node.Coordinate,
				Status:      domain2.NodeSucceeded,
				FetchRecord: &rec,
				FromCache:   out.fromCache,
				DurationMs:  out.durationMs,
			}
		}
	}

	// Step 4: ingest local-replace nodes from the filesystem.
	// Sequential: local I/O is fast and there are typically few local replaces.
	for _, node := range toFetchLocal {
		absPath := filepath.Join(req.LocalReplaceBase, node.LocalPath)
		fr, ferr := w.localFetcher.EnsureFetchedFromPath(ctx, node.Coordinate, absPath)
		if ferr != nil {
			log.WarnContext(ctx, "walker.local_fetch.failed",
				slog.String("module.path", node.Coordinate.Path),
				slog.String("local_path", absPath),
				slog.String("error", ferr.Error()),
			)
			outcome.PerNodeResults[node.Coordinate] = domain2.NodeResult{
				Coordinate: node.Coordinate,
				Status:     domain2.NodeLocalReplace,
				Error: &domain2.StoredError{
					Type:    "local_fetch_failed",
					Message: ferr.Error(),
				},
			}
			continue
		}
		rec := fr.Record
		outcome.PerNodeResults[node.Coordinate] = domain2.NodeResult{
			Coordinate:  node.Coordinate,
			Status:      domain2.NodeSucceeded,
			FetchRecord: &rec,
			FromCache:   fr.FromCache,
		}
		// Promote the graph node to ResolutionLocalAnalysed so extract and
		// vuln-scan treat it as a normal (analysable) module.
		for i := range outcome.Graph.Nodes {
			if outcome.Graph.Nodes[i].Coordinate == node.Coordinate {
				outcome.Graph.Nodes[i].ResolutionSource = domain2.ResolutionLocalAnalysed
				break
			}
		}
		log.InfoContext(ctx, "walker.local_fetch.ok",
			slog.String("module.path", node.Coordinate.Path),
			slog.String("local_path", absPath),
			slog.Bool("from_cache", fr.FromCache),
		)
	}

	// Step 5: ingest the project root's own working tree when requested.
	// Mirrors the local-replace ingest above: the root gets a real FactRecord
	// and is promoted to ResolutionLocalAnalysed so extraction treats it as a
	// normal analysable module instead of skipping it. The ingest is
	// always fresh — the localFetcher never serves a cached record for the
	// local version, so an edited tree is re-read on every run.
	if req.ProjectMode && req.AnalyseLocalRoot {
		w.ingestProjectRoot(ctx, req, &outcome, log)
	}

	// Step 6: aggregate overall status.
	outcome.CompletedAt = w.clock.Now()
	outcome.OverallStatus = aggregateStatus(ctx, outcome.PerNodeResults, req.Target)

	log.InfoContext(ctx, "walker.end",
		slog.String("status", outcome.OverallStatus.String()),
		slog.Int("nodes", len(outcome.PerNodeResults)),
	)
	return outcome, nil
}

// ingestProjectRoot ingests the project-walk root's working tree as a
// FactRecord and promotes the root graph node to ResolutionLocalAnalysed.
// On failure the root's synthesised success is replaced with a fetch-failed
// result, failing the walk: the caller explicitly asked for root analysis, so
// silently keeping the skip-with-reason root would misreport what ran.
func (w *Walker) ingestProjectRoot(
	ctx context.Context,
	req WalkRequest,
	outcome *domain2.WalkOutcome,
	log *slog.Logger,
) {
	fail := func(msg string) {
		log.WarnContext(ctx, "walker.local_root_ingest.failed",
			slog.String("module.path", req.Target.Path),
			slog.String("project_dir", req.ProjectDir),
			slog.String("error", msg),
		)
		outcome.PerNodeResults[req.Target] = domain2.NodeResult{
			Coordinate: req.Target,
			Status:     domain2.NodeFetchFailed,
			Error: &domain2.StoredError{
				Type:    "local_root_ingest_failed",
				Message: msg,
			},
		}
	}
	if w.localFetcher == nil {
		fail("local-root analysis requested but no local module fetcher is configured")
		return
	}
	if req.ProjectDir == "" {
		fail("local-root analysis requested but the project directory is unknown")
		return
	}

	fr, err := w.localFetcher.EnsureFetchedFromPath(ctx, req.Target, req.ProjectDir)
	if err != nil {
		fail(err.Error())
		return
	}
	rec := fr.Record
	outcome.PerNodeResults[req.Target] = domain2.NodeResult{
		Coordinate:  req.Target,
		Status:      domain2.NodeSucceeded,
		FetchRecord: &rec,
		FromCache:   fr.FromCache,
	}
	for i := range outcome.Graph.Nodes {
		if outcome.Graph.Nodes[i].Coordinate == req.Target {
			outcome.Graph.Nodes[i].ResolutionSource = domain2.ResolutionLocalAnalysed
			outcome.Graph.Nodes[i].LocalPath = req.ProjectDir
			break
		}
	}
	log.InfoContext(ctx, "walker.local_root_ingest.ok",
		slog.String("module.path", req.Target.Path),
		slog.String("project_dir", req.ProjectDir),
	)
}

// fetchOne fetches a single module through the recording fetcher and builds a
// NodeResult from the recorded outcome. Logging and panic recovery happen
// inside the recorder, so this function is a thin adapter from
// fetchOutcome → NodeResult.
//
// force is honoured by the underlying FetchModuleUseCase wired into the
// recorder's inner fetcher (constructed with Force=true when needed); the
// walker does not reach into fetch internals.
func (w *Walker) fetchOne(
	ctx context.Context,
	rec *recordingFetcher,
	c coordinate.ModuleCoordinate,
	force bool,
	_ *slog.Logger,
) domain2.NodeResult {
	_ = force
	result := domain2.NodeResult{Coordinate: c}
	_, err := rec.EnsureFetched(ctx, c)
	out, ok := rec.outcomeFor(c)
	if ok {
		result.DurationMs = out.durationMs
	}
	switch {
	case ok && out.panicked:
		result.Status = domain2.NodeInternalPanic
		result.Error = &domain2.StoredError{
			Type:    "internal_panic",
			Message: out.err.Error(),
		}
	case err != nil:
		result.Status = domain2.NodeFetchFailed
		result.Error = &domain2.StoredError{
			Type:    "fetch_failed",
			Message: err.Error(),
		}
	default:
		fact := out.record
		result.FetchRecord = &fact
		result.Status = domain2.NodeSucceeded
		result.FromCache = out.fromCache
	}
	return result
}

// aggregateStatus derives the WalkStatus from the per-node results map.
func aggregateStatus(
	ctx context.Context,
	results map[coordinate.ModuleCoordinate]domain2.NodeResult,
	target coordinate.ModuleCoordinate,
) domain2.WalkStatus {
	if ctx.Err() != nil {
		return domain2.WalkCancelled
	}
	tr, ok := results[target]
	if !ok || tr.Status != domain2.NodeSucceeded {
		return domain2.WalkFailed
	}
	for _, r := range results {
		switch r.Status {
		case domain2.NodeSucceeded, domain2.NodeLocalReplace:
			// NodeLocalReplace is intentional (the local replacement is what
			// compiles for the target); it does not partial-ise the walk.
		default:
			return domain2.WalkPartial
		}
	}
	return domain2.WalkSucceeded
}
