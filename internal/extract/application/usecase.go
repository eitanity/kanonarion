package application

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/oklog/ulid/v2"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/extract/domain"
	"github.com/eitanity/kanonarion/internal/extract/ports"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

type ExtractUseCase struct {
	runs             ports.ExtractionStore
	walks            walkports.WalkStore
	extractor        ports.Extractor
	stages           ports.StageRegistry
	clock            fetchports.Clock
	stopwatch        fetchports.Stopwatch
	hasher           domain.ExtractionRunHasher
	pipelineVersions map[string]string
	logger           *slog.Logger
	workers          int
}

type Config struct {
	Runs      ports.ExtractionStore
	Walks     walkports.WalkStore
	Extractor ports.Extractor
	// Stages controls which stage names are valid and their execution order.
	// Use adapters/stages/local.New for the default built-in set.
	Stages           ports.StageRegistry
	Clock            fetchports.Clock
	Stopwatch        fetchports.Stopwatch
	PipelineVersions map[string]string
	Logger           *slog.Logger
	// Workers controls the size of the module extraction pool. Zero means runtime.NumCPU.
	Workers int
}

func NewExtractUseCase(cfg Config) *ExtractUseCase {
	return &ExtractUseCase{
		runs:             cfg.Runs,
		walks:            cfg.Walks,
		extractor:        cfg.Extractor,
		stages:           cfg.Stages,
		clock:            cfg.Clock,
		stopwatch:        cfg.Stopwatch,
		pipelineVersions: cfg.PipelineVersions,
		logger:           cfg.Logger,
		workers:          cfg.Workers,
	}
}

type ExtractRequest struct {
	WalkID string
	Stages []string
	Force  bool
	// Workers overrides the use case's default concurrency when non-zero.
	Workers int
	// Progress receives a call after each module completes all requested
	// stages. Nil disables reporting.
	Progress ports.ProgressReporter
}

func resolveWorkers(reqWorkers, ucWorkers, nodeCount int) int {
	w := reqWorkers
	if w <= 0 {
		w = ucWorkers
	}
	if w <= 0 {
		w = runtime.NumCPU()
	}
	if w > nodeCount {
		w = nodeCount
	}
	return w
}

// unfetchableReason reports whether a graph node has no fetchable module
// artefact and, if so, the human-readable reason recorded on each skipped
// stage. Such nodes are skipped-with-reason rather than failed: they were never
// proxy-fetched, so a fetch-record lookup can only ever miss, and reporting that
// miss as a failure would mislabel "nothing to analyse here" as an error.
func unfetchableReason(node walkdomain.GraphNode) (string, bool) {
	switch node.ResolutionSource {
	case walkdomain.ResolutionLocalReplace:
		return "local replace at " + node.LocalPath, true
	case walkdomain.ResolutionLocalMainModule:
		return "local main module (project-walk root); has no fetched artefact — analyse its own source with the local call-graph command", true
	case walkdomain.ResolutionStdlib:
		return "Go standard library (toolchain-provided); has no fetched module artefact — vulnerabilities are resolved from advisory metadata by coordinate", true
	default:
		return "", false
	}
}

func (uc *ExtractUseCase) Execute(ctx context.Context, req ExtractRequest) (domain.ExtractionRun, error) {
	if len(req.Stages) == 0 {
		return domain.ExtractionRun{}, fmt.Errorf("no extraction stages requested")
	}

	walk, err := uc.walks.GetWalk(ctx, req.WalkID)
	if err != nil {
		return domain.ExtractionRun{}, fmt.Errorf("getting walk %s: %w", req.WalkID, err)
	}

	if len(walk.Graph.Nodes) == 0 {
		return domain.ExtractionRun{}, fmt.Errorf("walk %s has no modules", req.WalkID)
	}

	runID := ulid.Make().String()
	run := domain.ExtractionRun{
		SchemaVersion:    domain.ExtractionRunSchemaVersion,
		Ecosystem:        fetchdomain.EcosystemGo,
		ID:               runID,
		WalkID:           req.WalkID,
		RequestedStages:  req.Stages,
		PerModuleResults: make(map[coordinate.ModuleCoordinate]domain.ModuleExtractionResult),
		StartedAt:        uc.clock.Now().UTC(),
		PipelineVersions: uc.pipelineVersions,
		OverallStatus:    domain.ExtractionRunSucceeded,
	}

	requestedStagesSet := make(map[string]bool)
	for _, s := range req.Stages {
		if !uc.stages.Has(s) {
			return domain.ExtractionRun{}, fmt.Errorf("invalid extraction stage: %s", s)
		}
		requestedStagesSet[s] = true
	}

	var runStages []string
	for _, s := range uc.stages.Stages() {
		if requestedStagesSet[s] {
			runStages = append(runStages, s)
		}
	}

	nodes := walk.Graph.Nodes
	workers := resolveWorkers(req.Workers, uc.workers, len(nodes))

	type job struct {
		idx  int
		node walkdomain.GraphNode
	}

	type outcome struct {
		coord  coordinate.ModuleCoordinate
		result domain.ModuleExtractionResult
		set    bool
	}

	jobs := make(chan job, len(nodes))
	for i, node := range nodes {
		jobs <- job{idx: i, node: node}
	}
	close(jobs)

	outcomes := make([]outcome, len(nodes))
	var partial, cancelled atomic.Bool
	var completed atomic.Int64

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					cancelled.Store(true)
					continue
				}

				modRes := domain.ModuleExtractionResult{
					Coordinate: j.node.Coordinate,
					Stages:     make(map[string]domain.StageResult),
				}

				// A node with no fetchable artefact cannot be extracted from a
				// stored module zip: a require redirected to a local filesystem
				// path that was not locally analysed, or the project-walk root
				// (the local main module, which is the working tree itself and is
				// never proxy-fetched). Emit a deterministic skip-with-reason for
				// every requested stage so the run is succeeded, not failed, and
				// the absence is auditable rather than presented as an error.
				// Nodes promoted to ResolutionLocalAnalysed have a real FactRecord
				// and proceed normally through the extraction pipeline.
				if reason, unfetchable := unfetchableReason(j.node); unfetchable {
					for _, stage := range runStages {
						modRes.Stages[stage] = domain.StageResult{
							Status: domain.StageSkipped,
							Error:  reason,
						}
					}
					outcomes[j.idx] = outcome{coord: j.node.Coordinate, result: modRes, set: true}
					if req.Progress != nil {
						req.Progress.Advance(int(completed.Add(1)))
					}
					continue
				}

				for _, stage := range runStages {
					if ctx.Err() != nil {
						cancelled.Store(true)
						break
					}
					if stage == "callgraph" && !requestedStagesSet["interface"] {
						_ = requestedStagesSet
					}

					lap := uc.stopwatch.Start()
					res, extractErr := uc.extractor.Extract(ctx, j.node.Coordinate, stage, req.Force)
					duration := lap.Elapsed().Milliseconds()

					stageRes := domain.StageResult{
						Status:     res.Status,
						RecordID:   res.RecordID,
						Error:      res.Error,
						DurationMs: duration,
					}
					if extractErr != nil && stageRes.Error == "" {
						stageRes.Error = extractErr.Error()
						stageRes.Status = domain.StageFailed
					}
					modRes.Stages[stage] = stageRes

					if stageRes.Status == domain.StageFailed {
						partial.Store(true)
					}
				}

				outcomes[j.idx] = outcome{coord: j.node.Coordinate, result: modRes, set: true}
				if req.Progress != nil {
					req.Progress.Advance(int(completed.Add(1)))
				}
			}
		}()
	}

	wg.Wait()

	for _, o := range outcomes {
		if o.set {
			run.PerModuleResults[o.coord] = o.result
		}
	}

	if partial.Load() {
		run.OverallStatus = domain.ExtractionRunPartial
	}
	if cancelled.Load() || ctx.Err() != nil {
		run.OverallStatus = domain.ExtractionRunCancelled
	}

	run.CompletedAt = uc.clock.Now().UTC()

	run, err = uc.hasher.SetContentHash(run)
	if err != nil {
		return domain.ExtractionRun{}, fmt.Errorf("hashing run: %w", err)
	}

	if err := uc.runs.PutExtractionRun(ctx, run); err != nil {
		return domain.ExtractionRun{}, fmt.Errorf("persisting run: %w", err)
	}

	return run, nil
}
