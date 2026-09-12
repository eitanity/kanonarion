package application

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

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
	audit            ports.AuditSink // optional; nil disables audit emission
	// checkpointEvery is how often a running run re-states itself in the store.
	// Zero means DefaultCheckpointInterval; a negative value disables
	// checkpointing, which only a test that owns the clock wants.
	checkpointEvery time.Duration
}

// DefaultCheckpointInterval is how often a run in progress writes what it has
// completed so far.
//
// It is a compromise between two costs, and the expensive one is not the write.
// Every checkpoint is a single upsert of a few hundred kilobytes onto the same
// SQLite writer the call-graph subprocesses are queueing on, so a run of several
// minutes pays a dozen of them against the walk's own hundreds. Checkpointing
// per module instead would put one write per module on that writer to save at
// most one module's worth of detail on a run nothing ends.
const DefaultCheckpointInterval = 30 * time.Second

// WithCheckpointInterval overrides how often a run in progress re-states itself.
// It exists for tests, which cannot wait thirty seconds to observe one.
func (uc *ExtractUseCase) WithCheckpointInterval(d time.Duration) *ExtractUseCase {
	uc.checkpointEvery = d
	return uc
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

// WithAudit wires an audit sink so a run appends one extraction_run_completed
// event per persisted run record. It is optional — a nil sink (the default)
// disables emission — and returns the receiver for chaining, mirroring the
// stages' optional-dependency builders.
func (uc *ExtractUseCase) WithAudit(sink ports.AuditSink) *ExtractUseCase {
	uc.audit = sink
	return uc
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

// outcome is one worker's slot: what a module came to, and whether a worker
// reached it at all. The slice is indexed by the module's position in the walk,
// so two runs of one walk fill it in the same order however the pool schedules.
type outcome struct {
	coord  coordinate.ModuleCoordinate
	result domain.ModuleExtractionResult
	set    bool
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

	jobs := make(chan job, len(nodes))
	for i, node := range nodes {
		jobs <- job{idx: i, node: node}
	}
	close(jobs)

	outcomes := make([]outcome, len(nodes))
	// outMu guards outcomes against the checkpoint reader. A worker writes its
	// slot once, so the lock is uncontended in the normal case; without it the
	// checkpoint would race every worker in the pool.
	var outMu sync.Mutex
	var partial, cancelled atomic.Bool
	var completed atomic.Int64

	// The run is in the store before the first module is touched, and again
	// every checkpoint interval. Persisting only at the end meant the failure
	// with the worst consequence — the operating system ending the process —
	// was the only one that recorded nothing about itself, while a run that
	// merely finished badly recorded `partial` correctly.
	stopCheckpoints := uc.checkpointRun(ctx, run, outcomes, &outMu)
	defer stopCheckpoints()

	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
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
					outMu.Lock()
					outcomes[j.idx] = outcome{coord: j.node.Coordinate, result: modRes, set: true}
					outMu.Unlock()
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
					lap := uc.stopwatch.Start()
					res, extractErr := uc.extractor.Extract(ctx, j.node.Coordinate, stage, req.Force, req.WalkID)
					duration := lap.Elapsed().Milliseconds()

					stageRes := domain.StageResult{
						Status:     res.Status,
						RecordID:   res.RecordID,
						Error:      res.Error,
						Cause:      res.Cause,
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

				outMu.Lock()
				outcomes[j.idx] = outcome{coord: j.node.Coordinate, result: modRes, set: true}
				outMu.Unlock()
				if req.Progress != nil {
					req.Progress.Advance(int(completed.Add(1)))
				}
			}
		})
	}

	wg.Wait()
	stopCheckpoints()

	outMu.Lock()
	run.PerModuleResults = collectResults(outcomes)
	outMu.Unlock()

	if partial.Load() {
		run.OverallStatus = domain.ExtractionRunPartial
	}
	if cancelled.Load() || ctx.Err() != nil {
		run.OverallStatus = domain.ExtractionRunCancelled
	}

	run.CompletedAt = uc.clock.Now().UTC()

	return uc.sealAndPersist(ctx, run)
}

// collectResults turns the workers' slots into the run's per-module map. Only
// slots a worker actually filled are included: an unset slot names a module the
// run never reached, and inventing an empty result for it would state that
// every stage was skipped when nothing looked.
func collectResults(outcomes []outcome) map[coordinate.ModuleCoordinate]domain.ModuleExtractionResult {
	out := make(map[coordinate.ModuleCoordinate]domain.ModuleExtractionResult, len(outcomes))
	for _, o := range outcomes {
		if o.set {
			out[o.coord] = o.result
		}
	}
	return out
}

// checkpointRun writes the run as it stands, now and at every interval until
// the returned stop is called. Stop is idempotent and waits for an in-flight
// checkpoint, so the caller can stop it and then seal without racing its own
// record.
//
// A failed checkpoint is logged and never fails the run. The run's work is the
// extraction; a store that would not take an interim statement of it is a
// reason to say so, not a reason to throw the extraction away.
func (uc *ExtractUseCase) checkpointRun(ctx context.Context, run domain.ExtractionRun, outcomes []outcome, mu *sync.Mutex) func() {
	every := uc.checkpointEvery
	if every == 0 {
		every = DefaultCheckpointInterval
	}

	// A checkpoint competes with the run's own call-graph subprocesses for the
	// store's single writer, so one that would re-state what the last one said
	// is pure contention. -1 rather than 0, so the opening record — which names
	// no module — is still written.
	lastWritten := -1

	write := func() {
		mu.Lock()
		results := collectResults(outcomes)
		mu.Unlock()
		if len(results) == lastWritten {
			return
		}

		snapshot := run
		snapshot.PerModuleResults = results
		// The two fields that would otherwise lie. A run still going has not
		// succeeded and has not completed, and a record saying either would be
		// read as a finished run that lost most of its modules.
		snapshot.OverallStatus = domain.ExtractionRunInProgress
		snapshot.CompletedAt = time.Time{}

		sealed, err := uc.hasher.SetContentHash(snapshot)
		if err == nil {
			err = uc.runs.PutExtractionRun(ctx, sealed)
		}
		if err == nil {
			// Advanced only on success, so a checkpoint the store refused is
			// attempted again at the next tick rather than skipped for saying
			// nothing new — it never said it.
			lastWritten = len(results)
		}
		if err != nil {
			uc.log().WarnContext(ctx, "extraction_run_checkpoint_failed",
				slog.String("extraction.run.id", run.ID),
				slog.String("extraction.walk.id", run.WalkID),
				slog.Int("modules_completed", len(results)),
				slog.String("error", err.Error()))
		}
	}

	write()

	if every < 0 {
		return func() {}
	}

	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				write()
			}
		}
	}()

	var once sync.Once
	return func() {
		once.Do(func() { close(done) })
		<-stopped
	}
}

// log returns a usable logger, so a use case constructed without one still runs.
func (uc *ExtractUseCase) log() *slog.Logger {
	if uc.logger == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return uc.logger
}

// sealAndPersist hashes the completed run, writes it, and records it in the
// assurance log. It is a separate step from the orchestration above because the
// three are one operation: a run is not finished until it is sealed, stored and
// stated.
func (uc *ExtractUseCase) sealAndPersist(ctx context.Context, run domain.ExtractionRun) (domain.ExtractionRun, error) {
	run, err := uc.hasher.SetContentHash(run)
	if err != nil {
		return domain.ExtractionRun{}, fmt.Errorf("hashing run: %w", err)
	}

	if err := uc.runs.PutExtractionRun(ctx, run); err != nil {
		return domain.ExtractionRun{}, fmt.Errorf("persisting run: %w", err)
	}

	// Assurance log: one extraction_run_completed event per persisted run says
	// which campaign asked for the per-stage generations around it and what it
	// concluded. The run is written first, so a failed append reports that the
	// write is unlogged — it never undoes it.
	if err := uc.emitRunCompleted(run); err != nil {
		return domain.ExtractionRun{}, err
	}

	return run, nil
}
