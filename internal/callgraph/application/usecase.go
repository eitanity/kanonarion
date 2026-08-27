package application

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"

	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

// PipelineVersion identifies this release of the call graph extraction
// pipeline. Bump whenever extraction logic changes. It is the sole key for
// record reuse, so a record produced by older logic is only re-derived when this
// changes.
//
// Bumped to "0.2.0" when package loading began disabling Go workspace mode. A
// module shipping a go.work in its published zip previously put the loader into
// workspace mode, which then failed on sibling modules absent from the zip, and
// the module was stored as a LoadFailed record with an empty graph. Those
// records are indistinguishable from a genuine load failure once written, so
// they must be re-derived rather than served.
//
// Bumped to "0.4.1" when four things about what gets loaded changed at once:
// package membership is decided by the module path the analysed tree DECLARES
// rather than by the coordinate it was published under, the load no longer
// requires the artefact to carry a go.sum covering its own module graph, a
// synthesised go.mod pins its language version at 1.17 so the module graph is
// pruned, and a load that resolves nothing now records which of those it was.
// Records written by the previous logic can be right or wrong and there is no
// way to tell from the record, so they are re-derived rather than served.
//
// Bumped to "0.5.0" when the analyser stopped taking its function set from the
// SSA library's own enumeration. That enumeration answers differently on
// successive calls to one unchanged program — it de-duplicates types by
// identity while walking them under two spellings, so an alias can consume the
// entry its named twin needed and a pointer-receiver method wrapper is then
// never materialised. A record written before this says the analysis found no
// call to a method it simply never enumerated, and two records of one artefact
// disagree with no cause recorded. Neither can be told apart from a real answer
// once written, so they are re-derived rather than served.
//
// NOT bumped when the exported-API rule stopped mis-reading a synthetic method
// wrapper on a package-main type as library API. A bump is owed when a change
// makes a stored record say something FALSE, and every record this version
// serves was decoded and counted before deciding: the false claim appears only
// in records written by older logic, which this version already declines to
// serve, and in none of the records written at this version. Those keep serving
// what they say, correctly. Re-extraction under the fixed rule is what corrects
// an older record, and a bump would have stranded every served graph to correct
// nothing.
const PipelineVersion = "0.5.0"

// ExtractCallGraphUseCase extracts the call graph of a module and persists a
// CallGraphRecord.
type ExtractCallGraphUseCase struct {
	facts           fetchports.FactStore
	blobs           fetchports.BlobStore
	store           ports.CallGraphStore
	analyser        ports.CallGraphAnalyser
	clock           fetchports.Clock
	stopwatch       fetchports.Stopwatch
	pipelineVersion string
	exclusions      []string // normalised callgraph.exclude policy
	logger          *slog.Logger
	hasher          domain2.CallGraphRecordHasher
	audit           ports.AuditSink // optional; nil disables audit emission
	// toolchain names the Go this run analyses under, asked at most once. It is
	// optional: without it a disagreeing ledger simply falls through to
	// measuring, which is what every run did before this resolution existed.
	toolchain     ports.ToolchainNamer
	toolchainOnce sync.Once
	toolchainName gotoolchain.Version
}

// Config holds all construction parameters for ExtractCallGraphUseCase.
type Config struct {
	Facts           fetchports.FactStore
	Blobs           fetchports.BlobStore
	Store           ports.CallGraphStore
	Analyser        ports.CallGraphAnalyser
	Clock           fetchports.Clock
	Stopwatch       fetchports.Stopwatch
	PipelineVersion string // defaults to PipelineVersion constant
	// Exclusions is the raw callgraph.exclude list (module paths skipped from
	// analysis). Normalised on construction.
	Exclusions []string
	Logger     *slog.Logger
	// Toolchain names the Go this run analyses under. Optional: a nil namer
	// leaves a disagreeing ledger to be re-measured, as it was before.
	Toolchain ports.ToolchainNamer
}

// NewExtractCallGraphUseCase constructs an ExtractCallGraphUseCase from a Config.
func NewExtractCallGraphUseCase(cfg Config) *ExtractCallGraphUseCase {
	if cfg.PipelineVersion == "" {
		cfg.PipelineVersion = PipelineVersion
	}
	return &ExtractCallGraphUseCase{
		facts:           cfg.Facts,
		blobs:           cfg.Blobs,
		store:           cfg.Store,
		analyser:        cfg.Analyser,
		clock:           cfg.Clock,
		stopwatch:       cfg.Stopwatch,
		pipelineVersion: cfg.PipelineVersion,
		exclusions:      domain2.NormaliseExclusions(cfg.Exclusions),
		logger:          cfg.Logger,
		toolchain:       cfg.Toolchain,
	}
}

// WithAudit wires an audit sink so extraction appends one callgraph_extracted
// event per persisted generation. It is optional — a nil sink (the default)
// disables emission — and returns the receiver for chaining, mirroring the
// other stages' optional-dependency builders.
func (uc *ExtractCallGraphUseCase) WithAudit(sink ports.AuditSink) *ExtractCallGraphUseCase {
	uc.audit = sink
	return uc
}

// ExtractRequest is the input to Execute.
type ExtractRequest struct {
	Coordinate coordinate.ModuleCoordinate
	// Force re-extracts even if a record for this pipeline version exists.
	Force bool
	// Inputs carries the requesting walk's resolved build list, which is what
	// lets a module published before Go modules be analysed against the versions
	// that build selected rather than against nothing. The zero value is a
	// request that offers none, and the analysis behaves exactly as it did before
	// the field existed.
	Inputs domain2.AnalysisInputs
}

// ExtractResult is the output of Execute.
type ExtractResult struct {
	Record    domain2.CallGraphRecord
	FromCache bool
	// Reused says the analysis ran and came back identical to a generation the
	// ledger already holds, so nothing was appended. It is distinct from
	// FromCache, which says the analysis did not run at all: a caller told the two
	// apart can see that a re-measurement happened and changed nothing.
	Reused bool
}

// Execute runs the call graph extraction pipeline for the given module.
//
// The module must have been fetched first. If not, ErrModuleNotFetched is
// returned.
//
// Extraction failures are recorded in the CallGraphRecord with an appropriate
// status — they do not make Execute return an error. Only infrastructure
// errors (store access, blob I/O) return errors.
func (uc *ExtractCallGraphUseCase) Execute(ctx context.Context, req ExtractRequest) (_ ExtractResult, retErr error) {
	log := uc.logger.With(
		slog.String("extraction.module.path", req.Coordinate.Path()),
		slog.String("extraction.module.version", req.Coordinate.Version()),
		slog.String("extraction.stage", "callgraph"),
		slog.String("pipeline_version", uc.pipelineVersion),
	)
	lap := uc.stopwatch.Start()
	log.InfoContext(ctx, "callgraph_extract_start")

	defer func() {
		log.InfoContext(ctx, "callgraph_extract_end",
			slog.Int64("extraction.duration_ms", lap.Elapsed().Milliseconds()),
		)
	}()

	factRecord, err := uc.requireFetchRecord(ctx, req.Coordinate)
	if err != nil {
		return ExtractResult{}, err
	}

	// Which bytes this extraction is about, resolved before any work is done so a
	// fetch record that names no artefact fails here rather than after a full
	// analysis. This stage always holds a fetch record, so a record it cannot name
	// an artefact for is a fault in the measurement, not a legacy row. The
	// working-tree stage in local.go has no fetch record at all and leaves both
	// fields empty; see ExtractLocalCallGraphUseCase.Execute.
	artefact, err := domain.ArtefactIdentityOf(factRecord)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("deriving artefact identity for %s: %w", req.Coordinate, err)
	}
	if artefact.IsZero() {
		return ExtractResult{}, fmt.Errorf("fetch record for %s names no artefact: %w", req.Coordinate, domain.ErrZeroIdentity)
	}

	// A local coordinate (the project-walk root) is never served from cache:
	// the working tree mutates between runs, so its records are recomputed
	// fresh every time.
	var existing domain2.CallGraphRecord
	var found bool
	if !req.Force && !req.Coordinate.IsLocal() {
		var cerr error
		existing, found, cerr = uc.store.GetCallGraphRecord(ctx, req.Coordinate, uc.pipelineVersion)
		if errors.Is(cerr, ports.ErrCallGraphConflict) {
			// The question this lookup is asking is narrower than the one it just
			// asked. It does not need to know which generation answers the
			// coordinate for every reader; it needs to know whether one was
			// measured under the toolchain this run analyses under. A generation
			// built by a Go this run is not using is not a reason to re-measure,
			// and treating it as one re-analyses the same module every run for ever.
			existing, found, cerr = uc.resolvedForThisToolchain(ctx, log, req.Coordinate, cerr)
		}
		// A composition refusal that even the toolchain could not resolve says no
		// single stored generation answers this coordinate. Refusing to SERVE that
		// is right; refusing to MEASURE a new answer is not, so it is a cache miss
		// here. Extraction appends, and the ladder decides which generation answers
		// afterwards.
		switch {
		case errors.Is(cerr, ports.ErrCallGraphConflict):
			log.InfoContext(ctx, "callgraph_cache_conflict_remeasuring",
				slog.String("conflict", cerr.Error()),
			)
		case cerr != nil && !errors.Is(cerr, ports.ErrCallGraphIntegrity):
			return ExtractResult{}, fmt.Errorf("checking callgraph store: %w", cerr)
		}
		// Presence is not eligibility. A record whose failure was the analysis
		// environment failing — no usable toolchain, a cancelled run — measured
		// nothing about this module, and serving it back makes one bad run
		// permanent: every later run reports the same error and only --force ever
		// clears it. The record stays in the ledger as evidence; it just does not
		// answer this question. The rule lives in the domain so the vuln stage's
		// on-demand spawner applies the same one.
		// A cached record answers a question that was asked with the inputs it had.
		// One produced before any build list existed, that never built the module
		// with bodies, is the pre-feature generation of a module whose require
		// directives could not be pinned — and serving it back is what would make
		// that failure permanent. Re-analysis APPENDS; the ladder in composition
		// decides which generation answers afterwards, so nothing is overwritten.
		superseded := domain2.PinnedAnalysisSupersedes(existing, req.Inputs)
		if found && domain2.RecordIsCacheable(existing) && !superseded {
			log.InfoContext(ctx, "callgraph_cache_hit")
			return ExtractResult{Record: existing, FromCache: true}, nil
		}
		if found && superseded {
			log.InfoContext(ctx, "callgraph_cache_superseded_by_build_list",
				slog.String("completeness", string(existing.Completeness)),
				slog.String("failure_cause", existing.FailureCause.String()),
				slog.String("recorded_build_list_source", existing.BuildListSource),
				slog.String("requested_build_list_source", req.Inputs.Source),
				slog.String("content_hash", existing.ContentHash),
			)
		}
		if found {
			log.InfoContext(ctx, "callgraph_cache_ineligible",
				slog.String("overall_status", existing.OverallStatus.String()),
				slog.String("failure_cause", existing.FailureCause.String()),
				slog.String("content_hash", existing.ContentHash),
			)
		}
	}

	// Skip listed modules entirely before any traversal/SSA work (
	// budgets). The exclusion decision is a pure domain rule; the use case
	// only orchestrates persisting the resulting record.
	if domain2.IsModuleExcluded(req.Coordinate.Path(), uc.exclusions) {
		record := domain2.NewExcludedRecord(req.Coordinate, uc.analyser.AnalyserMetadata().Algorithm, uc.exclusions)
		record.ExtractedAt = uc.clock.Now().UTC()
		record.PipelineVersion = uc.pipelineVersion
		// An excluded module is still a decision about a specific artefact: the
		// record says these bytes were not analysed, which is only checkable if it
		// says which bytes.
		record.ArtefactIdentity = artefact.String()
		record.SourceContentHash = factRecord.ContentHash
		record.BuildListSource = req.Inputs.Source
		record, err = uc.hasher.SetContentHash(record)
		if err != nil {
			return ExtractResult{}, fmt.Errorf("computing content hash: %w", err)
		}
		if err := uc.store.PutCallGraphRecord(ctx, record); err != nil {
			return ExtractResult{}, fmt.Errorf("persisting callgraph record: %w", err)
		}
		log.InfoContext(ctx, "callgraph_module_excluded_by_config",
			slog.String("overall_status", record.OverallStatus.String()),
			slog.String("content_hash", record.ContentHash),
		)
		// An exclusion is still a generation this run wrote, and the decision it
		// records — these bytes were not analysed — is exactly the kind a later
		// reader needs anchored in the append-only log.
		if err := emitCallGraphExtracted(uc.audit, record); err != nil {
			return ExtractResult{}, err
		}
		return ExtractResult{Record: record, FromCache: false}, nil
	}

	// The zip is addressed by what it is, not by where some earlier measurement
	// put it, so any store holding the artefact answers.
	zipIdentity, hasZip, err := fetchports.ZipIdentity(factRecord)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("deriving zip address for %s: %w", req.Coordinate, err)
	}
	if !hasZip {
		return ExtractResult{}, fmt.Errorf("%w: %s carries no module zip", ports.ErrModuleNotFetched, req.Coordinate)
	}
	zipPath, cleanup, err := blobZipPath(ctx, uc.blobs, zipIdentity)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("resolving blob path for %s: %w", factRecord.ContentLocation, err)
	}
	defer cleanup()

	record, err := uc.analyser.Analyse(ctx, zipPath, req.Coordinate, req.Inputs)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("running call graph analyser: %w", err)
	}

	record.ExtractedAt = uc.clock.Now().UTC()
	record.PipelineVersion = uc.pipelineVersion
	// Record the exclusion policy in force so callgraph-show can report it
	// even for modules that were analysed (not excluded).
	record.ExclusionList = uc.exclusions
	record.NodeCount = len(record.Nodes)
	record.EdgeCount = len(record.Edges)
	record.ArtefactIdentity = artefact.String()
	record.SourceContentHash = factRecord.ContentHash

	record, err = uc.hasher.SetContentHash(record)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("computing content hash: %w", err)
	}

	// The analysis ran because the stored record was not eligible to answer — an
	// environment failure never is — and it came back saying exactly what the
	// stored one says. There is no new fact to append. Appending anyway is how a
	// coordinate that keeps failing grows a generation per run for ever, and it
	// is not free: each generation is a full blob plus its edge rows, and every
	// composed read of the coordinate carries them.
	if found {
		same, serr := domain2.SameMeasurement(record, existing)
		if serr != nil {
			return ExtractResult{}, fmt.Errorf("comparing with the stored generation for %s: %w", req.Coordinate, serr)
		}
		if same {
			log.InfoContext(ctx, "callgraph_remeasured_equal",
				slog.String("overall_status", record.OverallStatus.String()),
				slog.String("failure_cause", record.FailureCause.String()),
				slog.String("content_hash", existing.ContentHash),
			)
			return ExtractResult{Record: existing, Reused: true}, nil
		}
	}

	if err := uc.store.PutCallGraphRecord(ctx, record); err != nil {
		return ExtractResult{}, fmt.Errorf("persisting callgraph record: %w", err)
	}
	log.InfoContext(ctx, "callgraph_record_persisted",
		slog.String("overall_status", record.OverallStatus.String()),
		slog.Int("node_count", record.NodeCount),
		slog.Int("edge_count", record.EdgeCount),
		slog.String("content_hash", record.ContentHash),
	)

	// Assurance log: one callgraph_extracted event per persisted generation
	// anchors the graph every reachability and capability answer is derived from
	// in the tamper-resistant append-only log, not only in the mutable ledger.
	if err := emitCallGraphExtracted(uc.audit, record); err != nil {
		return ExtractResult{}, err
	}

	return ExtractResult{Record: record, FromCache: false}, nil
}

// resolvedForThisToolchain re-asks the disagreeing coordinate for the generation
// built by the toolchain this run analyses under, and returns the original
// refusal unchanged when there is no such generation.
//
// It is ToolchainPreference rather than Toolchain, and the difference is the
// whole point. Toolchain NARROWS the read: a coordinate holding no generation
// built by that Go has no answer, which would make every record written before
// the current toolchain was installed a cache miss and re-analyse a whole build
// on every run. ToolchainPreference is consulted only where the generations
// already disagree, and a coordinate that composes cleanly is served exactly as
// it was. That is the question this site asks — resolve a disagreement, do not
// impose a filter — and it is the same field --toolchain passes on the read
// side, so the resolution a reader is told to use is the one extraction applies.
func (uc *ExtractCallGraphUseCase) resolvedForThisToolchain(
	ctx context.Context,
	log *slog.Logger,
	coord coordinate.ModuleCoordinate,
	conflict error,
) (domain2.CallGraphRecord, bool, error) {
	reader, ok := uc.store.(ports.CallGraphSourceReader)
	if !ok {
		return domain2.CallGraphRecord{}, false, conflict
	}
	name := uc.runToolchain(ctx)
	if !name.Recorded() {
		return domain2.CallGraphRecord{}, false, conflict
	}
	rec, found, err := reader.GetCallGraphRecordFrom(ctx, coord, uc.pipelineVersion,
		domain2.ComposeRequest{ToolchainPreference: name})
	if err != nil {
		// Including a refusal the preference could not resolve: two generations of
		// ONE toolchain that disagree about the graph are still a disagreement, and
		// the caller treats it as the cache miss it is. Wrapped, never replaced —
		// the caller routes on the sentinel underneath.
		return domain2.CallGraphRecord{}, false,
			fmt.Errorf("resolving %s under %s: %w", coord, name, err)
	}
	log.InfoContext(ctx, "callgraph_cache_resolved_by_run_toolchain",
		slog.String("toolchain", string(name)),
		slog.String("content_hash", rec.ContentHash),
	)
	return rec, found, nil
}

// runToolchain names the Go this run analyses under, asking at most once.
func (uc *ExtractCallGraphUseCase) runToolchain(ctx context.Context) gotoolchain.Version {
	if uc.toolchain == nil {
		return gotoolchain.Unrecorded
	}
	uc.toolchainOnce.Do(func() { uc.toolchainName = uc.toolchain(ctx) })
	return uc.toolchainName
}

// requireFetchRecord asks the ledger what it has measured about coord and
// returns the record composition serves. Returns ErrModuleNotFetched when
// nothing has been measured.
//
// It names no fetch pipeline version. It used to try three — the fetch one, the
// local-ingest one, and this stage's own extraction version, which is a category
// error: an extraction version is not a fetch version, and the two namespaces
// only share a type. The list also returned on its first hit, so a module
// measured at two versions was extracted from whichever version was listed first
// rather than from the stronger measurement. Composition decides both questions.
func (uc *ExtractCallGraphUseCase) requireFetchRecord(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
) (domain.FactRecord, error) {
	r, ok, err := fetchports.ComposedFetchRecord(ctx, uc.facts, coord)
	if err != nil {
		return domain.FactRecord{}, fmt.Errorf("checking fetch record: %w", err)
	}
	if !ok {
		return domain.FactRecord{}, fmt.Errorf("%w: %s", ports.ErrModuleNotFetched, coord)
	}
	return r.FactRecord, nil
}

// blobZipPath resolves a local filesystem path to a module zip so the
// path-based analyser can read it. When the blob store implements the optional
// BlobPathOptimizer capability it returns the store's own path and a no-op
// cleanup. Otherwise it materialises the blob bytes into a temp file — cleaned
// up via the returned func — so analysis works over any BlobStore, including
// object stores that cannot expose a filesystem path.
func blobZipPath(
	ctx context.Context,
	blobs fetchports.BlobStore,
	identity fetchports.BlobIdentity,
) (path string, cleanup func(), err error) {
	noop := func() {}
	if opt, ok := blobs.(fetchports.BlobPathOptimizer); ok {
		p, gerr := opt.GetPath(ctx, identity)
		if gerr != nil {
			return "", noop, fmt.Errorf("getting blob path: %w", gerr)
		}
		return p, noop, nil
	}

	rc, gerr := blobs.Get(ctx, identity)
	if gerr != nil {
		return "", noop, fmt.Errorf("opening blob: %w", gerr)
	}
	defer func() { _ = rc.Close() }()

	tmp, cerr := os.CreateTemp("", "kanonarion-callgraph-*.zip")
	if cerr != nil {
		return "", noop, fmt.Errorf("creating temp blob file: %w", cerr)
	}
	remove := func() { _ = os.Remove(tmp.Name()) }
	if _, cpErr := io.Copy(tmp, rc); cpErr != nil {
		_ = tmp.Close()
		remove()
		return "", noop, fmt.Errorf("materialising blob: %w", cpErr)
	}
	if clErr := tmp.Close(); clErr != nil {
		remove()
		return "", noop, fmt.Errorf("closing temp blob file: %w", clErr)
	}
	return tmp.Name(), remove, nil
}
