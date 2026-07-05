package application

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
)

// PipelineVersion identifies this release of the call graph extraction
// pipeline. Bump whenever extraction logic changes.
const PipelineVersion = "0.1.0"

// ExtractCallGraphUseCase extracts the call graph of a module and persists a
// CallGraphRecord.
type ExtractCallGraphUseCase struct {
	facts                     fetchports.FactStore
	blobs                     fetchports.BlobStore
	store                     ports.CallGraphStore
	analyser                  ports.CallGraphAnalyser
	clock                     fetchports.Clock
	stopwatch                 fetchports.Stopwatch
	pipelineVersion           string
	fetchPipelineVersion      string
	localFetchPipelineVersion string
	exclusions                []string // normalised callgraph.exclude policy
	logger                    *slog.Logger
	hasher                    domain2.CallGraphRecordHasher
}

// Config holds all construction parameters for ExtractCallGraphUseCase.
type Config struct {
	Facts                fetchports.FactStore
	Blobs                fetchports.BlobStore
	Store                ports.CallGraphStore
	Analyser             ports.CallGraphAnalyser
	Clock                fetchports.Clock
	Stopwatch            fetchports.Stopwatch
	PipelineVersion      string // defaults to PipelineVersion constant
	FetchPipelineVersion string
	// LocalFetchPipelineVersion is the pipeline version under which locally
	// ingested modules (local-replace targets and the project-walk root)
	// persist their FactRecord. Empty disables the local fallback.
	LocalFetchPipelineVersion string
	// Exclusions is the raw callgraph.exclude list (module paths skipped from
	// analysis). Normalised on construction.
	Exclusions []string
	Logger     *slog.Logger
}

// NewExtractCallGraphUseCase constructs an ExtractCallGraphUseCase from a Config.
func NewExtractCallGraphUseCase(cfg Config) *ExtractCallGraphUseCase {
	if cfg.PipelineVersion == "" {
		cfg.PipelineVersion = PipelineVersion
	}
	return &ExtractCallGraphUseCase{
		facts:                     cfg.Facts,
		blobs:                     cfg.Blobs,
		store:                     cfg.Store,
		analyser:                  cfg.Analyser,
		clock:                     cfg.Clock,
		stopwatch:                 cfg.Stopwatch,
		pipelineVersion:           cfg.PipelineVersion,
		fetchPipelineVersion:      cfg.FetchPipelineVersion,
		localFetchPipelineVersion: cfg.LocalFetchPipelineVersion,
		exclusions:                domain2.NormaliseExclusions(cfg.Exclusions),
		logger:                    cfg.Logger,
	}
}

// ExtractRequest is the input to Execute.
type ExtractRequest struct {
	Coordinate domain.ModuleCoordinate
	// Force re-extracts even if a record for this pipeline version exists.
	Force bool
}

// ExtractResult is the output of Execute.
type ExtractResult struct {
	Record    domain2.CallGraphRecord
	FromCache bool
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
		slog.String("extraction.module.path", req.Coordinate.Path),
		slog.String("extraction.module.version", req.Coordinate.Version),
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

	// A local coordinate (the project-walk root) is never served from cache:
	// the working tree mutates between runs, so its records are recomputed
	// fresh every time.
	if !req.Force && !req.Coordinate.IsLocal() {
		existing, found, cerr := uc.store.GetCallGraphRecord(ctx, req.Coordinate, uc.pipelineVersion)
		if cerr != nil && !errors.Is(cerr, ports.ErrCallGraphIntegrity) {
			return ExtractResult{}, fmt.Errorf("checking callgraph store: %w", cerr)
		}
		if found {
			log.InfoContext(ctx, "callgraph_cache_hit")
			return ExtractResult{Record: existing, FromCache: true}, nil
		}
	}

	// Skip listed modules entirely before any traversal/SSA work (
	// budgets). The exclusion decision is a pure domain rule; the use case
	// only orchestrates persisting the resulting record.
	if domain2.IsModuleExcluded(req.Coordinate.Path, uc.exclusions) {
		record := domain2.NewExcludedRecord(req.Coordinate, uc.analyser.AnalyserMetadata().Algorithm, uc.exclusions)
		record.ExtractedAt = uc.clock.Now().UTC()
		record.PipelineVersion = uc.pipelineVersion
		record.Sort()
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
		return ExtractResult{Record: record, FromCache: false}, nil
	}

	blobHandle := fetchports.BlobHandle(factRecord.ContentLocation)
	zipPath, cleanup, err := blobZipPath(ctx, uc.blobs, blobHandle)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("resolving blob path for %s: %w", factRecord.ContentLocation, err)
	}
	defer cleanup()

	record, err := uc.analyser.Analyse(ctx, zipPath, req.Coordinate)
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

	record, err = uc.hasher.SetContentHash(record)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("computing content hash: %w", err)
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

	return ExtractResult{Record: record, FromCache: false}, nil
}

func (uc *ExtractCallGraphUseCase) requireFetchRecord(
	ctx context.Context,
	coord domain.ModuleCoordinate,
) (domain.FactRecord, error) {
	versions := []string{uc.fetchPipelineVersion, uc.localFetchPipelineVersion, uc.pipelineVersion}
	seen := map[string]bool{}
	for _, v := range versions {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		r, ok, err := uc.facts.GetFetchRecord(ctx, coord, v)
		if err != nil {
			return domain.FactRecord{}, fmt.Errorf("checking fetch record (pipeline %s): %w", v, err)
		}
		if ok {
			return r, nil
		}
	}
	return domain.FactRecord{}, fmt.Errorf("%w: %s", ports.ErrModuleNotFetched, coord)
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
	handle fetchports.BlobHandle,
) (path string, cleanup func(), err error) {
	noop := func() {}
	if opt, ok := blobs.(fetchports.BlobPathOptimizer); ok {
		p, gerr := opt.GetPath(ctx, handle)
		if gerr != nil {
			return "", noop, fmt.Errorf("getting blob path: %w", gerr)
		}
		return p, noop, nil
	}

	rc, gerr := blobs.Get(ctx, handle)
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
