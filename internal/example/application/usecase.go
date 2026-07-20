package application

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/eitanity/kanonarion/internal/coordinate"
	domain2 "github.com/eitanity/kanonarion/internal/example/domain"
	"github.com/eitanity/kanonarion/internal/example/ports"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
)

// PipelineVersion identifies this release of the example extraction pipeline.
// Bump this constant whenever extraction logic changes to ensure old records
// are not confused with new ones.
const PipelineVersion = "0.3.0"

// ExtractExampleUseCase harvests Example* functions from a module's _test.go
// files and persists an ExampleRecord.
type ExtractExampleUseCase struct {
	facts                     fetchports.FactStore
	blobs                     fetchports.BlobStore
	examples                  ports.ExampleStore
	parser                    ports.ExampleParser
	clock                     fetchports.Clock
	stopwatch                 fetchports.Stopwatch
	pipelineVersion           string
	fetchPipelineVersion      string
	localFetchPipelineVersion string
	logger                    *slog.Logger
	hasher                    domain2.ExampleRecordHasher
}

// Config holds all construction parameters for ExtractExampleUseCase.
type Config struct {
	Facts                fetchports.FactStore
	Blobs                fetchports.BlobStore
	Examples             ports.ExampleStore
	Parser               ports.ExampleParser
	Clock                fetchports.Clock
	Stopwatch            fetchports.Stopwatch
	PipelineVersion      string // defaults to PipelineVersion constant
	FetchPipelineVersion string // pipeline version used when modules were fetched
	// LocalFetchPipelineVersion is the pipeline version under which locally
	// ingested modules (local-replace targets and the project-walk root)
	// persist their FactRecord. Empty disables the local fallback.
	LocalFetchPipelineVersion string
	Logger                    *slog.Logger
}

// NewExtractExampleUseCase constructs an ExtractExampleUseCase from a Config.
func NewExtractExampleUseCase(cfg Config) *ExtractExampleUseCase {
	if cfg.PipelineVersion == "" {
		cfg.PipelineVersion = PipelineVersion
	}
	return &ExtractExampleUseCase{
		facts:                     cfg.Facts,
		blobs:                     cfg.Blobs,
		examples:                  cfg.Examples,
		parser:                    cfg.Parser,
		clock:                     cfg.Clock,
		stopwatch:                 cfg.Stopwatch,
		pipelineVersion:           cfg.PipelineVersion,
		fetchPipelineVersion:      cfg.FetchPipelineVersion,
		localFetchPipelineVersion: cfg.LocalFetchPipelineVersion,
		logger:                    cfg.Logger,
	}
}

// ExtractRequest is the input to Execute.
type ExtractRequest struct {
	Coordinate coordinate.ModuleCoordinate
	// Force re-extracts even if a record for this pipeline version exists.
	Force bool
}

// ExtractResult is the output of Execute.
type ExtractResult struct {
	Record    domain2.ExampleRecord
	FromCache bool
}

// Execute runs the example extraction pipeline for the given module.
//
// The module must have been fetched first. If not, ErrModuleNotFetched is
// returned.
//
// Extraction failures (unreadable zip, zip parse errors) are recorded in the
// ExampleRecord with status ExtractionFailed — they do not make Execute return
// an error. Only infrastructure errors (store access, blob I/O) return errors.
func (uc *ExtractExampleUseCase) Execute(ctx context.Context, req ExtractRequest) (_ ExtractResult, retErr error) {
	log := uc.logger.With(
		slog.String("extraction.module.path", req.Coordinate.Path),
		slog.String("extraction.module.version", req.Coordinate.Version),
		slog.String("extraction.stage", "example"),
		slog.String("pipeline_version", uc.pipelineVersion),
	)
	lap := uc.stopwatch.Start()
	log.InfoContext(ctx, "example_extract_start")

	defer func() {
		log.InfoContext(ctx, "example_extract_end",
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
		existing, found, cerr := uc.examples.GetExampleRecord(ctx, req.Coordinate, uc.pipelineVersion)
		if cerr != nil && !errors.Is(cerr, ports.ErrExampleIntegrity) {
			return ExtractResult{}, fmt.Errorf("checking example store: %w", cerr)
		}
		if found {
			log.InfoContext(ctx, "example_cache_hit")
			return ExtractResult{Record: existing, FromCache: true}, nil
		}
	}

	blobHandle := fetchports.BlobHandle(factRecord.ContentLocation)
	zipReader, err := uc.blobs.Get(ctx, blobHandle)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("opening blob %s: %w", factRecord.ContentLocation, err)
	}
	defer func() {
		if cerr := zipReader.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("closing blob reader: %w", cerr)
		}
	}()

	zipData, err := io.ReadAll(zipReader)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("reading blob: %w", err)
	}
	log.InfoContext(ctx, "blob_read", slog.Int("zip_bytes", len(zipData)))

	record, extractErr := uc.extractFromZip(ctx, log, req.Coordinate, zipData)
	if extractErr != nil {
		record = domain2.ExampleRecord{
			SchemaVersion:   domain2.ExampleSchemaVersion,
			Ecosystem:       domain.EcosystemGo,
			Coordinate:      req.Coordinate,
			OverallStatus:   domain2.ExampleStatusExtractionFailed,
			FailureDetail:   extractErr.Error(),
			ExtractedAt:     uc.clock.Now().UTC(),
			PipelineVersion: uc.pipelineVersion,
		}
		log.InfoContext(ctx, "example_extraction_failed", slog.String("error", extractErr.Error()))
	}

	record, err = uc.hasher.SetContentHash(record)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("computing content hash: %w", err)
	}

	if err := uc.examples.PutExampleRecord(ctx, record); err != nil {
		return ExtractResult{}, fmt.Errorf("persisting example record: %w", err)
	}
	log.InfoContext(ctx, "example_record_persisted",
		slog.String("overall_status", record.OverallStatus.String()),
		slog.Int("example_count", len(record.Examples)),
		slog.String("content_hash", record.ContentHash),
	)

	return ExtractResult{Record: record, FromCache: false}, nil
}

func (uc *ExtractExampleUseCase) requireFetchRecord(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
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

func (uc *ExtractExampleUseCase) extractFromZip(
	ctx context.Context,
	log *slog.Logger,
	coord coordinate.ModuleCoordinate,
	zipData []byte,
) (domain2.ExampleRecord, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return domain2.ExampleRecord{}, fmt.Errorf("example extraction cancelled: %w", ctxErr)
	}

	modulePrefix := coord.Path + "@" + coord.Version + "/"
	examples, failures, err := uc.parser.Parse(zipData, modulePrefix)
	if err != nil {
		return domain2.ExampleRecord{}, fmt.Errorf("parsing module zip: %w", err)
	}

	for _, pf := range failures {
		log.InfoContext(ctx, "example_parse_failure",
			slog.String("file", pf.File),
			slog.String("error", pf.Error),
		)
	}

	// Sort for determinism.
	r := domain2.ExampleRecord{
		SchemaVersion:   domain2.ExampleSchemaVersion,
		Ecosystem:       domain.EcosystemGo,
		Coordinate:      coord,
		Examples:        examples,
		ParseFailures:   failures,
		ExtractedAt:     uc.clock.Now().UTC(),
		PipelineVersion: uc.pipelineVersion,
	}
	r.SortExamples()

	if len(examples) > 0 {
		r.OverallStatus = domain2.ExampleStatusFound
	} else {
		r.OverallStatus = domain2.ExampleStatusNone
	}

	log.InfoContext(ctx, "example_parse_complete",
		slog.Int("example_count", len(examples)),
		slog.Int("parse_failure_count", len(failures)),
	)

	return r, nil
}
