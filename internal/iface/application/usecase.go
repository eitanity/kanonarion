package application

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/eitanity/kanonarion/internal/adapters/ziparchive"
	"github.com/eitanity/kanonarion/internal/coordinate"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	domain3 "github.com/eitanity/kanonarion/internal/iface/domain"
	"github.com/eitanity/kanonarion/internal/iface/ports"
)

// PipelineVersion identifies this release of the interface extraction pipeline.
// Bump whenever extraction logic changes to ensure old records are not confused
// with new ones.
const PipelineVersion = "0.3.0"

// ExtractInterfaceUseCase extracts the public API of a module and persists an
// InterfaceRecord.
type ExtractInterfaceUseCase struct {
	facts                     fetchports.FactStore
	blobs                     fetchports.BlobStore
	store                     ports.InterfaceStore
	extractor                 ports.InterfaceExtractor
	clock                     fetchports.Clock
	stopwatch                 fetchports.Stopwatch
	pipelineVersion           string
	fetchPipelineVersion      string
	localFetchPipelineVersion string
	logger                    *slog.Logger
	hasher                    domain3.InterfaceRecordHasher
}

// Config holds all construction parameters for ExtractInterfaceUseCase.
type Config struct {
	Facts                fetchports.FactStore
	Blobs                fetchports.BlobStore
	Store                ports.InterfaceStore
	Extractor            ports.InterfaceExtractor
	Clock                fetchports.Clock
	Stopwatch            fetchports.Stopwatch
	PipelineVersion      string // defaults to PipelineVersion constant
	FetchPipelineVersion string
	// LocalFetchPipelineVersion is the pipeline version under which locally
	// ingested modules (local-replace targets and the project-walk root)
	// persist their FactRecord. Empty disables the local fallback.
	LocalFetchPipelineVersion string
	Logger                    *slog.Logger
}

// NewExtractInterfaceUseCase constructs an ExtractInterfaceUseCase from a Config.
func NewExtractInterfaceUseCase(cfg Config) *ExtractInterfaceUseCase {
	if cfg.PipelineVersion == "" {
		cfg.PipelineVersion = PipelineVersion
	}
	return &ExtractInterfaceUseCase{
		facts:                     cfg.Facts,
		blobs:                     cfg.Blobs,
		store:                     cfg.Store,
		extractor:                 cfg.Extractor,
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
	Record    domain3.InterfaceRecord
	FromCache bool
}

// Execute runs the interface extraction pipeline for the given module.
//
// The module must have been fetched first. If not, ErrModuleNotFetched is
// returned.
//
// Extraction failures are recorded in the InterfaceRecord with status
// ExtractionFailed — they do not make Execute return an error. Only
// infrastructure errors (store access, blob I/O) return errors.
func (uc *ExtractInterfaceUseCase) Execute(ctx context.Context, req ExtractRequest) (_ ExtractResult, retErr error) {
	log := uc.logger.With(
		slog.String("extraction.module.path", req.Coordinate.Path),
		slog.String("extraction.module.version", req.Coordinate.Version),
		slog.String("extraction.stage", "interface"),
		slog.String("pipeline_version", uc.pipelineVersion),
	)
	lap := uc.stopwatch.Start()
	log.InfoContext(ctx, "interface_extract_start")

	defer func() {
		log.InfoContext(ctx, "interface_extract_end",
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
		existing, found, cerr := uc.store.GetInterfaceRecord(ctx, req.Coordinate, uc.pipelineVersion)
		if cerr != nil && !errors.Is(cerr, ports.ErrInterfaceIntegrity) {
			return ExtractResult{}, fmt.Errorf("checking interface store: %w", cerr)
		}
		if found {
			log.InfoContext(ctx, "interface_cache_hit")
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
		record = domain3.InterfaceRecord{
			SchemaVersion:   domain3.InterfaceSchemaVersion,
			Ecosystem:       domain2.EcosystemGo,
			Coordinate:      req.Coordinate,
			OverallStatus:   domain3.InterfaceStatusExtractionFailed,
			FailureDetail:   extractErr.Error(),
			ExtractedAt:     uc.clock.Now().UTC(),
			PipelineVersion: uc.pipelineVersion,
		}
		log.InfoContext(ctx, "interface_extraction_failed", slog.String("error", extractErr.Error()))
	} else {
		record.PipelineVersion = uc.pipelineVersion
	}

	record, err = uc.hasher.SetContentHash(record)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("computing content hash: %w", err)
	}

	if err := uc.store.PutInterfaceRecord(ctx, record); err != nil {
		return ExtractResult{}, fmt.Errorf("persisting interface record: %w", err)
	}
	log.InfoContext(ctx, "interface_record_persisted",
		slog.String("overall_status", record.OverallStatus.String()),
		slog.Int("package_count", len(record.Packages)),
		slog.String("content_hash", record.ContentHash),
	)

	return ExtractResult{Record: record, FromCache: false}, nil
}

func (uc *ExtractInterfaceUseCase) requireFetchRecord(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
) (domain2.FactRecord, error) {
	versions := []string{uc.fetchPipelineVersion, uc.localFetchPipelineVersion, uc.pipelineVersion}
	seen := map[string]bool{}
	for _, v := range versions {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		r, ok, err := uc.facts.GetFetchRecord(ctx, coord, v)
		if err != nil {
			return domain2.FactRecord{}, fmt.Errorf("checking fetch record (pipeline %s): %w", v, err)
		}
		if ok {
			return r, nil
		}
	}
	return domain2.FactRecord{}, fmt.Errorf("%w: %s", ports.ErrModuleNotFetched, coord)
}

func (uc *ExtractInterfaceUseCase) extractFromZip(
	ctx context.Context,
	log *slog.Logger,
	coord coordinate.ModuleCoordinate,
	zipData []byte,
) (domain3.InterfaceRecord, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return domain3.InterfaceRecord{}, fmt.Errorf("interface extraction cancelled: %w", ctxErr)
	}

	archive, err := ziparchive.New(zipData)
	if err != nil {
		return domain3.InterfaceRecord{}, fmt.Errorf("parsing zip: %w", err)
	}

	// Strip the "module@version/" prefix so paths inside the FS are
	// relative to the module root (e.g., "net/http/server.go").
	modulePrefix := coord.Path + "@" + coord.Version + "/"
	stripped := archive.FS(modulePrefix)

	record, err := uc.extractor.Extract(ctx, stripped, coord)
	if err != nil {
		return domain3.InterfaceRecord{}, fmt.Errorf("extracting interface: %w", err)
	}

	log.InfoContext(ctx, "interface_parse_complete",
		slog.Int("package_count", len(record.Packages)),
		slog.String("overall_status", record.OverallStatus.String()),
	)

	return record, nil
}
