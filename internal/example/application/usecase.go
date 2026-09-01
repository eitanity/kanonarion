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
	facts           fetchports.FactStore
	blobs           fetchports.BlobStore
	examples        ports.ExampleStore
	parser          ports.ExampleParser
	clock           fetchports.Clock
	stopwatch       fetchports.Stopwatch
	pipelineVersion string
	logger          *slog.Logger
	hasher          domain2.ExampleRecordHasher
	audit           ports.AuditSink // optional; nil disables audit emission
}

// Config holds all construction parameters for ExtractExampleUseCase.
type Config struct {
	Facts           fetchports.FactStore
	Blobs           fetchports.BlobStore
	Examples        ports.ExampleStore
	Parser          ports.ExampleParser
	Clock           fetchports.Clock
	Stopwatch       fetchports.Stopwatch
	PipelineVersion string // defaults to PipelineVersion constant
	Logger          *slog.Logger
}

// NewExtractExampleUseCase constructs an ExtractExampleUseCase from a Config.
func NewExtractExampleUseCase(cfg Config) *ExtractExampleUseCase {
	if cfg.PipelineVersion == "" {
		cfg.PipelineVersion = PipelineVersion
	}
	return &ExtractExampleUseCase{
		facts:           cfg.Facts,
		blobs:           cfg.Blobs,
		examples:        cfg.Examples,
		parser:          cfg.Parser,
		clock:           cfg.Clock,
		stopwatch:       cfg.Stopwatch,
		pipelineVersion: cfg.PipelineVersion,
		logger:          cfg.Logger,
	}
}

// WithAudit wires an audit sink so extraction appends one examples_extracted
// event per persisted generation. It is optional — a nil sink (the default)
// disables emission — and returns the receiver for chaining, mirroring the
// other stages' optional-dependency builders.
func (uc *ExtractExampleUseCase) WithAudit(sink ports.AuditSink) *ExtractExampleUseCase {
	uc.audit = sink
	return uc
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
	// Reused says the extraction ran and came back identical to a generation the
	// ledger already holds, so nothing was appended and Record is that held
	// generation.
	//
	// It is deliberately not FromCache. A cache hit means no extraction happened;
	// this means one did, and its result was already recorded. Reporting them as
	// one fact would tell a reader chasing a stale answer that the tree was never
	// read, when it was.
	Reused bool
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
		slog.String("extraction.module.path", req.Coordinate.Path()),
		slog.String("extraction.module.version", req.Coordinate.Version()),
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

	// Which bytes this extraction is about, resolved before any work is done so a
	// fetch record that names no artefact fails here rather than after a full
	// parse. This stage always holds a fetch record, so a record it cannot name
	// an artefact for is a fault in the measurement, not a legacy row.
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
	if !req.Force && !req.Coordinate.IsLocal() {
		existing, found, cerr := uc.examples.GetExampleRecord(ctx, req.Coordinate, uc.pipelineVersion)
		// A composition refusal says no single stored generation answers this
		// coordinate. Refusing to SERVE that is right; refusing to MEASURE a new
		// answer is not, so it is a cache miss here. Extraction appends, and the
		// ladder decides which generation answers afterwards.
		switch {
		case errors.Is(cerr, ports.ErrExampleConflict):
			log.InfoContext(ctx, "example_cache_conflict_remeasuring",
				slog.String("conflict", cerr.Error()),
			)
		case cerr != nil && !errors.Is(cerr, ports.ErrExampleIntegrity):
			return ExtractResult{}, fmt.Errorf("checking example store: %w", cerr)
		}
		if found {
			log.InfoContext(ctx, "example_cache_hit")
			return ExtractResult{Record: existing, FromCache: true}, nil
		}
	}

	// The zip is addressed by what it is, not by where some earlier measurement
	// put it, so any store holding the artefact answers.
	zipIdentity, hasZip, err := fetchports.ZipIdentity(factRecord)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("deriving zip address for %s: %w", req.Coordinate, err)
	}
	if !hasZip {
		return ExtractResult{}, fmt.Errorf("%w: %s carries no module zip: %s", ports.ErrModuleNotFetched, req.Coordinate, domain.NotFetchedRemedy(req.Coordinate))
	}
	zipReader, err := uc.blobs.Get(ctx, zipIdentity)
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

	// Stamped on every branch: a failed extraction is still a claim about a
	// specific artefact, and one that cannot say which is unfalsifiable.
	record.ArtefactIdentity = artefact.String()
	record.SourceContentHash = factRecord.ContentHash

	record, err = uc.hasher.SetContentHash(record)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("computing content hash: %w", err)
	}

	// A local coordinate never reached the cache lookup above, so nothing is held
	// to compare against yet. Whether a stored generation may be SERVED and
	// whether one already states this measurement are different questions: the
	// first is answered before the extraction and is always no for a working tree,
	// the second only after it, and asking it is what stops a re-read of an
	// unchanged tree appending its whole example set again.
	if !req.Force {
		if held, ok := uc.identicalGeneration(ctx, log, record); ok {
			log.InfoContext(ctx, "example_remeasured_equal",
				slog.String("overall_status", record.OverallStatus.String()),
				slog.Int("example_count", len(record.Examples)),
				slog.String("content_hash", held.ContentHash),
			)
			return ExtractResult{Record: held, Reused: true}, nil
		}
	}

	if err := uc.examples.PutExampleRecord(ctx, record); err != nil {
		return ExtractResult{}, fmt.Errorf("persisting example record: %w", err)
	}
	log.InfoContext(ctx, "example_record_persisted",
		slog.String("overall_status", record.OverallStatus.String()),
		slog.Int("example_count", len(record.Examples)),
		slog.String("content_hash", record.ContentHash),
	)

	// Assurance log: one examples_extracted event per persisted generation
	// anchors the examples a later adoption or migration answer quotes in the
	// append-only log, not only in the mutable example ledger. The record is
	// written first, so a failed append reports that the write is unlogged — it
	// never undoes it.
	if err := emitExamplesExtracted(uc.audit, record); err != nil {
		return ExtractResult{}, err
	}

	return ExtractResult{Record: record, FromCache: false}, nil
}

// identicalGeneration asks the ledger whether it already holds the measurement
// this run has just taken, and reports nothing held when it cannot say.
//
// It never returns an error, and that is the difference between this lookup and
// the cache lookup before the extraction. That one runs before any work and a
// store it cannot read must stop the run. This one runs after: the run holds a
// measurement, appending it is always correct, and refusing to record what was
// measured because an optimisation could not be checked would lose the answer.
// The fault is stated rather than swallowed, so a store that stops answering is
// visible as the extra generations it causes plus the line that says why.
func (uc *ExtractExampleUseCase) identicalGeneration(
	ctx context.Context,
	log *slog.Logger,
	record domain2.ExampleRecord,
) (domain2.ExampleRecord, bool) {
	reader, ok := uc.examples.(ports.IdenticalGenerationReader)
	if !ok {
		return domain2.ExampleRecord{}, false
	}
	held, found, err := reader.IdenticalGeneration(ctx, record)
	if err != nil {
		log.WarnContext(ctx, "example_held_generation_unreadable_appending",
			slog.String("reason", err.Error()),
		)
		return domain2.ExampleRecord{}, false
	}
	return held, found
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
func (uc *ExtractExampleUseCase) requireFetchRecord(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
) (domain.FactRecord, error) {
	r, ok, err := fetchports.ComposedFetchRecord(ctx, uc.facts, coord)
	if err != nil {
		return domain.FactRecord{}, fmt.Errorf("checking fetch record: %w", err)
	}
	if !ok {
		return domain.FactRecord{}, fmt.Errorf("%w: %s: %s", ports.ErrModuleNotFetched, coord, domain.NotFetchedRemedy(coord))
	}
	return r.FactRecord, nil
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

	modulePrefix := coord.Path() + "@" + coord.Version() + "/"
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
