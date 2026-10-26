package application

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"code.eitanity.com/kanonarion/internal/adapters/interrupt"
	"code.eitanity.com/kanonarion/internal/adapters/ziparchive"
	"code.eitanity.com/kanonarion/internal/coordinate"
	domain2 "code.eitanity.com/kanonarion/internal/fetch/domain"
	fetchports "code.eitanity.com/kanonarion/internal/fetch/ports"
	domain3 "code.eitanity.com/kanonarion/internal/iface/domain"
	"code.eitanity.com/kanonarion/internal/iface/ports"
)

// PipelineVersion identifies this release of the interface extraction pipeline.
// Bump whenever extraction logic changes to ensure old records are not confused
// with new ones.
//
// Bumped to "0.6.0" when extraction stopped walking testdata subtrees and
// stopped reading a public API out of a directory that declares one identifier
// twice: every record's package set and contents can change.
//
// Bumped to "0.7.0" when extraction stopped reading files and directories whose
// name begins with "_" or ".", which the go tool ignores: a 0.6.0 record of
// github.com/go-chi/chi/v5@v5.0.7 holds 16 packages where the go tool sees 2.
const PipelineVersion = "0.7.0"

// ExtractInterfaceUseCase extracts the public API of a module and persists an
// InterfaceRecord.
type ExtractInterfaceUseCase struct {
	facts           fetchports.FactStore
	blobs           fetchports.BlobStore
	store           ports.InterfaceStore
	extractor       ports.InterfaceExtractor
	clock           fetchports.Clock
	stopwatch       fetchports.Stopwatch
	pipelineVersion string
	logger          *slog.Logger
	hasher          domain3.InterfaceRecordHasher
	audit           ports.AuditSink // optional; nil disables audit emission
}

// Config holds all construction parameters for ExtractInterfaceUseCase.
type Config struct {
	Facts           fetchports.FactStore
	Blobs           fetchports.BlobStore
	Store           ports.InterfaceStore
	Extractor       ports.InterfaceExtractor
	Clock           fetchports.Clock
	Stopwatch       fetchports.Stopwatch
	PipelineVersion string // defaults to PipelineVersion constant
	Logger          *slog.Logger
}

// NewExtractInterfaceUseCase constructs an ExtractInterfaceUseCase from a Config.
func NewExtractInterfaceUseCase(cfg Config) *ExtractInterfaceUseCase {
	if cfg.PipelineVersion == "" {
		cfg.PipelineVersion = PipelineVersion
	}
	return &ExtractInterfaceUseCase{
		facts:           cfg.Facts,
		blobs:           cfg.Blobs,
		store:           cfg.Store,
		extractor:       cfg.Extractor,
		clock:           cfg.Clock,
		stopwatch:       cfg.Stopwatch,
		pipelineVersion: cfg.PipelineVersion,
		logger:          cfg.Logger,
	}
}

// WithAudit wires an audit sink so extraction appends one interface_extracted
// event per persisted generation. It is optional — a nil sink (the default)
// disables emission — and returns the receiver for chaining, mirroring the
// other stages' optional-dependency builders.
func (uc *ExtractInterfaceUseCase) WithAudit(sink ports.AuditSink) *ExtractInterfaceUseCase {
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
	Record    domain3.InterfaceRecord
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
		slog.String("extraction.module.path", req.Coordinate.Path()),
		slog.String("extraction.module.version", req.Coordinate.Version()),
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

	factRecord, artefact, err := uc.requireArtefact(ctx, req)
	if err != nil {
		return ExtractResult{}, err
	}

	// A local coordinate (the project-walk root) is never served from cache:
	// the working tree mutates between runs, so its records are recomputed
	// fresh every time.
	if !req.Force && !req.Coordinate.IsLocal() {
		if res, hit, cerr := uc.cachedRecord(ctx, log, req); cerr != nil || hit {
			return res, cerr
		}
	}

	zipReader, err := uc.openZip(ctx, req, factRecord)
	if err != nil {
		return ExtractResult{}, err
	}
	defer func() {
		if cerr := zipReader.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("closing blob reader: %w", cerr)
		}
	}()

	record, err := uc.measureInterface(ctx, log, req, zipReader)
	if err != nil {
		return ExtractResult{}, err
	}

	// Stamped on both branches: a failed extraction is still a claim about a
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
	// unchanged tree appending its whole package set again.
	if !req.Force {
		if held, ok := uc.identicalGeneration(ctx, log, record); ok {
			log.InfoContext(ctx, "interface_remeasured_equal",
				slog.String("overall_status", record.OverallStatus.String()),
				slog.Int("package_count", len(record.Packages)),
				slog.String("content_hash", held.ContentHash),
			)
			return ExtractResult{Record: held, Reused: true}, nil
		}
	}

	if err := uc.store.PutInterfaceRecord(ctx, record); err != nil {
		return ExtractResult{}, fmt.Errorf("persisting interface record: %w", err)
	}
	log.InfoContext(ctx, "interface_record_persisted",
		slog.String("overall_status", record.OverallStatus.String()),
		slog.Int("package_count", len(record.Packages)),
		slog.String("content_hash", record.ContentHash),
	)

	// Assurance log: one interface_extracted event per persisted generation
	// anchors the public API every compatibility answer is derived from in the
	// append-only log, not only in the mutable interface ledger. The record is
	// written first, so a failed append reports that the write is unlogged — it
	// never undoes it.
	if err := emitInterfaceExtracted(uc.audit, record); err != nil {
		return ExtractResult{}, err
	}

	return ExtractResult{Record: record, FromCache: false}, nil
}

// requireArtefact reads the fetch record for req's coordinate and the artefact
// it names, refusing one that names none.
func (uc *ExtractInterfaceUseCase) requireArtefact(ctx context.Context, req ExtractRequest) (domain2.FactRecord, domain2.ArtefactIdentity, error) {
	factRecord, err := uc.requireFetchRecord(ctx, req.Coordinate)
	if err != nil {
		return domain2.FactRecord{}, domain2.ArtefactIdentity{}, err
	}

	// Which bytes this extraction is about, resolved before any work is done so a
	// fetch record that names no artefact fails here rather than after a full
	// parse. This stage always holds a fetch record, so a record it cannot name
	// an artefact for is a fault in the measurement, not a legacy row.
	artefact, err := domain2.ArtefactIdentityOf(factRecord)
	if err != nil {
		return domain2.FactRecord{}, domain2.ArtefactIdentity{}, fmt.Errorf("deriving artefact identity for %s: %w", req.Coordinate, err)
	}
	if artefact.IsZero() {
		return domain2.FactRecord{}, domain2.ArtefactIdentity{}, fmt.Errorf("fetch record for %s names no artefact: %w", req.Coordinate, domain2.ErrZeroIdentity)
	}
	return factRecord, artefact, nil
}

// cachedRecord serves the stored generation when one is eligible to answer;
// hit reports that it did.
func (uc *ExtractInterfaceUseCase) cachedRecord(ctx context.Context, log *slog.Logger, req ExtractRequest) (ExtractResult, bool, error) {
	existing, found, cerr := uc.store.GetInterfaceRecord(ctx, req.Coordinate, uc.pipelineVersion)
	// A composition refusal says no single stored generation answers this
	// coordinate. Refusing to SERVE that is right; refusing to MEASURE a new
	// answer is not, so it is a cache miss here. Extraction appends, and the
	// ladder decides which generation answers afterwards.
	switch {
	case errors.Is(cerr, ports.ErrInterfaceConflict):
		log.InfoContext(ctx, "interface_cache_conflict_remeasuring",
			slog.String("conflict", cerr.Error()),
		)
	case cerr != nil && !errors.Is(cerr, ports.ErrInterfaceIntegrity):
		return ExtractResult{}, false, fmt.Errorf("checking interface store: %w", cerr)
	}
	switch {
	case found && !domain3.RecordIsCacheable(existing):
		// It may hold files a binary too old for the source could not read;
		// this one measures them rather than serve that record back.
		log.InfoContext(ctx, "interface_cache_not_servable_remeasuring",
			slog.String("toolchain", existing.Toolchain.String()))
	case found:
		log.InfoContext(ctx, "interface_cache_hit")
		return ExtractResult{Record: existing, FromCache: true}, true, nil
	}
	return ExtractResult{}, false, nil
}

// openZip opens the module zip the fetch record names. The caller closes it.
func (uc *ExtractInterfaceUseCase) openZip(ctx context.Context, req ExtractRequest, factRecord domain2.FactRecord) (io.ReadCloser, error) {
	// The zip is addressed by what it is, not by where some earlier measurement
	// put it, so any store holding the artefact answers.
	zipIdentity, hasZip, err := fetchports.ZipIdentity(factRecord)
	if err != nil {
		return nil, fmt.Errorf("deriving zip address for %s: %w", req.Coordinate, err)
	}
	if !hasZip {
		return nil, fmt.Errorf("%w: %s carries no module zip: %s", ports.ErrModuleNotFetched, req.Coordinate, domain2.NotFetchedRemedy(req.Coordinate))
	}
	zipReader, err := uc.blobs.Get(ctx, zipIdentity)
	if err != nil {
		return nil, fmt.Errorf("opening blob %s: %w", factRecord.ContentLocation, fetchports.AttributeBlobTamper(err, req.Coordinate))
	}
	return zipReader, nil
}

// measureInterface reads the module zip and extracts its interface. A failed
// extraction is a record of the failure, not an error.
func (uc *ExtractInterfaceUseCase) measureInterface(ctx context.Context, log *slog.Logger, req ExtractRequest, zipReader io.Reader) (domain3.InterfaceRecord, error) {
	zipData, err := io.ReadAll(zipReader)
	if err != nil {
		return domain3.InterfaceRecord{}, fmt.Errorf("reading blob: %w", err)
	}
	log.InfoContext(ctx, "blob_read", slog.Int("zip_bytes", len(zipData)))

	record, extractErr := uc.extractFromZip(ctx, log, req.Coordinate, zipData)
	if interrupt.Cancelled(ctx, extractErr) {
		// Stopped by the run's cancellation: no failed-extraction record is made of it.
		return domain3.InterfaceRecord{}, fmt.Errorf("extracting the interface of %s: %w", req.Coordinate, extractErr)
	}
	if extractErr != nil {
		record = domain3.InterfaceRecord{
			SchemaVersion:   domain3.InterfaceSchemaVersion,
			Ecosystem:       domain2.EcosystemGo,
			Coordinate:      req.Coordinate,
			OverallStatus:   domain3.InterfaceStatusExtractionFailed,
			FailureDetail:   extractErr.Error(),
			BuildFrame:      uc.extractor.BuildFrame(),
			Toolchain:       uc.extractor.Toolchain(),
			ExtractedAt:     uc.clock.Now().UTC(),
			PipelineVersion: uc.pipelineVersion,
		}
		log.InfoContext(ctx, "interface_extraction_failed", slog.String("error", extractErr.Error()))
	} else {
		record.PipelineVersion = uc.pipelineVersion
	}
	return record, nil
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
func (uc *ExtractInterfaceUseCase) identicalGeneration(
	ctx context.Context,
	log *slog.Logger,
	record domain3.InterfaceRecord,
) (domain3.InterfaceRecord, bool) {
	reader, ok := uc.store.(ports.IdenticalGenerationReader)
	if !ok {
		return domain3.InterfaceRecord{}, false
	}
	held, found, err := reader.IdenticalGeneration(ctx, record)
	if interrupt.Cancelled(ctx, err) {
		// The run was stopped; the write that follows fails on the same
		// cancellation and says so.
		return domain3.InterfaceRecord{}, false
	}
	if err != nil {
		log.WarnContext(ctx, "interface_held_generation_unreadable_appending",
			slog.String("reason", err.Error()),
		)
		return domain3.InterfaceRecord{}, false
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
func (uc *ExtractInterfaceUseCase) requireFetchRecord(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
) (domain2.FactRecord, error) {
	r, ok, err := fetchports.ComposedFetchRecord(ctx, uc.facts, coord)
	if err != nil {
		return domain2.FactRecord{}, fmt.Errorf("checking fetch record: %w", err)
	}
	if !ok {
		return domain2.FactRecord{}, fmt.Errorf("%w: %s: %s", ports.ErrModuleNotFetched, coord, domain2.NotFetchedRemedy(coord))
	}
	return r.FactRecord, nil
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
	modulePrefix := coord.Path() + "@" + coord.Version() + "/"
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
