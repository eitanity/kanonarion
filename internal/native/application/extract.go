package application

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/eitanity/kanonarion/internal/adapters/ziparchive"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/native/domain"
	"github.com/eitanity/kanonarion/internal/native/ports"
)

// Config wires the ExtractNativeUseCase dependencies.
type Config struct {
	Facts     fetchports.FactStore
	Blobs     fetchports.BlobStore
	Native    ports.NativeStore
	Source    ports.GoSourceReader
	Clock     fetchports.Clock
	Stopwatch fetchports.Stopwatch
	Logger    *slog.Logger
}

// ExtractNativeUseCase measures one module artefact for the native components
// it compiles into a binary.
type ExtractNativeUseCase struct {
	facts     fetchports.FactStore
	blobs     fetchports.BlobStore
	native    ports.NativeStore
	source    ports.GoSourceReader
	clock     fetchports.Clock
	stopwatch fetchports.Stopwatch
	logger    *slog.Logger
}

// NewExtractNativeUseCase constructs the use case.
func NewExtractNativeUseCase(cfg Config) *ExtractNativeUseCase {
	return &ExtractNativeUseCase{
		facts:     cfg.Facts,
		blobs:     cfg.Blobs,
		native:    cfg.Native,
		source:    cfg.Source,
		clock:     cfg.Clock,
		stopwatch: cfg.Stopwatch,
		logger:    cfg.Logger,
	}
}

// ExtractRequest is the input to Execute.
type ExtractRequest struct {
	Coordinate coordinate.ModuleCoordinate
	// Force re-measures even when a record for this generation is held.
	Force bool
}

// ExtractResult is the output of Execute.
type ExtractResult struct {
	Record    domain.Record
	FromCache bool
}

// Execute measures coord's artefact and persists the record.
//
// The bytes come from the verified module zip the fetch ledger already holds,
// so the record inherits that artefact's verification status and needs no
// separate trust story. Nothing is built and no C toolchain is invoked.
func (uc *ExtractNativeUseCase) Execute(ctx context.Context, req ExtractRequest) (_ ExtractResult, retErr error) {
	log := uc.log().With(
		slog.String("extraction.module.path", req.Coordinate.Path()),
		slog.String("extraction.module.version", req.Coordinate.Version()),
		slog.String("extraction.stage", "native"),
		slog.String("pipeline_version", domain.PipelineFingerprint()),
	)
	lap := uc.stopwatch.Start()
	defer func() {
		log.InfoContext(ctx, "native_extract_end", slog.Int64("extraction.duration_ms", lap.Elapsed().Milliseconds()))
	}()

	composed, found, err := fetchports.ComposedFetchRecord(ctx, uc.facts, req.Coordinate)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("checking fetch record: %w", err)
	}
	if !found {
		return ExtractResult{}, fmt.Errorf("%w: %s: %s", ports.ErrModuleNotFetched, req.Coordinate, fetchdomain.NotFetchedRemedy(req.Coordinate))
	}
	factRecord := composed.FactRecord

	artefact, err := fetchdomain.ArtefactIdentityOf(factRecord)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("deriving artefact identity for %s: %w", req.Coordinate, err)
	}
	if artefact.IsZero() {
		return ExtractResult{}, fmt.Errorf("fetch record for %s names no artefact: %w", req.Coordinate, fetchdomain.ErrZeroIdentity)
	}

	// A local coordinate is the project-walk root: its tree mutates between
	// runs, so a cached measurement of it would describe bytes that no longer
	// exist.
	if !req.Force && !req.Coordinate.IsLocal() {
		existing, held, cerr := uc.native.GetNativeRecord(ctx, req.Coordinate)
		if cerr != nil {
			return ExtractResult{}, fmt.Errorf("checking native store: %w", cerr)
		}
		if held {
			log.InfoContext(ctx, "native_cache_hit")
			return ExtractResult{Record: existing, FromCache: true}, nil
		}
	}

	zipIdentity, hasZip, err := fetchports.ZipIdentity(factRecord)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("deriving zip address for %s: %w", req.Coordinate, err)
	}
	if !hasZip {
		return ExtractResult{}, fmt.Errorf("%w: %s carries no module zip: %s", ports.ErrModuleNotFetched, req.Coordinate, fetchdomain.NotFetchedRemedy(req.Coordinate))
	}
	zipData, err := uc.readBlob(ctx, zipIdentity)
	if err != nil {
		return ExtractResult{}, err
	}

	components, sources, linked, err := uc.measure(ctx, req.Coordinate, zipData)
	if err != nil {
		return ExtractResult{}, err
	}

	presence := domain.PresenceOf(components, sources, linked)
	rec := domain.Record{
		SchemaVersion:          domain.NativeSchemaVersion,
		Ecosystem:              domain.EcosystemGo,
		Coordinate:             req.Coordinate,
		ArtefactIdentity:       artefact.String(),
		PipelineVersion:        domain.PipelineVersion,
		RecipeCatalogueVersion: domain.RecipeCatalogueVersion,
		Presence:               presence,
		Components:             components,
		Sources:                sources,
		LinkedLibraries:        linked,
		ExtractedAt:            uc.clock.Now().UTC(),
		ContentHash: domain.Hash(
			req.Coordinate.String(), artefact.String(),
			domain.PipelineVersion, domain.RecipeCatalogueVersion,
			presence, components, sources, linked,
		),
	}

	if err := uc.native.PutNativeRecord(ctx, rec); err != nil {
		return ExtractResult{}, fmt.Errorf("persisting native record: %w", err)
	}
	log.InfoContext(ctx, "native_record_persisted",
		slog.String("presence", string(rec.Presence)),
		slog.Int("components", len(rec.Components)),
		slog.Int("sources", len(rec.Sources)),
		slog.Int("linked_libraries", len(rec.LinkedLibraries)),
		slog.String("content_hash", rec.ContentHash),
	)
	return ExtractResult{Record: rec, FromCache: false}, nil
}

// readBlob loads the whole artefact. The zip's central directory is at its end,
// so a random-access read is what an archive reader needs; the blob port hands
// out a stream, and this is where the two meet.
func (uc *ExtractNativeUseCase) readBlob(ctx context.Context, identity fetchports.BlobIdentity) (_ []byte, retErr error) {
	reader, err := uc.blobs.Get(ctx, identity)
	if err != nil {
		return nil, fmt.Errorf("opening blob %s: %w", identity, err)
	}
	defer func() {
		if cerr := reader.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("closing blob reader: %w", cerr)
		}
	}()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading blob %s: %w", identity, err)
	}
	return data, nil
}

// measure walks the artefact twice: once to learn which package directories
// declare cgo and what their preambles link, once to read the native sources
// those directories hold.
//
// Two passes rather than one because the two facts are independent of file
// order — a directory's .c file can be listed before the .go file that makes it
// compiled — and a single pass would have to decide on an ordering the archive
// does not promise.
func (uc *ExtractNativeUseCase) measure(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	zipData []byte,
) ([]domain.Component, []domain.Source, []domain.LinkedLibrary, error) {
	archive, err := ziparchive.New(zipData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing zip for %s: %w", coord, err)
	}

	modulePrefix := coord.Path() + "@" + coord.Version() + "/"
	names := archive.Names()
	inModule := 0
	cgoDirs := map[string]bool{}
	detector := domain.NewDetector()

	for _, name := range names {
		if !strings.HasPrefix(name, modulePrefix) {
			continue
		}
		inModule++
		rel := strings.TrimPrefix(name, modulePrefix)
		if domain.IsIgnoredPath(rel) || !domain.IsBuildableGoSource(rel) {
			continue
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, nil, fmt.Errorf("native measurement cancelled: %w", ctxErr)
		}
		content, ok, rerr := archive.ReadFile(name)
		if rerr != nil {
			return nil, nil, nil, fmt.Errorf("reading %s: %w", rel, rerr)
		}
		if !ok {
			continue
		}
		imports, ierr := uc.source.ImportPaths(rel, content)
		if ierr != nil {
			return nil, nil, nil, fmt.Errorf("reading imports of %s in %s: %w", rel, coord, ierr)
		}
		if !domain.DeclaresCgo(imports) {
			continue
		}
		cgoDirs[domain.DirOf(rel)] = true
		preamble, perr := uc.source.CgoPreamble(rel, content)
		if perr != nil {
			return nil, nil, nil, fmt.Errorf("reading cgo preamble of %s in %s: %w", rel, coord, perr)
		}
		detector.AddDirectives(rel, preamble)
	}

	// An artefact holding nothing under the module prefix is not a module with
	// no native code — it is the wrong bytes, or a prefix this code failed to
	// derive. Reporting "absent" for it would be a silent wrong answer.
	if inModule == 0 {
		return nil, nil, nil, fmt.Errorf("artefact for %s holds no entry under %q", coord, modulePrefix)
	}

	for _, name := range names {
		if !strings.HasPrefix(name, modulePrefix) {
			continue
		}
		rel := strings.TrimPrefix(name, modulePrefix)
		if domain.IsIgnoredPath(rel) || !domain.IsNativeSource(rel) || !cgoDirs[domain.DirOf(rel)] {
			continue
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, nil, fmt.Errorf("native measurement cancelled: %w", ctxErr)
		}
		content, ok, rerr := archive.ReadFile(name)
		if rerr != nil {
			return nil, nil, nil, fmt.Errorf("reading %s: %w", rel, rerr)
		}
		if !ok {
			continue
		}
		detector.Add(rel, content)
	}

	components, sources, linked := detector.Result()
	return components, sources, linked, nil
}

// log returns a usable logger so a use case constructed without one still runs.
func (uc *ExtractNativeUseCase) log() *slog.Logger {
	if uc.logger == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return uc.logger
}
