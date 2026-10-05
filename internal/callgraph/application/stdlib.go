package application

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/stdlib/domain"
)

// ExtractStdlibCallGraphUseCase extracts the Go standard library's call graph
// and persists it as an ordinary CallGraphRecord at the stdlib coordinate.
//
// It is a third extraction path beside the fetched-module and working-tree ones
// because the standard library arrives by neither route. Nothing fetches it —
// `fetch` cannot even parse "stdlib" as a module path — and it is not a mutable
// checkout: a released toolchain's $GOROOT/src is fixed by its version. What it
// shares with the other two is everything after the load, including the record
// shape, the seal and the ledger, so a stdlib graph is read by every query that
// reads a module graph.
type ExtractStdlibCallGraphUseCase struct {
	store           ports.CallGraphStore
	analyser        ports.StdlibCallGraphAnalyser
	toolchains      ports.ToolchainSourceLocator
	custody         ports.StdlibCustodyReader
	clock           fetchports.Clock
	stopwatch       fetchports.Stopwatch
	pipelineVersion string
	logger          *slog.Logger
	hasher          domain2.CallGraphRecordHasher
	audit           ports.AuditSink // optional; nil disables audit emission
}

// StdlibConfig holds construction parameters for ExtractStdlibCallGraphUseCase.
type StdlibConfig struct {
	Store      ports.CallGraphStore
	Analyser   ports.StdlibCallGraphAnalyser
	Toolchains ports.ToolchainSourceLocator
	// Custody reads the recorded chain of custody. It is optional: without one
	// the graph is still measured and still stored, and the record says it
	// anchors to no custody measurement rather than inventing one.
	Custody         ports.StdlibCustodyReader
	Clock           fetchports.Clock
	Stopwatch       fetchports.Stopwatch
	PipelineVersion string // defaults to PipelineVersion constant
	Logger          *slog.Logger
}

// NewExtractStdlibCallGraphUseCase constructs the use case from a StdlibConfig.
func NewExtractStdlibCallGraphUseCase(cfg StdlibConfig) *ExtractStdlibCallGraphUseCase {
	if cfg.PipelineVersion == "" {
		cfg.PipelineVersion = PipelineVersion
	}
	return &ExtractStdlibCallGraphUseCase{
		store:           cfg.Store,
		analyser:        cfg.Analyser,
		toolchains:      cfg.Toolchains,
		custody:         cfg.Custody,
		clock:           cfg.Clock,
		stopwatch:       cfg.Stopwatch,
		pipelineVersion: cfg.PipelineVersion,
		logger:          cfg.Logger,
	}
}

// WithAudit wires an audit sink so extraction appends one callgraph_extracted
// event per persisted generation, on the same terms as the other two stages.
func (uc *ExtractStdlibCallGraphUseCase) WithAudit(sink ports.AuditSink) *ExtractStdlibCallGraphUseCase {
	uc.audit = sink
	return uc
}

// Execute extracts the standard library's call graph at req.Coordinate.
//
// The coordinate's version is a toolchain version wearing semver — the walk
// records stdlib@v1.26.5 for go1.26.5 — and the toolchain that supplies it must
// be installed on this host. Where none is, nothing is recorded and
// ErrToolchainSourceUnavailable says so: a graph built by a different Go
// describes a different standard library, and recording one under this
// coordinate would be a fabrication rather than an approximation.
func (uc *ExtractStdlibCallGraphUseCase) Execute(ctx context.Context, req ExtractRequest) (_ ExtractResult, retErr error) {
	if !req.Coordinate.IsStdlib() {
		return ExtractResult{}, fmt.Errorf("%s is not the standard-library coordinate", req.Coordinate)
	}
	goVersion := domain.CanonicalGoVersion(req.Coordinate.Version())
	if goVersion == "" {
		return ExtractResult{}, fmt.Errorf(
			"%s names no toolchain version, so there is no standard library to analyse", req.Coordinate)
	}

	log := uc.logger.With(
		slog.String("extraction.module.path", req.Coordinate.Path()),
		slog.String("extraction.module.version", req.Coordinate.Version()),
		slog.String("extraction.stage", "callgraph-stdlib"),
		slog.String("pipeline_version", uc.pipelineVersion),
	)
	lap := uc.stopwatch.Start()
	log.InfoContext(ctx, "callgraph_stdlib_extract_start", slog.String("go_version", goVersion))
	defer func() {
		log.InfoContext(ctx, "callgraph_stdlib_extract_end",
			slog.Int64("extraction.duration_ms", lap.Elapsed().Milliseconds()),
		)
	}()

	var existing domain2.CallGraphRecord
	var found bool
	if !req.Force {
		var cerr error
		existing, found, cerr = uc.store.GetCallGraphRecord(ctx, req.Coordinate, uc.pipelineVersion)
		switch {
		case errors.Is(cerr, ports.ErrCallGraphConflict), errors.Is(cerr, ports.ErrCallGraphIntegrity),
			errors.As(cerr, new(*recordseal.NothingServable)):
			// No single stored generation answers the coordinate. Refusing to SERVE
			// that is right; refusing to MEASURE a new answer is not, so it is a
			// cache miss here and the ladder decides afterwards.
			log.InfoContext(ctx, "callgraph_stdlib_cache_unreadable_remeasuring",
				slog.String("reason", cerr.Error()))
			found = false
		case cerr != nil:
			return ExtractResult{}, fmt.Errorf("checking callgraph store: %w", cerr)
		}
		if found && domain2.RecordIsCacheable(existing) {
			log.InfoContext(ctx, "callgraph_stdlib_cache_hit",
				slog.String("content_hash", existing.ContentHash))
			return ExtractResult{Record: existing, FromCache: true}, nil
		}
	}

	src, err := uc.toolchains.LocateToolchain(ctx, goVersion)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("locating the toolchain that supplies %s: %w", req.Coordinate, err)
	}

	custody, hasCustody, err := uc.readCustody(ctx, goVersion)
	if err != nil {
		return ExtractResult{}, err
	}

	record, err := uc.analyser.AnalyseStdlib(ctx, src, req.Coordinate)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("running the standard-library call graph analyser: %w", err)
	}

	record.DerivedBy = domain2.DerivationFor(domain2.ReuseGateLedger, req.Force)
	record.ExtractedAt = uc.clock.Now().UTC()
	record.PipelineVersion = uc.pipelineVersion
	record.NodeCount = len(record.Nodes)
	record.EdgeCount = len(record.Edges)
	// The custody chain's artefact, not a digest computed here. The identity says
	// WHICH published standard library this coordinate is about, and the ledger
	// holds exactly one answer to that per toolchain version; what this analysis
	// actually read is stated separately, by the source tree digest the analyser
	// stamped. Conflating the two would have the record assert that the installed
	// tree and the published tarball are the same bytes, which nothing here
	// measured.
	record.ArtefactIdentity = custody.ArtefactIdentity
	record.SourceContentHash = custody.MeasurementHash
	if !hasCustody {
		// No custody measurement to anchor to. The identity still has to name
		// something, or the store refuses the record outright and the graph is lost;
		// the toolchain's own version is what the analysis can honestly stand
		// behind, and it is spelled so it can never be mistaken for a digest.
		record.ArtefactIdentity = unanchoredStdlibIdentity(src)
	}

	record, err = uc.hasher.SetContentHash(record)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("computing content hash: %w", err)
	}

	if found {
		same, serr := domain2.SameMeasurement(record, existing)
		if serr != nil {
			return ExtractResult{}, fmt.Errorf("comparing with the stored generation for %s: %w", req.Coordinate, serr)
		}
		if same {
			log.InfoContext(ctx, "callgraph_stdlib_remeasured_equal",
				slog.String("content_hash", existing.ContentHash))
			return ExtractResult{Record: existing, Reused: true}, nil
		}
	}
	if !found && !req.Force {
		if held, ok := uc.identicalGeneration(ctx, log, record); ok {
			log.InfoContext(ctx, "callgraph_stdlib_remeasured_equal",
				slog.String("content_hash", held.ContentHash))
			return ExtractResult{Record: held, Reused: true}, nil
		}
	}

	if err := uc.store.PutCallGraphRecord(ctx, record); err != nil {
		return ExtractResult{}, fmt.Errorf("persisting callgraph record: %w", err)
	}
	log.InfoContext(ctx, "callgraph_stdlib_record_persisted",
		slog.String("overall_status", record.OverallStatus.String()),
		slog.String("toolchain", string(record.Toolchain)),
		slog.String("analysis_root", record.AnalysisRoot),
		slog.Int("node_count", record.NodeCount),
		slog.Int("edge_count", record.EdgeCount),
		slog.String("content_hash", record.ContentHash),
	)
	if err := emitCallGraphExtracted(uc.audit, record); err != nil {
		return ExtractResult{}, err
	}
	return ExtractResult{Record: record, FromCache: false}, nil
}

// unanchoredStdlibIdentity names the bytes a graph was built from where no
// custody measurement exists for the toolchain version.
//
// It is deliberately not a hash. A digest-shaped value would be compared
// against the custody chain's published SHA-256 by every reader that compares
// identities, and this is not that measurement; the toolchain's own name is
// what the analysis can stand behind, and it reads as what it is.
func unanchoredStdlibIdentity(src ports.ToolchainSource) string {
	return "toolchain:" + src.Version
}

// readCustody asks the ledger for the chain of custody anchoring this toolchain
// version, and reports nothing held where no reader is wired.
func (uc *ExtractStdlibCallGraphUseCase) readCustody(
	ctx context.Context,
	goVersion string,
) (ports.StdlibCustody, bool, error) {
	if uc.custody == nil {
		return ports.StdlibCustody{}, false, nil
	}
	c, ok, err := uc.custody.StdlibCustody(ctx, goVersion)
	if err != nil {
		return ports.StdlibCustody{}, false,
			fmt.Errorf("reading the standard-library chain of custody for %s: %w", goVersion, err)
	}
	if !ok || c.ArtefactIdentity == "" {
		return ports.StdlibCustody{}, false, nil
	}
	return c, true, nil
}

// identicalGeneration asks the ledger whether it already holds this
// measurement, on the terms the fetched-module stage states.
func (uc *ExtractStdlibCallGraphUseCase) identicalGeneration(
	ctx context.Context,
	log *slog.Logger,
	record domain2.CallGraphRecord,
) (domain2.CallGraphRecord, bool) {
	reader, ok := uc.store.(ports.IdenticalGenerationReader)
	if !ok {
		return domain2.CallGraphRecord{}, false
	}
	held, found, err := reader.IdenticalGeneration(ctx, record)
	if err != nil {
		log.WarnContext(ctx, "callgraph_held_generation_unreadable_appending",
			slog.String("reason", err.Error()))
		return domain2.CallGraphRecord{}, false
	}
	return held, found
}

// StdlibCoordinateFor renders the call-graph coordinate of the standard library
// a walk recorded at goVersion ("go1.26.5" -> stdlib@v1.26.5).
//
// It exists so the one conversion between the toolchain's spelling and the
// coordinate's is written once: the walk injects the node under a v-prefixed
// semver and the custody ledger keys on the go-prefixed form, and a surface
// that converts for itself eventually converts one of them wrongly.
func StdlibCoordinateFor(goVersion string) (coordinate.ModuleCoordinate, error) {
	canonical := domain.CanonicalGoVersion(goVersion)
	if canonical == "" {
		return coordinate.ModuleCoordinate{}, fmt.Errorf("%q names no toolchain version", goVersion)
	}
	coord, err := coordinate.NewStdlibCoordinateAt("v" + canonical[len("go"):])
	if err != nil {
		return coordinate.ModuleCoordinate{}, fmt.Errorf("the standard-library coordinate for %s: %w", canonical, err)
	}
	return coord, nil
}
