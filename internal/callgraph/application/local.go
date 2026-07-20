package application

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/eitanity/kanonarion/internal/coordinate"

	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"

	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
)

// ExtractLocalCallGraphUseCase extracts the call graph of a Go module
// working tree on disk and persists a CallGraphRecord, so callers/callees
// queries resolve the project's own internal symbols. Unlike
// ExtractCallGraphUseCase it does not require a prior fetch/blob: the
// source is the working tree itself.
type ExtractLocalCallGraphUseCase struct {
	store           ports.CallGraphStore
	analyser        ports.LocalCallGraphAnalyser
	clock           fetchports.Clock
	stopwatch       fetchports.Stopwatch
	pipelineVersion string
	logger          *slog.Logger
	hasher          domain2.CallGraphRecordHasher
}

// LocalConfig holds construction parameters for ExtractLocalCallGraphUseCase.
type LocalConfig struct {
	Store           ports.CallGraphStore
	Analyser        ports.LocalCallGraphAnalyser
	Clock           fetchports.Clock
	Stopwatch       fetchports.Stopwatch
	PipelineVersion string // defaults to PipelineVersion constant
	Logger          *slog.Logger
}

// NewExtractLocalCallGraphUseCase constructs the use case from a LocalConfig.
func NewExtractLocalCallGraphUseCase(cfg LocalConfig) *ExtractLocalCallGraphUseCase {
	if cfg.PipelineVersion == "" {
		cfg.PipelineVersion = PipelineVersion
	}
	return &ExtractLocalCallGraphUseCase{
		store:           cfg.Store,
		analyser:        cfg.Analyser,
		clock:           cfg.Clock,
		stopwatch:       cfg.Stopwatch,
		pipelineVersion: cfg.PipelineVersion,
		logger:          cfg.Logger,
	}
}

// LocalExtractRequest is the input to Execute.
type LocalExtractRequest struct {
	// Dir is the module working-tree root (contains go.mod).
	Dir string
	// Coordinate.Path must be the module path declared in Dir/go.mod;
	// Coordinate.Version is a synthetic local version (e.g. "v0.0.0").
	Coordinate coordinate.ModuleCoordinate
}

// Execute runs local call graph extraction and persists the record.
//
// A working tree mutates between runs, so a stored record for the local
// coordinate is never a valid cache: Execute always re-analyses and
// overwrites the persisted record (mirroring the local-coordinate handling in
// ExtractCallGraphUseCase). Persisting keeps callers/callees readable; it is
// never served back as a cache hit.
//
// Analysis failures are recorded in the CallGraphRecord's status — they do
// not make Execute return an error. Only infrastructure errors (store
// access, analyser infrastructure failures) return errors.
func (uc *ExtractLocalCallGraphUseCase) Execute(ctx context.Context, req LocalExtractRequest) (_ ExtractResult, retErr error) {
	log := uc.logger.With(
		slog.String("extraction.module.path", req.Coordinate.Path),
		slog.String("extraction.module.version", req.Coordinate.Version),
		slog.String("extraction.stage", "callgraph-local"),
		slog.String("pipeline_version", uc.pipelineVersion),
	)
	lap := uc.stopwatch.Start()
	log.InfoContext(ctx, "callgraph_local_extract_start", slog.String("dir", req.Dir))
	defer func() {
		log.InfoContext(ctx, "callgraph_local_extract_end",
			slog.Int64("extraction.duration_ms", lap.Elapsed().Milliseconds()),
		)
	}()

	record, err := uc.analyser.AnalyseDir(ctx, req.Dir, req.Coordinate)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("running local call graph analyser: %w", err)
	}

	record.ExtractedAt = uc.clock.Now().UTC()
	record.PipelineVersion = uc.pipelineVersion
	record.NodeCount = len(record.Nodes)
	record.EdgeCount = len(record.Edges)

	record, err = uc.hasher.SetContentHash(record)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("computing content hash: %w", err)
	}

	if err := uc.store.PutCallGraphRecord(ctx, record); err != nil {
		return ExtractResult{}, fmt.Errorf("persisting callgraph record: %w", err)
	}
	log.InfoContext(ctx, "callgraph_local_record_persisted",
		slog.String("overall_status", record.OverallStatus.String()),
		slog.Int("node_count", record.NodeCount),
		slog.Int("edge_count", record.EdgeCount),
		slog.String("content_hash", record.ContentHash),
	)

	return ExtractResult{Record: record, FromCache: false}, nil
}
