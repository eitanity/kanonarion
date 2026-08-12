package application

import (
	"context"
	"errors"
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
	audit           ports.AuditSink // optional; nil disables audit emission
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

// WithAudit wires an audit sink so local extraction appends one
// callgraph_extracted event per persisted generation. It is optional — a nil
// sink (the default) disables emission — and returns the receiver for chaining,
// mirroring the other stages' optional-dependency builders.
func (uc *ExtractLocalCallGraphUseCase) WithAudit(sink ports.AuditSink) *ExtractLocalCallGraphUseCase {
	uc.audit = sink
	return uc
}

// LocalExtractRequest is the input to Execute.
type LocalExtractRequest struct {
	// Dir is the module working-tree root (contains go.mod).
	Dir string
	// Force re-analyses even when the ledger already holds a record of this tree
	// in this state. It is how a caller re-measures after something OUTSIDE the
	// tree changed — a different toolchain, a repopulated module cache — which the
	// tree's own digest cannot see.
	Force bool
	// Coordinate.Path must be the module path declared in Dir/go.mod;
	// Coordinate.Version is coordinate.LocalVersion — nothing published the tree,
	// so there is no version to name. Which tree it was is carried by the record's
	// AnalysisSource and WorktreeDigest, not by the version component.
	Coordinate coordinate.ModuleCoordinate
}

// Execute runs local call graph extraction and persists the record.
//
// A working tree mutates between runs, so a stored record is only a valid answer
// while the tree it was taken of is still the tree in front of the run. That is
// a question about the tree rather than about the clock, and it is answerable:
// the tree is scanned first, and a held record that states the same scan digest
// at the same root is served instead of being re-derived. Nothing is written on
// that path — the ledger already holds the identical measurement, and appending
// a second copy of it costs a full edge set per run and makes the ledger's own
// history unreadable.
//
// The scan happens BEFORE the analysis, and the digest stamped on a new record
// is the one taken then. A tree edited while the analysis runs then differs from
// what the next run scans, and that run re-derives; stamping the tree as it was
// afterwards would let the next run reuse a graph taken of a state that never
// existed.
//
// What the digest cannot see is everything outside the tree: the toolchain, the
// module cache, the build environment. Those change what an analysis of an
// unchanged tree produces, and Force is how a caller re-measures for that reason.
// A record that failed for an environment reason is never served back either —
// see domain.WorktreeRecordAnswersFor.
//
// Analysis failures are recorded in the CallGraphRecord's status — they do
// not make Execute return an error. Only infrastructure errors (store
// access, analyser infrastructure failures) return errors.
func (uc *ExtractLocalCallGraphUseCase) Execute(ctx context.Context, req LocalExtractRequest) (_ ExtractResult, retErr error) {
	log := uc.logger.With(
		slog.String("extraction.module.path", req.Coordinate.Path()),
		slog.String("extraction.module.version", req.Coordinate.Version()),
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

	identity, err := uc.analyser.TreeIdentity(ctx, req.Dir)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("identifying working tree: %w", err)
	}

	if !req.Force {
		existing, found, rerr := uc.heldRecord(ctx, req.Coordinate, identity)
		if rerr != nil {
			return ExtractResult{}, rerr
		}
		if found && domain2.WorktreeRecordAnswersFor(existing, identity) {
			log.InfoContext(ctx, "callgraph_local_tree_unchanged",
				slog.String("worktree_scan_digest", identity.ScanDigest),
				slog.String("analysis_root", identity.Root),
				slog.String("content_hash", existing.ContentHash),
			)
			return ExtractResult{Record: existing, FromCache: true}, nil
		}
	}

	record, err := uc.analyser.AnalyseDir(ctx, req.Dir, req.Coordinate)
	if err != nil {
		return ExtractResult{}, fmt.Errorf("running local call graph analyser: %w", err)
	}
	// Which tree this analysis was HANDED, as it was when the run started. The
	// digest AnalyseDir stamps says which files the loader read; this one is what
	// the next run can compare against before doing any work. They are different
	// claims and carry different scheme prefixes.
	record.WorktreeScanDigest = identity.ScanDigest

	record.ExtractedAt = uc.clock.Now().UTC()
	record.PipelineVersion = uc.pipelineVersion
	record.NodeCount = len(record.Nodes)
	record.EdgeCount = len(record.Edges)
	// ArtefactIdentity and SourceContentHash are deliberately left empty. The
	// source here is a working tree, not a fetched artefact: nothing was measured,
	// so there is no identity to name and no fetch record to point at. Empty reads
	// as "not recorded", which is the truth. Stamping a hash of the tree computed
	// here would invent an artefact no fetch measurement ever saw, and it would key
	// rows in every table that composes on the identity.

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

	// Assurance log: one callgraph_extracted event per persisted generation, and
	// only per persisted generation. A run served from a held record wrote
	// nothing, so it appends nothing: an event stating an extraction that did not
	// happen is a claim about store activity that a reader watching the stream
	// would have no way to check.
	if err := emitCallGraphExtracted(uc.audit, record); err != nil {
		return ExtractResult{}, err
	}

	return ExtractResult{Record: record, FromCache: false}, nil
}

// heldRecord asks the ledger for the generation it holds of this working tree.
//
// The store is asked about the ROOT this run was pointed at, not about whichever
// tree a reader is standing in. A store that cannot answer that question reports
// nothing held, and the run analyses — which is what every run did before reuse
// existed, so a store without the capability loses time rather than correctness.
func (uc *ExtractLocalCallGraphUseCase) heldRecord(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	identity domain2.WorktreeIdentity,
) (domain2.CallGraphRecord, bool, error) {
	reader, ok := uc.store.(ports.WorktreeGenerationReader)
	if !ok {
		return domain2.CallGraphRecord{}, false, nil
	}
	rec, found, err := reader.WorktreeGeneration(ctx, coord, uc.pipelineVersion, identity.Root, identity.ScanDigest)
	if err != nil {
		// A record that cannot be read is not a reason to refuse to measure: the
		// run holds the tree and can answer from it. It is a reason not to be
		// silent about the ledger's state, which the integrity error already is
		// when a reader asks for it directly.
		if errors.Is(err, ports.ErrCallGraphIntegrity) || errors.Is(err, ports.ErrCallGraphConflict) {
			return domain2.CallGraphRecord{}, false, nil
		}
		return domain2.CallGraphRecord{}, false, fmt.Errorf("checking callgraph store: %w", err)
	}
	return rec, found, nil
}
