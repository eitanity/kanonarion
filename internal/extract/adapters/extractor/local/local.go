package local

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/childproc"
	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/extract/domain"
	"github.com/eitanity/kanonarion/internal/extract/ports"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	exapp "github.com/eitanity/kanonarion/internal/example/application"
	exdomain "github.com/eitanity/kanonarion/internal/example/domain"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
)

// callgraphSubprocessTimeout is the per-module timeout for callgraph subprocess
// invocations. SSA closure construction for large modules can take many minutes;
// 10 minutes provides headroom while bounding the blast radius of a hung child.
const callgraphSubprocessTimeout = 10 * time.Minute

type LicenseUseCase interface {
	Execute(ctx context.Context, req licapp.ExtractRequest) (licapp.ExtractResult, error)
}

type InterfaceUseCase interface {
	Execute(ctx context.Context, req ifaceapp.ExtractRequest) (ifaceapp.ExtractResult, error)
}

// SubprocessExecutor runs a child process and returns its stderr output.
// A non-nil error indicates the child exited non-zero or was killed by a signal
// or context deadline.
type SubprocessExecutor interface {
	Execute(ctx context.Context, args []string) (stderr []byte, err error)
}

// CallGraphReader reads the call graph generations the ledger holds for a
// coordinate. It is satisfied by the sqlite call graph store.
//
// Two reads, because the stage asks two different questions. GetCallGraphRecord
// COMPOSES — "which generation answers questions about this coordinate" — and
// may refuse when two of them disagree. ListCallGraphRecordsFor does not
// compose. Confirming a write is the second question: the subprocess appended a
// generation, and that is the one the stage reports, whatever composition would
// serve to a reader afterwards.
type CallGraphReader interface {
	GetCallGraphRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (cgdomain.CallGraphRecord, bool, error)
	// ListCallGraphRecordsFor returns every generation for the coordinate and
	// pipeline version, oldest first.
	ListCallGraphRecordsFor(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]cgdomain.CallGraphRecord, error)
}

type ExampleUseCase interface {
	Execute(ctx context.Context, req exapp.ExtractRequest) (exapp.ExtractResult, error)
}

// AdapterExtractor routes extract calls to the appropriate local use case by
// stage name. Nil use cases are permitted; an Extract call for a nil stage
// returns an error.
type AdapterExtractor struct {
	license           LicenseUseCase
	iface             InterfaceUseCase
	cgExec            SubprocessExecutor
	cgReader          CallGraphReader
	cgPipelineVersion string
	// cgExtraArgs is appended to the "callgraph" subprocess invocation, after
	// the coordinate and before --force. It carries CLI state that is
	// process-global in the parent (e.g. --store-root, --from-modcache) and
	// therefore does not otherwise cross the subprocess boundary.
	cgExtraArgs []string
	example     ExampleUseCase
	// logger is optional; a nil one discards. See WithLogger.
	logger *slog.Logger
}

// WithLogger wires a logger so the stage can say when it reported the
// generation it measured rather than the one composition would serve. It is
// optional — a nil logger discards — and returns the receiver for chaining.
func (a *AdapterExtractor) WithLogger(l *slog.Logger) *AdapterExtractor {
	a.logger = l
	return a
}

// log returns a usable logger, so an adapter constructed without one still runs.
func (a *AdapterExtractor) log() *slog.Logger {
	if a.logger == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return a.logger
}

// CallGraphSubprocessArgs builds the extra arguments a callgraph child needs to
// run against the same store — and the same module source — as its parent. The
// child is a fresh kanonarion process: it inherits none of the parent's
// process-global CLI state, so anything that state selects must be named on its
// command line or the child silently resolves the DEFAULT store root, reading,
// writing and migrating a store its caller never named.
//
// Every composition root that wires the callgraph stage MUST build its extra
// args here rather than assembling the list itself: a hand-copied argv list is
// how the library driver came to run its children against the default store.
// An empty modcacheDir means "no module-cache mode", which is the library
// driver's case — it has no --from-modcache concept and always reads bytes
// through the content-addressed blob store.
func CallGraphSubprocessArgs(storeRoot, modcacheDir string) []string {
	args := []string{"--store-root=" + storeRoot}
	if modcacheDir != "" {
		args = append(args, "--from-modcache="+modcacheDir)
	}
	return args
}

func NewAdapterExtractor(
	lic LicenseUseCase,
	iface InterfaceUseCase,
	cgExec SubprocessExecutor,
	cgReader CallGraphReader,
	cgPipelineVersion string,
	cgExtraArgs []string,
	ex ExampleUseCase,
) *AdapterExtractor {
	return &AdapterExtractor{
		license:           lic,
		iface:             iface,
		cgExec:            cgExec,
		cgReader:          cgReader,
		cgPipelineVersion: cgPipelineVersion,
		cgExtraArgs:       cgExtraArgs,
		example:           ex,
	}
}

func (a *AdapterExtractor) Extract(ctx context.Context, coord coordinate.ModuleCoordinate, stage string, force bool, walkID string) (ports.StageResult, error) {
	switch stage {
	case "license":
		res, err := a.license.Execute(ctx, licapp.ExtractRequest{Coordinate: coord, Force: force})
		if err != nil {
			return ports.StageResult{}, fmt.Errorf("license extraction failed: %w", err)
		}
		status := domain.StageSucceeded
		switch res.Record.OverallStatus {
		case licdomain.LicenceStatusUnknown, licdomain.LicenseStatusExtractionFailed, licdomain.LicenseStatusCancelled:
			status = domain.StageFailed
		}
		return ports.StageResult{
			RecordID: res.Record.ContentHash,
			Status:   status,
			Error:    failureReason(stage, status, res.Record.OverallStatus.String(), res.Record.FailureDetail),
		}, nil

	case "interface":
		res, err := a.iface.Execute(ctx, ifaceapp.ExtractRequest{Coordinate: coord, Force: force})
		if err != nil {
			return ports.StageResult{}, fmt.Errorf("interface extraction failed: %w", err)
		}
		status := domain.StageSucceeded
		switch res.Record.OverallStatus {
		case ifacedomain.InterfaceStatusUnknown, ifacedomain.InterfaceStatusExtractionFailed, ifacedomain.InterfaceStatusCancelled:
			status = domain.StageFailed
		}
		return ports.StageResult{
			RecordID: res.Record.ContentHash,
			Status:   status,
			Error:    failureReason(stage, status, res.Record.OverallStatus.String(), res.Record.FailureDetail),
		}, nil

	case "callgraph":
		return a.extractCallgraphSubprocess(ctx, coord, force, walkID)

	case "example":
		res, err := a.example.Execute(ctx, exapp.ExtractRequest{Coordinate: coord, Force: force})
		if err != nil {
			return ports.StageResult{}, fmt.Errorf("example extraction failed: %w", err)
		}
		status := domain.StageSucceeded
		switch res.Record.OverallStatus {
		case exdomain.ExampleStatusUnknown, exdomain.ExampleStatusExtractionFailed, exdomain.ExampleStatusCancelled:
			status = domain.StageFailed
		}
		return ports.StageResult{
			RecordID: res.Record.ContentHash,
			Status:   status,
			Error:    failureReason(stage, status, res.Record.OverallStatus.String(), res.Record.FailureDetail),
		}, nil

	default:
		return ports.StageResult{}, fmt.Errorf("unknown stage: %s", stage)
	}
}

// extractCallgraphSubprocess runs the callgraph stage by spawning a child
// process. The child runs the full callgraph extraction and persists the record
// to the store. The parent reads the record back on success.
func (a *AdapterExtractor) extractCallgraphSubprocess(ctx context.Context, coord coordinate.ModuleCoordinate, force bool, walkID string) (ports.StageResult, error) {
	cgCtx, cancel := context.WithTimeout(ctx, callgraphSubprocessTimeout)
	defer cancel()

	args := []string{"callgraph", coord.String()}
	args = append(args, a.cgExtraArgs...)
	if force {
		args = append(args, "--force")
	}
	// The walk is lost at the process boundary unless it is named on the command
	// line: the child opens the store fresh and knows only its arguments. Without
	// it a pre-modules module is analysed with no build list, which is what left
	// this population failing.
	if walkID != "" {
		args = append(args, "--from-walk", walkID)
	}

	stderr, execErr := a.cgExec.Execute(cgCtx, args)
	// A child that exited Partial wrote its graph; the record read below is what
	// classifies it. Reading that exit as a fault made every incompletely
	// analysable module a failed stage.
	if execErr != nil && !childproc.ExitedPartial(execErr) {
		detail := buildSubprocessErrorDetail(cgCtx, execErr, stderr)
		return ports.StageResult{
			Status: domain.StageFailed,
			Error:  fmt.Sprintf("callgraph stage status=ExtractionFailed: %s", detail),
		}, nil
	}

	rec, found, err := a.cgReader.GetCallGraphRecord(ctx, coord, a.cgPipelineVersion)
	if errors.Is(err, cgports.ErrCallGraphConflict) {
		// The child has just appended a generation that disagrees with an older
		// one, so composition refuses to name which of them answers the
		// coordinate. That refusal is correct for a reader and irrelevant here:
		// this stage reports the measurement it just took, not a served answer.
		a.log().InfoContext(ctx, "callgraph_stage_reports_measured_generation",
			slog.String("extraction.module.path", coord.Path()),
			slog.String("extraction.module.version", coord.Version()),
			slog.String("extraction.stage", "callgraph"),
			slog.String("pipeline_version", a.cgPipelineVersion),
			slog.String("conflict", err.Error()),
		)
		rec, found, err = a.measuredGeneration(ctx, coord)
	}
	if err != nil {
		return ports.StageResult{}, fmt.Errorf("reading callgraph record after subprocess: %w", err)
	}
	if !found {
		return ports.StageResult{
			Status: domain.StageFailed,
			Error:  "callgraph stage status=ExtractionFailed: subprocess exited 0 but no record found in store",
		}, nil
	}

	status := domain.StageSucceeded
	switch rec.OverallStatus {
	case cgdomain.CallGraphStatusUnknown, cgdomain.CallGraphStatusExtractionFailed, cgdomain.CallGraphStatusCancelled, cgdomain.CallGraphStatusLoadFailed:
		status = domain.StageFailed
	}
	return ports.StageResult{
		RecordID: rec.ContentHash,
		Status:   status,
		Error:    failureReason("callgraph", status, rec.OverallStatus.String(), rec.FailureDetail),
	}, nil
}

// measuredGeneration returns the generation the subprocess just appended.
//
// The ledger is append-only and lists in insertion order, so the newest row is
// the child's own write. LatestObservation states that rule, and stating it once
// is why this does not index the slice itself.
func (a *AdapterExtractor) measuredGeneration(ctx context.Context, coord coordinate.ModuleCoordinate) (cgdomain.CallGraphRecord, bool, error) {
	recs, err := a.cgReader.ListCallGraphRecordsFor(ctx, coord, a.cgPipelineVersion)
	if err != nil {
		return cgdomain.CallGraphRecord{}, false, fmt.Errorf("listing callgraph generations for %s: %w", coord, err)
	}
	if len(recs) == 0 {
		return cgdomain.CallGraphRecord{}, false, nil
	}
	return cgdomain.LatestObservation(recs), true, nil
}

// buildSubprocessErrorDetail formats the error_detail for a failed callgraph
// subprocess. The context is checked first so timeout failures are labelled
// clearly regardless of what the OS-level kill returns.
func buildSubprocessErrorDetail(ctx context.Context, execErr error, stderr []byte) string {
	stderrStr := strings.TrimSpace(string(stderr))

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		if stderrStr != "" {
			return fmt.Sprintf("subprocess timed out after %s: %s", callgraphSubprocessTimeout, stderrStr)
		}
		return fmt.Sprintf("subprocess timed out after %s", callgraphSubprocessTimeout)
	}

	if stderrStr != "" {
		return fmt.Sprintf("subprocess failed (%v): %s", execErr, stderrStr)
	}
	return fmt.Sprintf("subprocess failed: %v", execErr)
}

// failureReason builds the diagnostic string surfaced via StageResult.Error
// for a non-zero stage status. Only failed stages get a non-empty reason —
// succeeded stages return "" so the JSON field is omitted.
//
// The string always contains the stage name and the underlying record's
// OverallStatus value (e.g. "LoadFailed", "ExtractionFailed") so callers can
// distinguish failure classes without parsing free-form text. The record's
// own FailureDetail is appended when present; when the record forgot to set
// one, the status alone is still actionable.
func failureReason(stage string, status domain.StageStatus, recordStatus, recordDetail string) string {
	if status != domain.StageFailed {
		return ""
	}
	if recordDetail != "" {
		return fmt.Sprintf("%s stage status=%s: %s", stage, recordStatus, recordDetail)
	}
	return fmt.Sprintf("%s stage status=%s (no failure detail recorded)", stage, recordStatus)
}
