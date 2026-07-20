package local

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/extract/domain"
	"github.com/eitanity/kanonarion/internal/extract/ports"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
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

// CallGraphReader reads a persisted call graph record from the store.
// It is satisfied by [*cgapp.QueryCallGraphUseCase].
type CallGraphReader interface {
	GetCallGraphRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (cgdomain.CallGraphRecord, bool, error)
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
	example           ExampleUseCase
}

func NewAdapterExtractor(
	lic LicenseUseCase,
	iface InterfaceUseCase,
	cgExec SubprocessExecutor,
	cgReader CallGraphReader,
	cgPipelineVersion string,
	ex ExampleUseCase,
) *AdapterExtractor {
	return &AdapterExtractor{
		license:           lic,
		iface:             iface,
		cgExec:            cgExec,
		cgReader:          cgReader,
		cgPipelineVersion: cgPipelineVersion,
		example:           ex,
	}
}

func (a *AdapterExtractor) Extract(ctx context.Context, coord coordinate.ModuleCoordinate, stage string, force bool) (ports.StageResult, error) {
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
		return a.extractCallgraphSubprocess(ctx, coord, force)

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
func (a *AdapterExtractor) extractCallgraphSubprocess(ctx context.Context, coord coordinate.ModuleCoordinate, force bool) (ports.StageResult, error) {
	cgCtx, cancel := context.WithTimeout(ctx, callgraphSubprocessTimeout)
	defer cancel()

	args := []string{"callgraph", coord.String()}
	if force {
		args = append(args, "--force")
	}

	stderr, execErr := a.cgExec.Execute(cgCtx, args)
	if execErr != nil {
		detail := buildSubprocessErrorDetail(cgCtx, execErr, stderr)
		return ports.StageResult{
			Status: domain.StageFailed,
			Error:  fmt.Sprintf("callgraph stage status=ExtractionFailed: %s", detail),
		}, nil
	}

	rec, found, err := a.cgReader.GetCallGraphRecord(ctx, coord, a.cgPipelineVersion)
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
