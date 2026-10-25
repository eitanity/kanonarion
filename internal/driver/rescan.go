package driver

import (
	"context"

	"github.com/eitanity/kanonarion/internal/coordinate"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// rescanRunner is the slice of RescanWalkUseCase the rescan driver needs.
type rescanRunner interface {
	Rescan(ctx context.Context, req vulnapp.RescanRequest) (vulndomain.WalkScanRun, error)
}

// RescanUseCase re-scans a stored walk against a fresh or pinned advisory
// snapshot, appending a new scan run: what `kanonarion vuln-scan-rescan
// <walk-id>` runs. The command runs through this same type.
type RescanUseCase struct {
	rescan rescanRunner
}

// NewRescanUseCase constructs the rescan driver.
func NewRescanUseCase(rescan rescanRunner) *RescanUseCase {
	return &RescanUseCase{rescan: rescan}
}

// RescanRequest is the input to Run.
type RescanRequest struct {
	// WalkID names the stored walk to re-scan.
	WalkID string
	// Snapshot pins a stored advisory snapshot; nil downloads a fresh one.
	Snapshot *vulndomain.DatabaseSnapshot
	// Reachability turns on call-graph reachability analysis.
	Reachability bool
	// Operator is recorded on the new run as who asked for it.
	Operator string
	// Progress, when set, is told of each module as it is re-scanned.
	Progress func(coord coordinate.ModuleCoordinate, record vulndomain.VulnerabilityRecord, current, total int)
}

// Run re-scans every module of the walk, bypassing the per-module cache, and
// returns the new run. Its error is the re-scan's own, unwrapped, so a caller
// can match a frame the re-scan refuses to change.
func (uc *RescanUseCase) Run(ctx context.Context, req RescanRequest) (vulndomain.WalkScanRun, error) {
	return uc.rescan.Rescan(ctx, vulnapp.RescanRequest{ //nolint:wrapcheck // see the doc comment
		WalkID:             req.WalkID,
		Snapshot:           req.Snapshot,
		EnableReachability: req.Reachability,
		Operator:           req.Operator,
		Progress:           req.Progress,
	})
}
