package driver

import (
	"context"
	"fmt"

	"code.eitanity.com/kanonarion/internal/coordinate"
	vulnapp "code.eitanity.com/kanonarion/internal/vuln/application"
	vulndomain "code.eitanity.com/kanonarion/internal/vuln/domain"
)

// walkScanner is the slice of ScanWalkUseCase the scan stage needs.
type walkScanner interface {
	RefreshSnapshot(ctx context.Context, walkID string) (vulnapp.SnapshotRefresh, error)
	ReusableRun(ctx context.Context, walkID, projectDir string) (vulndomain.WalkScanRun, bool, error)
	ServeReusableRun(run vulndomain.WalkScanRun, surface string) error
	Scan(ctx context.Context, params vulnapp.ScanWalkParams) (vulndomain.WalkScanRun, error)
}

// WalkScan is what the scan stage is asked: the walk, and every choice that
// reaches the run it records or the stored run it serves.
type WalkScan struct {
	WalkID string
	// Force measures even when a stored run already answers.
	Force bool
	// Fresh refreshes the advisory database before reuse is decided.
	Fresh             bool
	Reachability      bool
	CallGraphWorkers  int
	BinaryModePrePass bool
	Operator          string
	ProjectDir        string
	NoVendor          bool
	Surface           string
	Progress          func(coord coordinate.ModuleCoordinate, record vulndomain.VulnerabilityRecord, current, total int)
}

// ScanHooks is what a caller states around the scan stage. A nil hook states
// nothing; a hook's error ends the stage and is returned unchanged.
type ScanHooks struct {
	// Refreshed is told what a Fresh refresh established, before its failure
	// is returned.
	Refreshed func(vulnapp.SnapshotRefresh, error) error
	// Serve hands back a stored run that already answers. It replaces the
	// stage's own witnessing, so it must witness the serving itself.
	Serve func(vulndomain.WalkScanRun) error
	// Scanning is told that a new run is about to be measured.
	Scanning func()
}

// ScanFailedError is the measurement's own failure, kept apart from the
// refresh and reuse failures around it so a caller can name the step.
type ScanFailedError struct{ Err error }

func (e *ScanFailedError) Error() string { return e.Err.Error() }

func (e *ScanFailedError) Unwrap() error { return e.Err }

// ScanWalk is the scan stage every walk scan runs: refresh when asked, then
// serve the stored run that already answers unless Force, else measure. reused
// reports a served run.
func ScanWalk(ctx context.Context, s walkScanner, req WalkScan, h ScanHooks) (vulndomain.WalkScanRun, bool, error) {
	if req.Fresh {
		refresh, rerr := s.RefreshSnapshot(ctx, req.WalkID)
		if h.Refreshed != nil {
			if err := h.Refreshed(refresh, rerr); err != nil {
				return vulndomain.WalkScanRun{}, false, err
			}
		}
		if rerr != nil {
			return vulndomain.WalkScanRun{}, false, fmt.Errorf("refreshing the advisory database: %w", rerr)
		}
	}
	if !req.Force {
		prior, ok, err := s.ReusableRun(ctx, req.WalkID, req.ProjectDir)
		if err != nil {
			return vulndomain.WalkScanRun{}, false, fmt.Errorf("checking for a reusable scan run: %w", err)
		}
		if ok {
			if h.Serve != nil {
				return prior, true, h.Serve(prior)
			}
			if err := s.ServeReusableRun(prior, req.Surface); err != nil {
				return vulndomain.WalkScanRun{}, false, fmt.Errorf("witnessing the served scan run: %w", err)
			}
			return prior, true, nil
		}
	}
	if h.Scanning != nil {
		h.Scanning()
	}
	run, err := s.Scan(ctx, vulnapp.ScanWalkParams{
		WalkID: req.WalkID,
		Force:  req.Force,
		// The refresh above settled the database this run is judged against.
		Fresh:              false,
		EnableReachability: req.Reachability,
		CallGraphWorkers:   req.CallGraphWorkers,
		BinaryModePrePass:  req.BinaryModePrePass,
		Operator:           req.Operator,
		ProjectDir:         req.ProjectDir,
		NoVendor:           req.NoVendor,
		Progress:           req.Progress,
	})
	if err != nil {
		return vulndomain.WalkScanRun{}, false, &ScanFailedError{Err: err}
	}
	return run, false, nil
}
