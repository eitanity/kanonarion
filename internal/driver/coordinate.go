package driver

import (
	"context"
	"errors"
	"fmt"

	"code.eitanity.com/kanonarion/internal/coordinate"
	extractapp "code.eitanity.com/kanonarion/internal/extract/application"
	extractdomain "code.eitanity.com/kanonarion/internal/extract/domain"
	vulnapp "code.eitanity.com/kanonarion/internal/vuln/application"
	vulndomain "code.eitanity.com/kanonarion/internal/vuln/domain"
	walkapp "code.eitanity.com/kanonarion/internal/walk/application"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// CoordinateAnalysisUseCase runs, for one published module version, what
// `kanonarion inspect <module>@<version>` runs: the walk, the extraction stages
// and the vulnerability scan. The CLI builds its stage requests with the same
// functions below, so the two record the same thing for the same input.
type CoordinateAnalysisUseCase struct {
	walk          walkRunner
	extract       extractRunner
	scan          walkScanner
	defaultStages []string
	isPrivate     func(path string) bool
}

// NewCoordinateAnalysisUseCase constructs the use case. isPrivate names the
// paths the module proxy is never asked about; nil names none.
func NewCoordinateAnalysisUseCase(walk walkRunner, extract extractRunner, scan walkScanner, defaultStages []string, isPrivate func(path string) bool) *CoordinateAnalysisUseCase {
	return &CoordinateAnalysisUseCase{
		walk: walk, extract: extract, scan: scan,
		defaultStages: append([]string(nil), defaultStages...),
		isPrivate:     isPrivate,
	}
}

// CoordinateAnalysisRequest is the input to Run.
type CoordinateAnalysisRequest struct {
	// Coordinate is the published module version to analyse.
	Coordinate coordinate.ModuleCoordinate
	// Force re-runs every stage even when stored records answer.
	Force bool
	// Stages names the extraction stages to run. Empty runs every built-in
	// stage, as inspect does.
	Stages []string
	// Reachability turns on call-graph reachability analysis in the scan.
	Reachability bool
	// FreshAdvisories refreshes the advisory database before the scan.
	FreshAdvisories bool
	// Operator is recorded on a new scan run as who asked for it.
	Operator string
}

// CoordinateAnalysisResult is the output of Run: the three records, and
// whether the walk and the scan were served from the store.
type CoordinateAnalysisResult struct {
	Walk       walkdomain.WalkRecord
	WalkReused bool
	Extraction extractdomain.ExtractionRun
	Scan       vulndomain.WalkScanRun
	ScanReused bool
}

// Run walks the coordinate, runs the extraction stages over the walk and scans
// it. A walk that failed or was cancelled stops the run; a partial one does
// not, as in inspect. A served scan run is attributed to inspect in the
// assurance log, because this is the run inspect performs.
func (uc *CoordinateAnalysisUseCase) Run(ctx context.Context, req CoordinateAnalysisRequest) (CoordinateAnalysisResult, error) {
	if err := uc.refuse(req.Coordinate); err != nil {
		return CoordinateAnalysisResult{}, err
	}
	walkRes, err := uc.walk.Execute(ctx, CoordinateWalkRequest(req))
	if err != nil {
		return CoordinateAnalysisResult{}, fmt.Errorf("walk: %w", err)
	}
	res := CoordinateAnalysisResult{Walk: walkRes.Record, WalkReused: walkRes.Reused}
	if serr := walkStopsAnalysis(walkRes.Record); serr != nil {
		return res, fmt.Errorf("walk: %w", serr)
	}

	res.Extraction, err = uc.extract.Execute(ctx, CoordinateExtractRequest(res.Walk.ID, req, uc.defaultStages))
	if err != nil {
		return res, fmt.Errorf("extract: %w", err)
	}
	if cerr := ctx.Err(); cerr != nil {
		return res, fmt.Errorf("extract: %w", cerr)
	}

	res.Scan, res.ScanReused, err = ScanWalk(ctx, uc.scan, CoordinateScanRequest(res.Walk.ID, req), ScanHooks{})
	if err != nil {
		return res, fmt.Errorf("vuln-scan: %w", err)
	}
	return res, nil
}

// refuse states why a coordinate cannot be analysed here: a local version has
// no published bytes, and a private path is never named to the proxy.
func (uc *CoordinateAnalysisUseCase) refuse(c coordinate.ModuleCoordinate) error {
	switch {
	case c.Path() == "":
		return errors.New("coordinate analysis: no module coordinate given")
	case c.IsLocal():
		return fmt.Errorf("coordinate analysis: %s is a local working tree, not a published version; LocalWalkExtract analyses one", c)
	case uc.isPrivate != nil && uc.isPrivate(c.Path()):
		return fmt.Errorf("coordinate analysis: %s matches GOPRIVATE/GONOPROXY, and a private module is never asked of the module proxy", c.Path())
	}
	return nil
}

// walkStopsAnalysis is the walk outcome inspect does not carry on past.
func walkStopsAnalysis(rec walkdomain.WalkRecord) error {
	switch rec.OverallStatus {
	case walkdomain.WalkFailed:
		return fmt.Errorf("walk %s failed: target module could not be fetched", rec.ID)
	case walkdomain.WalkCancelled:
		return fmt.Errorf("walk %s cancelled", rec.ID)
	default:
		return nil
	}
}

// CoordinateWalkRequest is the walk a coordinate analysis runs: the code
// dependencies of the module, at full depth. A caller adds only what does not
// reach the record's question (progress, the depth policy it loaded).
func CoordinateWalkRequest(req CoordinateAnalysisRequest) walkapp.WalkRequest {
	return walkapp.WalkRequest{
		Target: req.Coordinate,
		Force:  req.Force,
		Scope:  walkdomain.WalkScopeCode,
		Depth:  walkdomain.WalkDepthFull,
	}
}

// CoordinateExtractRequest is the extraction a coordinate analysis runs over
// its walk; empty Stages runs defaultStages.
func CoordinateExtractRequest(walkID string, req CoordinateAnalysisRequest, defaultStages []string) extractapp.ExtractRequest {
	stages := req.Stages
	if len(stages) == 0 {
		stages = defaultStages
	}
	return extractapp.ExtractRequest{
		WalkID: walkID,
		Stages: append([]string(nil), stages...),
		Force:  req.Force,
	}
}

// CoordinateScanRequest is the scan a coordinate analysis runs over its walk:
// rooted at the module itself, one call-graph worker, served under inspect.
func CoordinateScanRequest(walkID string, req CoordinateAnalysisRequest) WalkScan {
	return WalkScan{
		WalkID:           walkID,
		Force:            req.Force,
		Fresh:            req.FreshAdvisories,
		Reachability:     req.Reachability,
		CallGraphWorkers: 1,
		Operator:         req.Operator,
		Surface:          vulnapp.ServeSurfaceInspect,
	}
}
