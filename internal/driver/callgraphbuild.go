package driver

import (
	"context"
	"errors"
	"fmt"

	cgports "code.eitanity.com/kanonarion/internal/callgraph/ports"
	"code.eitanity.com/kanonarion/internal/coordinate"
	extractdomain "code.eitanity.com/kanonarion/internal/extract/domain"
	extractports "code.eitanity.com/kanonarion/internal/extract/ports"
)

// callGraphStage is the extraction's call-graph stage: it starts the
// call-graph child for one coordinate and reports what the child recorded.
const callGraphStage = "callgraph"

// CallGraphBuildUseCase builds and stores the call graph of one module
// version, as `kanonarion callgraph <module>@<version>` does: it starts the
// call-graph child the extraction stage starts, and that child runs the
// extraction the command runs.
type CallGraphBuildUseCase struct {
	stage           extractports.Extractor
	outcomes        cgports.CallGraphOutcomeReader
	pipelineVersion string
}

// NewCallGraphBuildUseCase constructs the use case over the extraction's stage
// runner and the store the child writes to.
func NewCallGraphBuildUseCase(stage extractports.Extractor, outcomes cgports.CallGraphOutcomeReader, pipelineVersion string) *CallGraphBuildUseCase {
	return &CallGraphBuildUseCase{stage: stage, outcomes: outcomes, pipelineVersion: pipelineVersion}
}

// CallGraphBuildRequest is the input to Run.
type CallGraphBuildRequest struct {
	// Coordinate is the module version to analyse. It must already be fetched.
	Coordinate coordinate.ModuleCoordinate
	// Force re-analyses even when a stored graph answers.
	Force bool
	// FromWalk names a stored walk whose build list a module published before
	// Go modules is analysed against.
	FromWalk string
}

// CallGraphBuildResult is the output of Run: what the newest stored
// generation for the coordinate states.
type CallGraphBuildResult struct {
	Outcome cgports.CallGraphOutcome
}

// Run starts the child and reads back what it recorded. A child that fails, or
// records no usable graph, is an error carrying the child's own account; a
// partial graph is not, and Outcome says it is partial.
func (uc *CallGraphBuildUseCase) Run(ctx context.Context, req CallGraphBuildRequest) (CallGraphBuildResult, error) {
	if req.Coordinate.IsZero() {
		return CallGraphBuildResult{}, errors.New("building a call graph: no module coordinate given")
	}
	res, err := uc.stage.Extract(ctx, req.Coordinate, callGraphStage, req.Force, req.FromWalk, false)
	if err != nil {
		return CallGraphBuildResult{}, fmt.Errorf("building the call graph of %s: %w", req.Coordinate, err)
	}
	if res.Status != extractdomain.StageSucceeded {
		return CallGraphBuildResult{}, fmt.Errorf("building the call graph of %s: %s", req.Coordinate, res.Error)
	}
	out, found, err := uc.outcomes.LatestCallGraphOutcome(ctx, req.Coordinate, uc.pipelineVersion)
	if err != nil {
		return CallGraphBuildResult{}, fmt.Errorf("reading the call graph recorded for %s: %w", req.Coordinate, err)
	}
	if !found {
		return CallGraphBuildResult{}, fmt.Errorf("building the call graph of %s: the child exited cleanly and no record was stored", req.Coordinate)
	}
	return CallGraphBuildResult{Outcome: out}, nil
}
