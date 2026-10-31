package driver

import (
	"context"
	"errors"
	"strings"
	"testing"

	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	cgports "code.eitanity.com/kanonarion/internal/callgraph/ports"
	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	extractdomain "code.eitanity.com/kanonarion/internal/extract/domain"
	extractports "code.eitanity.com/kanonarion/internal/extract/ports"
)

type fakeStage struct {
	res      extractports.StageResult
	err      error
	stage    string
	force    bool
	walkID   string
	localDep bool
}

func (f *fakeStage) Extract(_ context.Context, _ coordinate.ModuleCoordinate, stage string, force bool, walkID string, localDep bool) (extractports.StageResult, error) {
	f.stage, f.force, f.walkID, f.localDep = stage, force, walkID, localDep
	return f.res, f.err
}

type fakeOutcomes struct {
	out   cgports.CallGraphOutcome
	found bool
	err   error
	pv    string
}

func (f *fakeOutcomes) LatestCallGraphOutcome(_ context.Context, _ coordinate.ModuleCoordinate, pv string) (cgports.CallGraphOutcome, bool, error) {
	f.pv = pv
	return f.out, f.found, f.err
}

func TestCallGraphBuild_RunsTheStageAndReadsBackWhatTheChildRecorded(t *testing.T) {
	stage := &fakeStage{res: extractports.StageResult{Status: extractdomain.StageSucceeded}}
	outcomes := &fakeOutcomes{out: cgports.CallGraphOutcome{OverallStatus: cgdomain.CallGraphStatusPartial}, found: true}
	got, err := NewCallGraphBuildUseCase(stage, outcomes, "9.9.9").Run(t.Context(), CallGraphBuildRequest{
		Coordinate: coordinatetest.MustNew("example.com/m", "v1.0.0"), Force: true, FromWalk: "w",
	})
	if err != nil || got.Outcome.OverallStatus != cgdomain.CallGraphStatusPartial {
		t.Fatalf("Run = %+v, %v; want the partial outcome and no error", got, err)
	}
	if stage.stage != "callgraph" || !stage.force || stage.walkID != "w" || stage.localDep || outcomes.pv != "9.9.9" {
		t.Errorf("stage got %+v, outcome read at %q", stage, outcomes.pv)
	}
}

func TestCallGraphBuild_EveryFailureIsAnError(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/m", "v1.0.0")
	ok := extractports.StageResult{Status: extractdomain.StageSucceeded}
	for name, tc := range map[string]struct {
		coord    coordinate.ModuleCoordinate
		stage    *fakeStage
		outcomes *fakeOutcomes
		want     string
	}{
		"no coordinate":  {stage: &fakeStage{res: ok}, outcomes: &fakeOutcomes{found: true}, want: "no module coordinate"},
		"stage error":    {coord: coord, stage: &fakeStage{err: errors.New("blob refused")}, outcomes: &fakeOutcomes{}, want: "blob refused"},
		"child failed":   {coord: coord, stage: &fakeStage{res: extractports.StageResult{Status: extractdomain.StageFailed, Error: "subprocess failed: exit status 2"}}, outcomes: &fakeOutcomes{}, want: "subprocess failed: exit status 2"},
		"read error":     {coord: coord, stage: &fakeStage{res: ok}, outcomes: &fakeOutcomes{err: errors.New("store down")}, want: "store down"},
		"nothing stored": {coord: coord, stage: &fakeStage{res: ok}, outcomes: &fakeOutcomes{}, want: "no record was stored"},
	} {
		_, err := NewCallGraphBuildUseCase(tc.stage, tc.outcomes, "9.9.9").Run(t.Context(), CallGraphBuildRequest{Coordinate: tc.coord})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Run error = %v, want one naming %q", name, err, tc.want)
		}
	}
}
