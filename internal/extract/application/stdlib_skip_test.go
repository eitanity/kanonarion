package application

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/extract/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// TestExtractUseCase_stdlibNodeSkippedNotFailed verifies the standard-library
// node — which has no fetched module artefact — is skipped-with-reason for every
// stage rather than failing the extraction run, while real dependencies extract
// normally.
func TestExtractUseCase_stdlibNodeSkippedNotFailed(t *testing.T) {
	ctx := t.Context()
	root := coordinate.ModuleCoordinate{Path: "example.com/project", Version: coordinate.LocalVersion}
	std := coordinate.ModuleCoordinate{Path: walkdomain.StdlibModulePath, Version: "v1.26.4"}
	dep, _ := coordinate.NewModuleCoordinate("github.com/foo/bar", "v1.0.0")
	walkID := "walk-stdlib"

	walk := walkdomain.WalkRecord{
		Target: root,
		Graph: walkdomain.Graph{
			Nodes: []walkdomain.GraphNode{
				{Coordinate: root, ResolutionSource: walkdomain.ResolutionLocalMainModule},
				{Coordinate: std, ResolutionSource: walkdomain.ResolutionStdlib},
				{Coordinate: dep, ResolutionSource: walkdomain.ResolutionMVS},
			},
		},
	}

	runs := &mockExtractionStore{runs: make(map[string]domain.ExtractionRun)}
	walks := &mockWalkStore{walks: map[string]walkdomain.WalkRecord{walkID: walk}}
	extractor := &mockExtractor{}

	uc := NewExtractUseCase(Config{
		Runs:      runs,
		Walks:     walks,
		Extractor: extractor,
		Stages:    mockStageRegistry{},
		Clock:     fakeClock{t: testClockTime},
		Stopwatch: fakeStopwatch{},
	})

	run, err := uc.Execute(ctx, ExtractRequest{WalkID: walkID, Stages: []string{"license", "interface"}})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if run.OverallStatus == domain.ExtractionRunPartial {
		t.Errorf("stdlib skip must not partial-ise the run: status = %v", run.OverallStatus)
	}

	// The extractor must never be invoked for the stdlib node.
	for _, c := range extractor.calls {
		if c.coord == std {
			t.Errorf("extractor called for stdlib node stage %s; should be skipped", c.stage)
		}
	}

	stdResult, ok := run.PerModuleResults[std]
	if !ok {
		t.Fatalf("no PerModuleResults entry for stdlib node %s", std)
	}
	for _, stage := range []string{"license", "interface"} {
		sr := stdResult.Stages[stage]
		if sr.Status != domain.StageSkipped {
			t.Errorf("stdlib stage %s status = %v, want skipped", stage, sr.Status)
		}
		if sr.Error == "" {
			t.Errorf("stdlib stage %s error should explain the skip", stage)
		}
	}
}
