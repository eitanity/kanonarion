package application

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/extract/domain"
	"github.com/eitanity/kanonarion/internal/extract/ports"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// refusingExtractor refuses the first stage of one module as the blob store
// does an altered artefact, and records every stage it was asked to run.
type refusingExtractor struct {
	refused coordinate.ModuleCoordinate
	ran     map[coordinate.ModuleCoordinate][]string
}

func (r *refusingExtractor) Extract(_ context.Context, coord coordinate.ModuleCoordinate, stage string, _ bool, _ string) (ports.StageResult, error) {
	r.ran[coord] = append(r.ran[coord], stage)
	if coord == r.refused {
		return ports.StageResult{}, fmt.Errorf("license extraction failed: %w", fetchports.ErrBlobTampered)
	}
	return ports.StageResult{Status: domain.StageSucceeded, RecordID: "rec-" + stage}, nil
}

// A stored artefact refused as altered fails the module's remaining stages
// without running them, since each would read the same refused bytes; the run
// is still recorded, the other modules are extracted, and the refusal is
// returned so the caller exits on it.
func TestExtractUseCase_ARefusedArtefactStopsItsModuleAndIsReturned(t *testing.T) {
	refused := coordinatetest.MustNew("example.com/refused", "v1.0.0")
	intact := coordinatetest.MustNew("example.com/intact", "v1.0.0")
	walk := walkdomain.WalkRecord{Target: intact, Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{
		{Coordinate: refused}, {Coordinate: intact},
	}}}
	runs := &mockExtractionStore{runs: map[string]domain.ExtractionRun{}}
	extractor := &refusingExtractor{refused: refused, ran: map[coordinate.ModuleCoordinate][]string{}}
	uc := mustExtractUseCase(t, Config{
		Runs:      runs,
		Walks:     &mockWalkStore{walks: map[string]walkdomain.WalkRecord{"w": walk}},
		Extractor: extractor,
		Stages:    mockStageRegistry{},
		Clock:     fakeClock{t: testClockTime},
		Stopwatch: fakeStopwatch{},
		Workers:   1,
	})

	run, err := uc.Execute(t.Context(), ExtractRequest{WalkID: "w", Stages: testStages})
	if !errors.Is(err, fetchports.ErrBlobTampered) {
		t.Fatalf("Execute err = %v, want the refusal", err)
	}
	if _, stored := runs.runs[run.ID]; !stored {
		t.Error("the run was not recorded")
	}
	if got := extractor.ran[refused]; len(got) != 1 {
		t.Errorf("refused module ran stages %v, want only the one that was refused", got)
	}
	for _, stage := range testStages {
		if s := run.PerModuleResults[refused].Stages[stage]; s.Status != domain.StageFailed || s.Error == "" {
			t.Errorf("refused module %s = %+v, want failed with the refusal", stage, s)
		}
	}
	if got := extractor.ran[intact]; len(got) != len(testStages) {
		t.Errorf("intact module ran %v, want every stage", got)
	}
}
