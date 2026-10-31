package application_test

import (
	"context"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	"code.eitanity.com/kanonarion/internal/example/application"
	"code.eitanity.com/kanonarion/internal/example/domain"
	exampleports "code.eitanity.com/kanonarion/internal/example/ports"
)

// examplePipelineSpy answers only at the current pipeline, as a store holding
// only current records does.
type examplePipelineSpy struct{ exampleports.ExampleStore }

func (examplePipelineSpy) GetExampleRecord(_ context.Context, _ coordinate.ModuleCoordinate, pv string) (domain.ExampleRecord, bool, error) {
	return domain.ExampleRecord{}, pv == application.PipelineVersion, nil
}

func (examplePipelineSpy) ListExampleRecordsFor(_ context.Context, _ coordinate.ModuleCoordinate, pv string) ([]domain.ExampleRecord, error) {
	if pv != application.PipelineVersion {
		return nil, nil
	}
	return []domain.ExampleRecord{{}}, nil
}

func (examplePipelineSpy) refs(pv string) []exampleports.ExampleRef {
	if pv != application.PipelineVersion {
		return nil
	}
	return []exampleports.ExampleRef{{}}
}

func (s examplePipelineSpy) FindBySymbol(_ context.Context, _, pv string, _ coordinate.ModuleSet) ([]exampleports.ExampleRef, error) {
	return s.refs(pv), nil
}

func (s examplePipelineSpy) FindBySymbolInModule(_ context.Context, _ coordinate.ModuleCoordinate, _, pv string) ([]exampleports.ExampleRef, error) {
	return s.refs(pv), nil
}

// An empty pipeline version reads the current one; passed through, it named
// no generation and the read answered as if nothing were recorded.
func TestQueryExamples_AnEmptyPipelineVersionReadsTheCurrentOne(t *testing.T) {
	uc := application.NewQueryExamplesUseCase(examplePipelineSpy{})
	coord := coordinatetest.MustNew("example.com/m", "v1.0.0")
	if _, ok, err := uc.GetExampleRecord(t.Context(), coord, ""); err != nil || !ok {
		t.Errorf("GetExampleRecord with no pipeline version = %v, %v; want the current record", ok, err)
	}
	if recs, err := uc.ExampleHistory(t.Context(), coord, ""); err != nil || len(recs) != 1 {
		t.Errorf("ExampleHistory with no pipeline version = %v, %v; want the current generation", recs, err)
	}
	if refs, err := uc.FindBySymbol(t.Context(), "example.com/m.F", "", coordinate.ModuleSet{}); err != nil || len(refs) != 1 {
		t.Errorf("FindBySymbol with no pipeline version = %v, %v; want the current example", refs, err)
	}
	if refs, err := uc.FindBySymbolInModule(t.Context(), coord, "example.com/m.F", ""); err != nil || len(refs) != 1 {
		t.Errorf("FindBySymbolInModule with no pipeline version = %v, %v; want the current example", refs, err)
	}
}
