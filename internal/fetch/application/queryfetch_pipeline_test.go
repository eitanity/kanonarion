package application_test

import (
	"context"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	"code.eitanity.com/kanonarion/internal/fetch/application"
	"code.eitanity.com/kanonarion/internal/fetch/domain"
	"code.eitanity.com/kanonarion/internal/fetch/ports"
)

// fetchPipelineSpy answers only at the current pipeline, as a store holding
// only current records does.
type fetchPipelineSpy struct{ ports.FactStore }

func (fetchPipelineSpy) GetFetchRecord(_ context.Context, _ coordinate.ModuleCoordinate, pv string) (domain.CompositeRecord, bool, error) {
	return domain.CompositeRecord{}, pv == domain.PipelineVersion, nil
}

// An empty pipeline version reads the current one; passed through, it named
// no generation and the read answered as if nothing were recorded.
func TestQueryFetch_AnEmptyPipelineVersionReadsTheCurrentOne(t *testing.T) {
	uc := application.NewQueryFetchUseCase(fetchPipelineSpy{})
	if _, ok, err := uc.GetFetchRecord(t.Context(), coordinatetest.MustNew("example.com/m", "v1.0.0"), ""); err != nil || !ok {
		t.Errorf("GetFetchRecord with no pipeline version = %v, %v; want the current record", ok, err)
	}
}
