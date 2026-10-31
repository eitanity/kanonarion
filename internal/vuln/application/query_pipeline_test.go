package application_test

import (
	"context"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	"code.eitanity.com/kanonarion/internal/vuln/application"
	"code.eitanity.com/kanonarion/internal/vuln/domain"
	"code.eitanity.com/kanonarion/internal/vuln/ports"
)

// vulnPipelineSpy answers only at the current pipeline, as a store holding
// only current records does.
type vulnPipelineSpy struct{ ports.VulnerabilityStore }

func (vulnPipelineSpy) records(pv string) []domain.VulnerabilityRecord {
	if pv != application.PipelineVersion {
		return nil
	}
	return []domain.VulnerabilityRecord{{}}
}

func (s vulnPipelineSpy) ListVulnerabilityRecordsForModuleInWalk(_ context.Context, _ coordinate.ModuleCoordinate, pv, _ string) ([]domain.VulnerabilityRecord, error) {
	return s.records(pv), nil
}

func (s vulnPipelineSpy) ListVulnerabilityRecordsForModule(_ context.Context, _ coordinate.ModuleCoordinate, pv string) ([]domain.VulnerabilityRecord, error) {
	return s.records(pv), nil
}

// An empty pipeline version reads the current one; passed through, it named
// no generation and the read answered as if nothing were recorded.
func TestQueryVuln_AnEmptyPipelineVersionReadsTheCurrentOne(t *testing.T) {
	uc := application.NewQueryVulnUseCase(vulnPipelineSpy{})
	coord := coordinatetest.MustNew("example.com/m", "v1.0.0")
	if recs, err := uc.ListRecordsForModuleInWalk(t.Context(), coord, "", "w"); err != nil || len(recs) != 1 {
		t.Errorf("ListRecordsForModuleInWalk with no pipeline version = %v, %v; want the current record", recs, err)
	}
	if recs, err := uc.ListRecordsForModule(t.Context(), coord, ""); err != nil || len(recs) != 1 {
		t.Errorf("ListRecordsForModule with no pipeline version = %v, %v; want the current record", recs, err)
	}
}
