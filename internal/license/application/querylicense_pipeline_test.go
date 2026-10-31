package application_test

import (
	"context"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	"code.eitanity.com/kanonarion/internal/license/application"
	"code.eitanity.com/kanonarion/internal/license/domain"
	licenseports "code.eitanity.com/kanonarion/internal/license/ports"
)

// licencePipelineSpy answers only at the current pipeline, as a store holding
// only current records does.
type licencePipelineSpy struct{ licenseports.LicenseStore }

func (licencePipelineSpy) GetLicenseRecord(_ context.Context, _ coordinate.ModuleCoordinate, pv string) (domain.LicenseRecord, bool, error) {
	return domain.LicenseRecord{}, pv == application.PipelineVersion, nil
}

func (licencePipelineSpy) ListLicenseRecordsFor(_ context.Context, _ coordinate.ModuleCoordinate, pv string) ([]domain.LicenseRecord, error) {
	if pv != application.PipelineVersion {
		return nil, nil
	}
	return []domain.LicenseRecord{{}}, nil
}

// An empty pipeline version reads the current one; passed through, it named
// no generation and the read answered as if nothing were recorded.
func TestQueryLicense_AnEmptyPipelineVersionReadsTheCurrentOne(t *testing.T) {
	uc := application.NewQueryLicenseUseCase(licencePipelineSpy{})
	coord := coordinatetest.MustNew("example.com/m", "v1.0.0")
	if _, ok, err := uc.GetLicenseRecord(t.Context(), coord, ""); err != nil || !ok {
		t.Errorf("GetLicenseRecord with no pipeline version = %v, %v; want the current record", ok, err)
	}
	if recs, err := uc.LicenseHistory(t.Context(), coord, ""); err != nil || len(recs) != 1 {
		t.Errorf("LicenseHistory with no pipeline version = %v, %v; want the current generation", recs, err)
	}
}
