package application_test

import (
	"context"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	"code.eitanity.com/kanonarion/internal/iface/application"
	"code.eitanity.com/kanonarion/internal/iface/domain"
	ifaceports "code.eitanity.com/kanonarion/internal/iface/ports"
)

// interfacePipelineSpy answers only at the current pipeline, as a store
// holding only current records does.
type interfacePipelineSpy struct{ ifaceports.InterfaceStore }

func (interfacePipelineSpy) GetInterfaceRecord(_ context.Context, _ coordinate.ModuleCoordinate, pv string) (domain.InterfaceRecord, bool, error) {
	return domain.InterfaceRecord{}, pv == application.PipelineVersion, nil
}

func (interfacePipelineSpy) ListInterfaceRecordsFor(_ context.Context, _ coordinate.ModuleCoordinate, pv string) ([]domain.InterfaceRecord, error) {
	if pv != application.PipelineVersion {
		return nil, nil
	}
	return []domain.InterfaceRecord{{}}, nil
}

func (interfacePipelineSpy) FindSymbol(_ context.Context, _, pv string, _ coordinate.ModuleSet) ([]ifaceports.SymbolRef, error) {
	if pv != application.PipelineVersion {
		return nil, nil
	}
	return []ifaceports.SymbolRef{{}}, nil
}

// An empty pipeline version reads the current one; passed through, it named
// no generation and the read answered as if nothing were recorded.
func TestQueryInterface_AnEmptyPipelineVersionReadsTheCurrentOne(t *testing.T) {
	uc := application.NewQueryInterfaceUseCase(interfacePipelineSpy{})
	coord := coordinatetest.MustNew("example.com/m", "v1.0.0")
	if _, ok, err := uc.GetInterfaceRecord(t.Context(), coord, ""); err != nil || !ok {
		t.Errorf("GetInterfaceRecord with no pipeline version = %v, %v; want the current record", ok, err)
	}
	if recs, err := uc.InterfaceHistory(t.Context(), coord, ""); err != nil || len(recs) != 1 {
		t.Errorf("InterfaceHistory with no pipeline version = %v, %v; want the current generation", recs, err)
	}
	if refs, err := uc.FindSymbol(t.Context(), "example.com/m.F", "", coordinate.ModuleSet{}); err != nil || len(refs) != 1 {
		t.Errorf("FindSymbol with no pipeline version = %v, %v; want the current symbol", refs, err)
	}
}
