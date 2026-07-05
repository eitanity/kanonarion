package application

import (
	"context"
	"fmt"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/iface/domain"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
)

// QueryInterfaceUseCase provides read-only access to stored interface records.
type QueryInterfaceUseCase struct {
	store ifaceports.InterfaceStore
}

// NewQueryInterfaceUseCase constructs a QueryInterfaceUseCase.
func NewQueryInterfaceUseCase(store ifaceports.InterfaceStore) *QueryInterfaceUseCase {
	return &QueryInterfaceUseCase{store: store}
}

// GetInterfaceRecord retrieves the interface record for a module coordinate.
func (uc *QueryInterfaceUseCase) GetInterfaceRecord(ctx context.Context, coord fetchdomain.ModuleCoordinate, pipelineVersion string) (domain.InterfaceRecord, bool, error) {
	rec, found, err := uc.store.GetInterfaceRecord(ctx, coord, pipelineVersion)
	if err != nil {
		return domain.InterfaceRecord{}, false, fmt.Errorf("getting interface record for %s: %w", coord, err)
	}
	return rec, found, nil
}

// ListInterfaceRecords returns summaries matching the given filter.
func (uc *QueryInterfaceUseCase) ListInterfaceRecords(ctx context.Context, filter ifaceports.InterfaceFilter) ([]ifaceports.InterfaceSummary, error) {
	sums, err := uc.store.ListInterfaceRecords(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("listing interface records: %w", err)
	}
	return sums, nil
}

// FindSymbol returns all packages that export a symbol with the given name.
func (uc *QueryInterfaceUseCase) FindSymbol(ctx context.Context, symbolName, pipelineVersion string) ([]ifaceports.SymbolRef, error) {
	refs, err := uc.store.FindSymbol(ctx, symbolName, pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("finding symbol %q: %w", symbolName, err)
	}
	return refs, nil
}
