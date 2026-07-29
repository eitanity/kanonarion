package application

import (
	"context"
	"errors"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"

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
func (uc *QueryInterfaceUseCase) GetInterfaceRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain.InterfaceRecord, bool, error) {
	rec, found, err := uc.store.GetInterfaceRecord(ctx, coord, pipelineVersion)
	if err != nil {
		return domain.InterfaceRecord{}, false, fmt.Errorf("getting interface record for %s: %w", coord, err)
	}
	return rec, found, nil
}

// ErrNoInterfaceHistory is returned by InterfaceHistory when the configured
// store cannot produce one. It is not "there is no history": it says the store
// this build was wired with does not keep generations, which is a different
// answer from a module that has only ever been extracted once.
var ErrNoInterfaceHistory = errors.New("this interface store keeps no generation history")

// InterfaceHistory returns every generation the ledger holds for a coordinate,
// in the order they were appended, oldest first.
//
// This is the read that an overwriting store could not answer, and it is where a
// reported non-determination becomes examinable: both records that disagree are
// still here, each naming the artefact it was computed from.
func (uc *QueryInterfaceUseCase) InterfaceHistory(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]domain.InterfaceRecord, error) {
	lister, ok := uc.store.(ifaceports.InterfaceRecordLister)
	if !ok {
		return nil, ErrNoInterfaceHistory
	}
	recs, err := lister.ListInterfaceRecordsFor(ctx, coord, pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("listing interface generations for %s: %w", coord, err)
	}
	return recs, nil
}

// ListInterfaceRecords returns summaries matching the given filter.
func (uc *QueryInterfaceUseCase) ListInterfaceRecords(ctx context.Context, filter ifaceports.InterfaceFilter) ([]ifaceports.InterfaceSummary, error) {
	sums, err := uc.store.ListInterfaceRecords(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("listing interface records: %w", err)
	}
	return sums, nil
}

// FindSymbol returns all packages that export a symbol with the given name,
// restricted to the modules in scope (the zero ModuleSet imposes no restriction).
//
// A conflict is returned ALONGSIDE the refs, not instead of them. The store omits
// a module whose records composition refused to pick between and reports the
// omission; discarding the refs here would let one disputed module delete every
// other module's answer, which is the failure the ledger's conflict handling
// exists to avoid. Callers render what they got and then fail.
func (uc *QueryInterfaceUseCase) FindSymbol(ctx context.Context, symbolName, pipelineVersion string, scope coordinate.ModuleSet) ([]ifaceports.SymbolRef, error) {
	refs, err := uc.store.FindSymbol(ctx, symbolName, pipelineVersion, scope)
	if errors.Is(err, ifaceports.ErrInterfaceConflict) {
		return refs, fmt.Errorf("finding symbol %q: %w", symbolName, err)
	}
	if err != nil {
		return nil, fmt.Errorf("finding symbol %q: %w", symbolName, err)
	}
	return refs, nil
}
