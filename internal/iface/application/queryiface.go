package application

import (
	"context"
	"errors"
	"fmt"

	"code.eitanity.com/kanonarion/internal/coordinate"

	"code.eitanity.com/kanonarion/internal/iface/domain"
	ifaceports "code.eitanity.com/kanonarion/internal/iface/ports"
)

// QueryInterfaceUseCase provides read-only access to stored interface records.
//
// Every method that takes a pipeline version reads PipelineVersion when given
// an empty one.
type QueryInterfaceUseCase struct {
	store ifaceports.InterfaceStore
}

// NewQueryInterfaceUseCase constructs a QueryInterfaceUseCase.
func NewQueryInterfaceUseCase(store ifaceports.InterfaceStore) *QueryInterfaceUseCase {
	return &QueryInterfaceUseCase{store: store}
}

// GetInterfaceRecord retrieves the interface record for a module coordinate.
func (uc *QueryInterfaceUseCase) GetInterfaceRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain.InterfaceRecord, bool, error) {
	pipelineVersion = servedPipeline(pipelineVersion)
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
	pipelineVersion = servedPipeline(pipelineVersion)
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

// ListInterfaceGenerations names every generation the ledger holds. A store
// without the column read answers from its summaries, which compose.
func (uc *QueryInterfaceUseCase) ListInterfaceGenerations(ctx context.Context) ([]ifaceports.InterfaceGeneration, error) {
	if lister, ok := uc.store.(ifaceports.InterfaceGenerationLister); ok {
		gens, err := lister.ListInterfaceGenerations(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing interface generations: %w", err)
		}
		return gens, nil
	}
	sums, err := uc.store.ListInterfaceRecords(ctx, ifaceports.InterfaceFilter{})
	if err != nil {
		return nil, fmt.Errorf("listing interface records: %w", err)
	}
	gens := make([]ifaceports.InterfaceGeneration, 0, len(sums))
	for _, s := range sums {
		gens = append(gens, ifaceports.InterfaceGeneration{
			ModulePath: s.ModulePath, ModuleVersion: s.ModuleVersion, PipelineVersion: s.PipelineVersion,
		})
	}
	return gens, nil
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
	pipelineVersion = servedPipeline(pipelineVersion)
	refs, err := uc.store.FindSymbol(ctx, symbolName, pipelineVersion, scope)
	if errors.Is(err, ifaceports.ErrInterfaceConflict) {
		return refs, fmt.Errorf("finding symbol %q: %w", symbolName, err)
	}
	if err != nil {
		return nil, fmt.Errorf("finding symbol %q: %w", symbolName, err)
	}
	return refs, nil
}

// servedPipeline is pv, or PipelineVersion when pv is empty. No record is
// stored at an empty version, so an empty one would read nothing and answer
// as if nothing were recorded.
func servedPipeline(pv string) string {
	if pv == "" {
		return PipelineVersion
	}
	return pv
}
