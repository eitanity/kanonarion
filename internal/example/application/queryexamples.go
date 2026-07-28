package application

import (
	"context"
	"errors"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/example/domain"
	exampleports "github.com/eitanity/kanonarion/internal/example/ports"
)

// QueryExamplesUseCase provides read-only access to stored example records.
type QueryExamplesUseCase struct {
	store exampleports.ExampleStore
}

// NewQueryExamplesUseCase constructs a QueryExamplesUseCase.
func NewQueryExamplesUseCase(store exampleports.ExampleStore) *QueryExamplesUseCase {
	return &QueryExamplesUseCase{store: store}
}

// GetExampleRecord retrieves the example record for a module coordinate.
func (uc *QueryExamplesUseCase) GetExampleRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain.ExampleRecord, bool, error) {
	rec, found, err := uc.store.GetExampleRecord(ctx, coord, pipelineVersion)
	if err != nil {
		return domain.ExampleRecord{}, false, fmt.Errorf("getting example record for %s: %w", coord, err)
	}
	return rec, found, nil
}

// ErrNoExampleHistory is returned by ExampleHistory when the configured store
// cannot produce one. It is not "there is no history": it says the store this
// build was wired with does not keep generations, which is a different answer
// from a module that has only ever been extracted once.
var ErrNoExampleHistory = errors.New("this example store keeps no generation history")

// ExampleHistory returns every generation the ledger holds for a coordinate, in
// the order they were appended, oldest first.
//
// This is the read that an overwriting store could not answer. The composed
// record says what is found now; this says what was found before, each entry
// naming the artefact it was computed from.
func (uc *QueryExamplesUseCase) ExampleHistory(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]domain.ExampleRecord, error) {
	lister, ok := uc.store.(exampleports.ExampleRecordLister)
	if !ok {
		return nil, ErrNoExampleHistory
	}
	recs, err := lister.ListExampleRecordsFor(ctx, coord, pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("listing example generations for %s: %w", coord, err)
	}
	return recs, nil
}

// ListExampleRecords returns summaries matching the given filter.
func (uc *QueryExamplesUseCase) ListExampleRecords(ctx context.Context, filter exampleports.ExampleFilter) ([]exampleports.ExampleSummary, error) {
	sums, err := uc.store.ListExampleRecords(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("listing example records: %w", err)
	}
	return sums, nil
}

// FindBySymbol returns all examples associated with the given symbol,
// restricted to the modules in scope (the zero ModuleSet imposes no
// restriction).
func (uc *QueryExamplesUseCase) FindBySymbol(ctx context.Context, symbol, pipelineVersion string, scope coordinate.ModuleSet) ([]exampleports.ExampleRef, error) {
	refs, err := uc.store.FindBySymbol(ctx, symbol, pipelineVersion, scope)
	if errors.Is(err, exampleports.ErrExampleConflict) {
		// Returned ALONGSIDE the refs, not instead of them: the store omits a
		// module whose records composition refused to pick between and reports the
		// omission, and discarding the refs here would let one disputed module
		// delete every other module's answer.
		return refs, fmt.Errorf("finding examples for symbol %q: %w", symbol, err)
	}
	if err != nil {
		return nil, fmt.Errorf("finding examples for symbol %q: %w", symbol, err)
	}
	return refs, nil
}

// FindBySymbolInModule returns examples for a symbol scoped to a specific module@version.
func (uc *QueryExamplesUseCase) FindBySymbolInModule(ctx context.Context, coord coordinate.ModuleCoordinate, symbol, pipelineVersion string) ([]exampleports.ExampleRef, error) {
	refs, err := uc.store.FindBySymbolInModule(ctx, coord, symbol, pipelineVersion)
	if errors.Is(err, exampleports.ErrExampleConflict) {
		return refs, fmt.Errorf("finding examples for symbol %q in %s: %w", symbol, coord, err)
	}
	if err != nil {
		return nil, fmt.Errorf("finding examples for symbol %q in %s: %w", symbol, coord, err)
	}
	return refs, nil
}
