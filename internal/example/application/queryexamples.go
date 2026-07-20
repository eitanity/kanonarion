package application

import (
	"context"
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

// ListExampleRecords returns summaries matching the given filter.
func (uc *QueryExamplesUseCase) ListExampleRecords(ctx context.Context, filter exampleports.ExampleFilter) ([]exampleports.ExampleSummary, error) {
	sums, err := uc.store.ListExampleRecords(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("listing example records: %w", err)
	}
	return sums, nil
}

// FindBySymbol returns all examples associated with the given symbol.
func (uc *QueryExamplesUseCase) FindBySymbol(ctx context.Context, symbol, pipelineVersion string) ([]exampleports.ExampleRef, error) {
	refs, err := uc.store.FindBySymbol(ctx, symbol, pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("finding examples for symbol %q: %w", symbol, err)
	}
	return refs, nil
}

// FindBySymbolInModule returns examples for a symbol scoped to a specific module@version.
func (uc *QueryExamplesUseCase) FindBySymbolInModule(ctx context.Context, coord coordinate.ModuleCoordinate, symbol, pipelineVersion string) ([]exampleports.ExampleRef, error) {
	refs, err := uc.store.FindBySymbolInModule(ctx, coord, symbol, pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("finding examples for symbol %q in %s: %w", symbol, coord, err)
	}
	return refs, nil
}
