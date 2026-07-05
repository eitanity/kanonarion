package application

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/extract/domain"
	extractports "github.com/eitanity/kanonarion/internal/extract/ports"
)

// QueryExtractionUseCase provides read-only access to stored extraction runs.
type QueryExtractionUseCase struct {
	store extractports.ExtractionStore
}

// NewQueryExtractionUseCase constructs a QueryExtractionUseCase.
func NewQueryExtractionUseCase(store extractports.ExtractionStore) *QueryExtractionUseCase {
	return &QueryExtractionUseCase{store: store}
}

// GetExtractionRun retrieves an extraction run by ID.
func (uc *QueryExtractionUseCase) GetExtractionRun(ctx context.Context, id string) (domain.ExtractionRun, error) {
	run, err := uc.store.GetExtractionRun(ctx, id)
	if err != nil {
		return domain.ExtractionRun{}, fmt.Errorf("getting extraction run %s: %w", id, err)
	}
	return run, nil
}

// ListExtractionRuns returns summaries matching the given filter.
func (uc *QueryExtractionUseCase) ListExtractionRuns(ctx context.Context, filter extractports.ExtractionRunFilter) ([]extractports.ExtractionRunSummary, error) {
	sums, err := uc.store.ListExtractionRuns(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("listing extraction runs: %w", err)
	}
	return sums, nil
}
