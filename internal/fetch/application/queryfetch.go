package application

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// QueryFetchUseCase provides read-only access to stored fetch (fact) records.
type QueryFetchUseCase struct {
	store ports.FactStore
}

// NewQueryFetchUseCase constructs a QueryFetchUseCase.
func NewQueryFetchUseCase(store ports.FactStore) *QueryFetchUseCase {
	return &QueryFetchUseCase{store: store}
}

// GetFetchRecord retrieves the fact record for the given coordinate and pipeline version.
func (uc *QueryFetchUseCase) GetFetchRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain.FactRecord, bool, error) {
	rec, found, err := uc.store.GetFetchRecord(ctx, coord, pipelineVersion)
	if err != nil {
		return domain.FactRecord{}, false, fmt.Errorf("getting fetch record for %s: %w", coord, err)
	}
	return rec, found, nil
}
