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

// GetFetchRecord retrieves the composed fetch record for the given coordinate
// and pipeline version — the artefact as the ledger knows it, folded from every
// measurement of it, rather than any single row.
func (uc *QueryFetchUseCase) GetFetchRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain.CompositeRecord, bool, error) {
	rec, found, err := uc.store.GetFetchRecord(ctx, coord, pipelineVersion)
	if err != nil {
		return domain.CompositeRecord{}, false, fmt.Errorf("getting fetch record for %s: %w", coord, err)
	}
	return rec, found, nil
}

// ComposeFetchRecord retrieves the composed fetch record for a coordinate across
// every fetch pipeline version — what the ledger has measured about the artefact,
// naming no generation of the pipeline.
//
// It is what a reporting command wants. Pinning the read to the current fetch
// pipeline version made every module measured only under a retired one report as
// "(not fetched)" — on the maintainer's store, 1357 of 5652 coordinates — which is
// a false statement about a module whose artefact is held, not a gap in coverage.
func (uc *QueryFetchUseCase) ComposeFetchRecord(ctx context.Context, coord coordinate.ModuleCoordinate) (domain.CompositeRecord, bool, error) {
	//nolint:wrapcheck // ComposedFetchRecord already names the coordinate it read
	return ports.ComposedFetchRecord(ctx, uc.store, coord)
}
