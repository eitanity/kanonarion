package application

import (
	"context"
	"fmt"

	"code.eitanity.com/kanonarion/internal/coordinate"

	"code.eitanity.com/kanonarion/internal/fetch/domain"
	"code.eitanity.com/kanonarion/internal/fetch/ports"
)

// QueryFetchUseCase provides read-only access to stored fetch (fact) records.
//
// Every method that takes a pipeline version reads PipelineVersion when given
// an empty one.
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
	pipelineVersion = servedPipeline(pipelineVersion)
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

// SupersededArtefacts names the artefacts of coord the ledger holds only as
// local-source measurements under a published coordinate, so a history view
// can say which of its generations no read composes.
func (uc *QueryFetchUseCase) SupersededArtefacts(ctx context.Context, coord coordinate.ModuleCoordinate) (map[string]bool, error) {
	//nolint:wrapcheck // SupersededArtefactsOf already names the coordinate it read
	return ports.SupersededArtefactsOf(ctx, uc.store, coord)
}

// servedPipeline is pv, or domain.PipelineVersion when pv is empty. No record is
// stored at an empty version, so an empty one would read nothing and answer
// as if nothing were recorded.
func servedPipeline(pv string) string {
	if pv == "" {
		return domain.PipelineVersion
	}
	return pv
}
