package application

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/sbom/domain"
	sbomports "github.com/eitanity/kanonarion/internal/sbom/ports"
)

// QuerySBOMUseCase provides read-only access to stored SBOM records.
type QuerySBOMUseCase struct {
	store sbomports.SBOMStore
}

// NewQuerySBOMUseCase constructs a QuerySBOMUseCase.
func NewQuerySBOMUseCase(store sbomports.SBOMStore) *QuerySBOMUseCase {
	return &QuerySBOMUseCase{store: store}
}

// GetSBOMRecord retrieves an SBOM record by ID.
func (uc *QuerySBOMUseCase) GetSBOMRecord(ctx context.Context, id string) (domain.SBOMRecord, error) {
	rec, err := uc.store.GetSBOMRecord(ctx, id)
	if err != nil {
		return domain.SBOMRecord{}, fmt.Errorf("getting sbom %s: %w", id, err)
	}
	return rec, nil
}

// ListSBOMRecords returns all SBOM records for a walk, most recent first.
func (uc *QuerySBOMUseCase) ListSBOMRecords(ctx context.Context, walkID string) ([]domain.SBOMRecord, error) {
	recs, err := uc.store.ListSBOMRecords(ctx, walkID)
	if err != nil {
		return nil, fmt.Errorf("listing sbom records: %w", err)
	}
	return recs, nil
}
