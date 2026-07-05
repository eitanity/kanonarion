package application

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/fips/domain"
	"github.com/eitanity/kanonarion/internal/fips/ports"
)

// QueryFIPSUseCase is read-only access to stored FIPS records.
type QueryFIPSUseCase struct {
	store ports.FIPSStore
}

// NewQueryFIPSUseCase constructs the query use case.
func NewQueryFIPSUseCase(store ports.FIPSStore) *QueryFIPSUseCase {
	return &QueryFIPSUseCase{store: store}
}

// Get returns the stored record for a project module path. found is false
// (no error) when the project has not been scanned — callers must surface
// that as "not analysed", never as "no FIPS issues".
func (uc *QueryFIPSUseCase) Get(ctx context.Context, projectModulePath string) (domain.Record, bool, error) {
	rec, found, err := uc.store.GetFIPSRecord(ctx, projectModulePath)
	if err != nil {
		return domain.Record{}, false, fmt.Errorf("querying fips record: %w", err)
	}
	return rec, found, nil
}
