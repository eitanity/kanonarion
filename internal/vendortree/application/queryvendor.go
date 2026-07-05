package application

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/vendortree/domain"
	"github.com/eitanity/kanonarion/internal/vendortree/ports"
)

// QueryVendorUseCase is read-only access to stored vendor records, used by
// the `vendor` command and the `inspect` aggregate.
type QueryVendorUseCase struct {
	store ports.VendorStore
}

// NewQueryVendorUseCase constructs the query use case.
func NewQueryVendorUseCase(store ports.VendorStore) *QueryVendorUseCase {
	return &QueryVendorUseCase{store: store}
}

// Get returns the stored record for a project module path. found is false
// (no error) when the project has not been scanned — callers must surface
// that as "not analysed", never as "no findings / clean".
func (uc *QueryVendorUseCase) Get(ctx context.Context, projectModulePath string) (domain.Record, bool, error) {
	rec, found, err := uc.store.GetVendorRecord(ctx, projectModulePath)
	if err != nil {
		return domain.Record{}, false, fmt.Errorf("querying vendor record: %w", err)
	}
	return rec, found, nil
}
