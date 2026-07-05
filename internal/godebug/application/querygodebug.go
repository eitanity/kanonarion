package application

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/godebug/domain"
	"github.com/eitanity/kanonarion/internal/godebug/ports"
)

// QueryGoDebugUseCase is read-only access to stored godebug records, used by
// the `godebug` command and the `inspect` aggregate.
type QueryGoDebugUseCase struct {
	store ports.GoDebugStore
}

// NewQueryGoDebugUseCase constructs the query use case.
func NewQueryGoDebugUseCase(store ports.GoDebugStore) *QueryGoDebugUseCase {
	return &QueryGoDebugUseCase{store: store}
}

// Get returns the stored record for a project module path. found is false
// (no error) when the project has not been scanned — callers must surface
// that as "not analysed", never as "no settings".
func (uc *QueryGoDebugUseCase) Get(ctx context.Context, projectModulePath string) (domain.Record, bool, error) {
	rec, found, err := uc.store.GetGoDebugRecord(ctx, projectModulePath)
	if err != nil {
		return domain.Record{}, false, fmt.Errorf("querying godebug record: %w", err)
	}
	return rec, found, nil
}
