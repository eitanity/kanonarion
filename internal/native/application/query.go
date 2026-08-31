package application

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/native/domain"
	"github.com/eitanity/kanonarion/internal/native/ports"
)

// QueryNativeUseCase is read-only access to stored native-component records.
type QueryNativeUseCase struct {
	store ports.NativeStore
}

// NewQueryNativeUseCase constructs the query use case.
func NewQueryNativeUseCase(store ports.NativeStore) *QueryNativeUseCase {
	return &QueryNativeUseCase{store: store}
}

// Get returns the stored record for a coordinate. found is false (with no
// error) when the module has not been examined at this generation — callers
// must surface that as "not examined", never as "no native component".
func (uc *QueryNativeUseCase) Get(ctx context.Context, coord coordinate.ModuleCoordinate) (domain.Record, bool, error) {
	rec, found, err := uc.store.GetNativeRecord(ctx, coord)
	if err != nil {
		return domain.Record{}, false, fmt.Errorf("querying native record: %w", err)
	}
	return rec, found, nil
}
