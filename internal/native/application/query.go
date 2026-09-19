package application

import (
	"context"
	"errors"
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

// ErrNoNativeSurvey is returned when the store this build was wired with cannot
// survey its own records. It is a different answer from "the store holds none",
// which is why it is an error and not an empty list.
var ErrNoNativeSurvey = errors.New("this native store cannot list its records")

// List returns summaries of the stored native records matching the filter.
//
// It is the read that answers "which modules ship or link native code" without
// asking about each module in turn. The generation restriction lives in the
// filter and defaults to the generation this build serves; see
// ports.NativeFilter.
func (uc *QueryNativeUseCase) List(ctx context.Context, filter ports.NativeFilter) ([]ports.NativeSummary, error) {
	lister, ok := uc.store.(ports.NativeRecordLister)
	if !ok {
		return nil, ErrNoNativeSurvey
	}
	sums, err := lister.ListNativeRecords(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("listing native records: %w", err)
	}
	return sums, nil
}
