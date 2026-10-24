package application_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	"github.com/eitanity/kanonarion/internal/license/application"
)

// pipelineListingStore is a store that can list the pipelines a coordinate is
// held at.
type pipelineListingStore struct {
	*queryLicFakeStore
	held []string
	err  error
}

func (s pipelineListingStore) PipelinesHeld(context.Context, coordinate.ModuleCoordinate) ([]string, error) {
	return s.held, s.err
}

// PipelinesHeld passes the store's answer through, wraps its fault, and names a
// store that cannot list rather than answering "none held".
func TestQueryLicensePipelinesHeld(t *testing.T) {
	ctx := context.Background()
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	got, err := application.NewQueryLicenseUseCase(pipelineListingStore{queryLicFakeStore: &queryLicFakeStore{}, held: []string{"1.3.0"}}).PipelinesHeld(ctx, coord)
	if err != nil || !slices.Equal(got, []string{"1.3.0"}) {
		t.Errorf("PipelinesHeld = %v, %v", got, err)
	}
	storeErr := errors.New("disk")
	if _, err := application.NewQueryLicenseUseCase(pipelineListingStore{queryLicFakeStore: &queryLicFakeStore{}, err: storeErr}).PipelinesHeld(ctx, coord); !errors.Is(err, storeErr) {
		t.Errorf("store fault = %v, want it wrapped", err)
	}
	if _, err := application.NewQueryLicenseUseCase(&queryLicFakeStore{}).PipelinesHeld(ctx, coord); !errors.Is(err, application.ErrNoPipelineListing) {
		t.Errorf("a store that cannot list = %v, want ErrNoPipelineListing", err)
	}
}
