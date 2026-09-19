package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/native/application"
	"github.com/eitanity/kanonarion/internal/native/domain"
	"github.com/eitanity/kanonarion/internal/native/ports"
)

// listingNativeStore is a store that can survey itself.
type listingNativeStore struct {
	fakeNativeStore
	sawFilter ports.NativeFilter
	rows      []ports.NativeSummary
	err       error
}

func (s *listingNativeStore) ListNativeRecords(_ context.Context, filter ports.NativeFilter) ([]ports.NativeSummary, error) {
	s.sawFilter = filter
	return s.rows, s.err
}

func TestList_PassesTheFilterThroughUntouched(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	store := &listingNativeStore{rows: []ports.NativeSummary{{Coordinate: coord, Presence: domain.PresenceAbsent}}}
	uc := application.NewQueryNativeUseCase(store)

	want := ports.NativeFilter{
		Presence:       []string{string(domain.PresenceIdentified)},
		AllGenerations: true, Limit: 7, Offset: 3,
	}
	got, err := uc.List(context.Background(), want)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].Coordinate != coord {
		t.Fatalf("List returned %+v, want the store's one row", got)
	}
	// A use case that dropped a filter field would answer a narrower question
	// with a wider corpus, and the caller would never see it happen.
	if len(store.sawFilter.Presence) != 1 || store.sawFilter.Presence[0] != string(domain.PresenceIdentified) {
		t.Errorf("presence reached the store as %v, want %v", store.sawFilter.Presence, want.Presence)
	}
	if !store.sawFilter.AllGenerations || store.sawFilter.Limit != 7 || store.sawFilter.Offset != 3 {
		t.Errorf("filter reached the store as %+v, want %+v", store.sawFilter, want)
	}
}

func TestList_StoreThatCannotSurveySaysSoRatherThanAnsweringEmpty(t *testing.T) {
	// A store with only the single-record read. Answering "no records" here
	// would report a capability gap as a measurement.
	uc := application.NewQueryNativeUseCase(&fakeNativeStore{})

	_, err := uc.List(context.Background(), ports.NativeFilter{})
	if !errors.Is(err, application.ErrNoNativeSurvey) {
		t.Fatalf("List error = %v, want ErrNoNativeSurvey", err)
	}
}

func TestList_StoreFailureIsWrappedNotSwallowed(t *testing.T) {
	boom := errors.New("disk fell over")
	uc := application.NewQueryNativeUseCase(&listingNativeStore{err: boom})

	_, err := uc.List(context.Background(), ports.NativeFilter{})
	if !errors.Is(err, boom) {
		t.Fatalf("List error = %v, want it to wrap %v", err, boom)
	}
}

func TestGet_AbsenceIsNotAnError(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("example.com/never-examined", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	uc := application.NewQueryNativeUseCase(&fakeNativeStore{})

	_, found, err := uc.Get(context.Background(), coord)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if found {
		t.Error("Get found a record in an empty store")
	}
}

func TestGet_StoreFailureIsWrappedNotReportedAsAbsence(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	boom := errors.New("two records describe two artefacts")
	uc := application.NewQueryNativeUseCase(&fakeNativeStore{getErr: boom})

	if _, _, gerr := uc.Get(context.Background(), coord); !errors.Is(gerr, boom) {
		t.Fatalf("Get error = %v, want it to wrap %v", gerr, boom)
	}
}
