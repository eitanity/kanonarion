package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	"github.com/eitanity/kanonarion/internal/iface/application"
	"github.com/eitanity/kanonarion/internal/iface/domain"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
)

// queryFakeStore is a minimal InterfaceStore for QueryInterfaceUseCase tests.
type queryFakeStore struct {
	records    map[queryIfaceKey]domain.InterfaceRecord
	summaries  []ifaceports.InterfaceSummary
	lastFilter ifaceports.InterfaceFilter
	symbolRefs []ifaceports.SymbolRef
	getErr     error
	listErr    error
	findErr    error
}

type queryIfaceKey struct{ path, version, pipeline string }

func (s *queryFakeStore) PutInterfaceRecord(_ context.Context, r domain.InterfaceRecord) error {
	if s.records == nil {
		s.records = make(map[queryIfaceKey]domain.InterfaceRecord)
	}
	s.records[queryIfaceKey{r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion}] = r
	return nil
}

func (s *queryFakeStore) GetInterfaceRecord(_ context.Context, coord coordinate.ModuleCoordinate, pv string) (domain.InterfaceRecord, bool, error) {
	if s.getErr != nil {
		return domain.InterfaceRecord{}, false, s.getErr
	}
	r, ok := s.records[queryIfaceKey{coord.Path(), coord.Version(), pv}]
	return r, ok, nil
}

func (s *queryFakeStore) ListInterfaceRecords(_ context.Context, filter ifaceports.InterfaceFilter) ([]ifaceports.InterfaceSummary, error) {
	s.lastFilter = filter
	if filter.Coordinate == nil {
		return s.summaries, s.listErr
	}
	out := make([]ifaceports.InterfaceSummary, 0, len(s.summaries))
	for _, sum := range s.summaries {
		if sum.ModulePath == filter.Coordinate.Path() && sum.ModuleVersion == filter.Coordinate.Version() {
			out = append(out, sum)
		}
	}
	return out, s.listErr
}

func (s *queryFakeStore) FindSymbol(_ context.Context, _ string, _ string, _ coordinate.ModuleSet) ([]ifaceports.SymbolRef, error) {
	return s.symbolRefs, s.findErr
}

var _ ifaceports.InterfaceStore = (*queryFakeStore)(nil)

func TestQueryInterfaceUseCase_GetInterfaceRecord(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	store := &queryFakeStore{}
	_ = store.PutInterfaceRecord(context.Background(), domain.InterfaceRecord{
		Coordinate:      coord,
		PipelineVersion: "0.1.0",
	})

	uc := application.NewQueryInterfaceUseCase(store)

	got, found, err := uc.GetInterfaceRecord(context.Background(), coord, "0.1.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Fatal("expected record to be found")
	}
	if got.Coordinate != coord {
		t.Errorf("got coordinate %v, want %v", got.Coordinate, coord)
	}
}

func TestQueryInterfaceUseCase_GetInterfaceRecord_NotFound(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	uc := application.NewQueryInterfaceUseCase(&queryFakeStore{})

	_, found, err := uc.GetInterfaceRecord(context.Background(), coord, "0.1.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("expected record not to be found")
	}
}

func TestQueryInterfaceUseCase_GetInterfaceRecord_StoreError(t *testing.T) {
	storeErr := errors.New("db failure")
	uc := application.NewQueryInterfaceUseCase(&queryFakeStore{getErr: storeErr})

	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	_, _, err := uc.GetInterfaceRecord(context.Background(), coord, "0.1.0")
	if !errors.Is(err, storeErr) {
		t.Errorf("got %v, want wrapping %v", err, storeErr)
	}
}

func TestQueryInterfaceUseCase_ListInterfaceRecords(t *testing.T) {
	store := &queryFakeStore{
		summaries: []ifaceports.InterfaceSummary{
			{ModulePath: "example.com/mod", ModuleVersion: "v1.0.0"},
		},
	}
	uc := application.NewQueryInterfaceUseCase(store)

	sums, err := uc.ListInterfaceRecords(context.Background(), ifaceports.InterfaceFilter{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sums) != 1 {
		t.Errorf("got %d summaries, want 1", len(sums))
	}
}

// The use case must hand the filter to the store unchanged. A pass-through that
// dropped a field would leave every caller asking a question the store never
// heard, and the answer would still look right — just read from the whole corpus.
func TestQueryInterfaceUseCase_ListInterfaceRecords_PassesTheFilterThrough(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	store := &queryFakeStore{
		summaries: []ifaceports.InterfaceSummary{
			{ModulePath: "example.com/mod", ModuleVersion: "v1.0.0"},
			{ModulePath: "example.com/other", ModuleVersion: "v2.0.0"},
		},
	}
	uc := application.NewQueryInterfaceUseCase(store)

	sums, err := uc.ListInterfaceRecords(context.Background(), ifaceports.InterfaceFilter{Coordinate: &coord})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store.lastFilter.Coordinate == nil {
		t.Fatal("the coordinate was dropped on the way to the store")
	}
	if store.lastFilter.Coordinate.String() != coord.String() {
		t.Errorf("the store was asked about %s, want %s", store.lastFilter.Coordinate, coord)
	}
	if len(sums) != 1 {
		t.Errorf("got %d summaries, want 1", len(sums))
	}
}

func TestQueryInterfaceUseCase_FindSymbol(t *testing.T) {
	store := &queryFakeStore{
		symbolRefs: []ifaceports.SymbolRef{
			{ModulePath: "example.com/mod", SymbolName: "Marshal"},
		},
	}
	uc := application.NewQueryInterfaceUseCase(store)

	refs, err := uc.FindSymbol(context.Background(), "Marshal", "0.1.0", coordinate.ModuleSet{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 1 {
		t.Errorf("got %d refs, want 1", len(refs))
	}
}

func TestQueryInterfaceUseCase_FindSymbol_Error(t *testing.T) {
	findErr := errors.New("index failure")
	uc := application.NewQueryInterfaceUseCase(&queryFakeStore{findErr: findErr})

	_, err := uc.FindSymbol(context.Background(), "Marshal", "0.1.0", coordinate.ModuleSet{})
	if !errors.Is(err, findErr) {
		t.Errorf("got %v, want wrapping %v", err, findErr)
	}
}
