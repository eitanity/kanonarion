package application_test

import (
	"context"
	"errors"
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/iface/application"
	"github.com/eitanity/kanonarion/internal/iface/domain"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
)

// queryFakeStore is a minimal InterfaceStore for QueryInterfaceUseCase tests.
type queryFakeStore struct {
	records    map[queryIfaceKey]domain.InterfaceRecord
	summaries  []ifaceports.InterfaceSummary
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
	s.records[queryIfaceKey{r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion}] = r
	return nil
}

func (s *queryFakeStore) GetInterfaceRecord(_ context.Context, coord fetchdomain.ModuleCoordinate, pv string) (domain.InterfaceRecord, bool, error) {
	if s.getErr != nil {
		return domain.InterfaceRecord{}, false, s.getErr
	}
	r, ok := s.records[queryIfaceKey{coord.Path, coord.Version, pv}]
	return r, ok, nil
}

func (s *queryFakeStore) ListInterfaceRecords(_ context.Context, _ ifaceports.InterfaceFilter) ([]ifaceports.InterfaceSummary, error) {
	return s.summaries, s.listErr
}

func (s *queryFakeStore) FindSymbol(_ context.Context, _ string, _ string) ([]ifaceports.SymbolRef, error) {
	return s.symbolRefs, s.findErr
}

var _ ifaceports.InterfaceStore = (*queryFakeStore)(nil)

func TestQueryInterfaceUseCase_GetInterfaceRecord(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
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
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
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

	coord := fetchdomain.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
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

func TestQueryInterfaceUseCase_FindSymbol(t *testing.T) {
	store := &queryFakeStore{
		symbolRefs: []ifaceports.SymbolRef{
			{ModulePath: "example.com/mod", SymbolName: "Marshal"},
		},
	}
	uc := application.NewQueryInterfaceUseCase(store)

	refs, err := uc.FindSymbol(context.Background(), "Marshal", "0.1.0")
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

	_, err := uc.FindSymbol(context.Background(), "Marshal", "0.1.0")
	if !errors.Is(err, findErr) {
		t.Errorf("got %v, want wrapping %v", err, findErr)
	}
}
