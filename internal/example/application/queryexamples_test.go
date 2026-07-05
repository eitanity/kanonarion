package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/example/application"
	"github.com/eitanity/kanonarion/internal/example/domain"
	exampleports "github.com/eitanity/kanonarion/internal/example/ports"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// queryExFakeStore is a minimal ExampleStore for QueryExamplesUseCase tests.
type queryExFakeStore struct {
	records     map[queryExKey]domain.ExampleRecord
	summaries   []exampleports.ExampleSummary
	exampleRefs []exampleports.ExampleRef
	getErr      error
	listErr     error
	findErr     error
}

type queryExKey struct{ path, version, pipeline string }

func (s *queryExFakeStore) PutExampleRecord(_ context.Context, r domain.ExampleRecord) error {
	if s.records == nil {
		s.records = make(map[queryExKey]domain.ExampleRecord)
	}
	s.records[queryExKey{r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion}] = r
	return nil
}

func (s *queryExFakeStore) GetExampleRecord(_ context.Context, coord fetchdomain.ModuleCoordinate, pv string) (domain.ExampleRecord, bool, error) {
	if s.getErr != nil {
		return domain.ExampleRecord{}, false, s.getErr
	}
	r, ok := s.records[queryExKey{coord.Path, coord.Version, pv}]
	return r, ok, nil
}

func (s *queryExFakeStore) ListExampleRecords(_ context.Context, _ exampleports.ExampleFilter) ([]exampleports.ExampleSummary, error) {
	return s.summaries, s.listErr
}

func (s *queryExFakeStore) FindBySymbol(_ context.Context, _ string, _ string) ([]exampleports.ExampleRef, error) {
	return s.exampleRefs, s.findErr
}

func (s *queryExFakeStore) FindBySymbolInModule(_ context.Context, coord fetchdomain.ModuleCoordinate, _ string, _ string) ([]exampleports.ExampleRef, error) {
	if s.findErr != nil {
		return nil, s.findErr
	}
	var out []exampleports.ExampleRef
	for _, ref := range s.exampleRefs {
		if ref.ModulePath == coord.Path && ref.ModuleVersion == coord.Version {
			out = append(out, ref)
		}
	}
	return out, nil
}

var _ exampleports.ExampleStore = (*queryExFakeStore)(nil)

func TestQueryExamplesUseCase_GetExampleRecord(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
	store := &queryExFakeStore{}
	_ = store.PutExampleRecord(context.Background(), domain.ExampleRecord{
		Coordinate:      coord,
		PipelineVersion: "0.1.0",
	})

	uc := application.NewQueryExamplesUseCase(store)

	got, found, err := uc.GetExampleRecord(context.Background(), coord, "0.1.0")
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

func TestQueryExamplesUseCase_GetExampleRecord_NotFound(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
	uc := application.NewQueryExamplesUseCase(&queryExFakeStore{})

	_, found, err := uc.GetExampleRecord(context.Background(), coord, "0.1.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("expected record not to be found")
	}
}

func TestQueryExamplesUseCase_GetExampleRecord_StoreError(t *testing.T) {
	storeErr := errors.New("db failure")
	uc := application.NewQueryExamplesUseCase(&queryExFakeStore{getErr: storeErr})

	coord := fetchdomain.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
	_, _, err := uc.GetExampleRecord(context.Background(), coord, "0.1.0")
	if !errors.Is(err, storeErr) {
		t.Errorf("got %v, want wrapping %v", err, storeErr)
	}
}

func TestQueryExamplesUseCase_ListExampleRecords(t *testing.T) {
	store := &queryExFakeStore{
		summaries: []exampleports.ExampleSummary{
			{ModulePath: "example.com/mod", ModuleVersion: "v1.0.0", ExampleCount: 3},
		},
	}
	uc := application.NewQueryExamplesUseCase(store)

	sums, err := uc.ListExampleRecords(context.Background(), exampleports.ExampleFilter{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sums) != 1 {
		t.Errorf("got %d summaries, want 1", len(sums))
	}
}

func TestQueryExamplesUseCase_FindBySymbol(t *testing.T) {
	store := &queryExFakeStore{
		exampleRefs: []exampleports.ExampleRef{
			{ModulePath: "example.com/mod", ExampleName: "ExampleMarshal"},
		},
	}
	uc := application.NewQueryExamplesUseCase(store)

	refs, err := uc.FindBySymbol(context.Background(), "Marshal", "0.1.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 1 {
		t.Errorf("got %d refs, want 1", len(refs))
	}
}

func TestQueryExamplesUseCase_FindBySymbol_Error(t *testing.T) {
	findErr := errors.New("index failure")
	uc := application.NewQueryExamplesUseCase(&queryExFakeStore{findErr: findErr})

	_, err := uc.FindBySymbol(context.Background(), "Marshal", "0.1.0")
	if !errors.Is(err, findErr) {
		t.Errorf("got %v, want wrapping %v", err, findErr)
	}
}

func TestQueryExamplesUseCase_FindBySymbolInModule(t *testing.T) {
	coordA := fetchdomain.ModuleCoordinate{Path: "example.com/a", Version: "v1.0.0"}
	coordB := fetchdomain.ModuleCoordinate{Path: "example.com/b", Version: "v1.0.0"}
	store := &queryExFakeStore{
		exampleRefs: []exampleports.ExampleRef{
			{ModulePath: coordA.Path, ModuleVersion: coordA.Version, ExampleName: "ExampleMarshal"},
			{ModulePath: coordB.Path, ModuleVersion: coordB.Version, ExampleName: "ExampleMarshal"},
		},
	}
	uc := application.NewQueryExamplesUseCase(store)

	refs, err := uc.FindBySymbolInModule(context.Background(), coordA, "Marshal", "0.1.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("expected 1 scoped ref, got %d", len(refs))
	}
	if refs[0].ModulePath != coordA.Path {
		t.Errorf("got ModulePath %q, want %q", refs[0].ModulePath, coordA.Path)
	}
}

func TestQueryExamplesUseCase_FindBySymbolInModule_Error(t *testing.T) {
	findErr := errors.New("index failure")
	uc := application.NewQueryExamplesUseCase(&queryExFakeStore{findErr: findErr})

	coord := fetchdomain.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
	_, err := uc.FindBySymbolInModule(context.Background(), coord, "Marshal", "0.1.0")
	if !errors.Is(err, findErr) {
		t.Errorf("got %v, want wrapping %v", err, findErr)
	}
}
