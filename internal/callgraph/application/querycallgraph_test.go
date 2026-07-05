package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/application"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// queryCGFakeStore is a minimal CallGraphStore for QueryCallGraphUseCase tests.
type queryCGFakeStore struct {
	records   map[queryCGKey]domain.CallGraphRecord
	summaries []cgports.CallGraphSummary
	callers   map[string][]cgports.CallEdgeRef
	callees   map[string][]cgports.CallEdgeRef
	getErr    error
	listErr   error
	edgeErr   error
}

type queryCGKey struct{ path, version, pipeline string }

func (s *queryCGFakeStore) PutCallGraphRecord(_ context.Context, r domain.CallGraphRecord) error {
	if s.records == nil {
		s.records = make(map[queryCGKey]domain.CallGraphRecord)
	}
	s.records[queryCGKey{r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion}] = r
	return nil
}

func (s *queryCGFakeStore) GetCallGraphRecord(_ context.Context, coord fetchdomain.ModuleCoordinate, pv string) (domain.CallGraphRecord, bool, error) {
	if s.getErr != nil {
		return domain.CallGraphRecord{}, false, s.getErr
	}
	r, ok := s.records[queryCGKey{coord.Path, coord.Version, pv}]
	return r, ok, nil
}

func (s *queryCGFakeStore) ListCallGraphRecords(_ context.Context, _ cgports.CallGraphFilter) ([]cgports.CallGraphSummary, error) {
	return s.summaries, s.listErr
}

func (s *queryCGFakeStore) FindCallers(_ context.Context, sym, _ string) ([]cgports.CallEdgeRef, error) {
	if s.edgeErr != nil {
		return nil, s.edgeErr
	}
	return s.callers[sym], nil
}

func (s *queryCGFakeStore) FindCallees(_ context.Context, sym, _ string) ([]cgports.CallEdgeRef, error) {
	if s.edgeErr != nil {
		return nil, s.edgeErr
	}
	return s.callees[sym], nil
}

var _ cgports.CallGraphStore = (*queryCGFakeStore)(nil)

func TestQueryCallGraphUseCase_GetCallGraphRecord(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
	store := &queryCGFakeStore{}
	_ = store.PutCallGraphRecord(context.Background(), domain.CallGraphRecord{
		Coordinate:      coord,
		PipelineVersion: "0.1.0",
	})

	uc := application.NewQueryCallGraphUseCase(store)

	got, found, err := uc.GetCallGraphRecord(context.Background(), coord, "0.1.0")
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

func TestQueryCallGraphUseCase_GetCallGraphRecord_NotFound(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
	uc := application.NewQueryCallGraphUseCase(&queryCGFakeStore{})

	_, found, err := uc.GetCallGraphRecord(context.Background(), coord, "0.1.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("expected record not to be found")
	}
}

func TestQueryCallGraphUseCase_GetCallGraphRecord_StoreError(t *testing.T) {
	storeErr := errors.New("db failure")
	uc := application.NewQueryCallGraphUseCase(&queryCGFakeStore{getErr: storeErr})

	coord := fetchdomain.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
	_, _, err := uc.GetCallGraphRecord(context.Background(), coord, "0.1.0")
	if !errors.Is(err, storeErr) {
		t.Errorf("got %v, want wrapping %v", err, storeErr)
	}
}

func TestQueryCallGraphUseCase_ListCallGraphRecords(t *testing.T) {
	store := &queryCGFakeStore{
		summaries: []cgports.CallGraphSummary{
			{ModulePath: "example.com/mod", ModuleVersion: "v1.0.0", NodeCount: 42},
		},
	}
	uc := application.NewQueryCallGraphUseCase(store)

	sums, err := uc.ListCallGraphRecords(context.Background(), cgports.CallGraphFilter{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sums) != 1 {
		t.Errorf("got %d summaries, want 1", len(sums))
	}
}

func TestQueryCallGraphUseCase_ListCallGraphRecords_Error(t *testing.T) {
	listErr := errors.New("db failure")
	uc := application.NewQueryCallGraphUseCase(&queryCGFakeStore{listErr: listErr})

	_, err := uc.ListCallGraphRecords(context.Background(), cgports.CallGraphFilter{})
	if !errors.Is(err, listErr) {
		t.Errorf("got %v, want wrapping %v", err, listErr)
	}
}

func TestQueryCallGraphUseCase_FindCallers(t *testing.T) {
	store := &queryCGFakeStore{
		callers: map[string][]cgports.CallEdgeRef{
			"pkg.Foo": {{FromID: "pkg.Bar", ToID: "pkg.Foo", ModulePath: "example.com/mod"}},
		},
	}
	uc := application.NewQueryCallGraphUseCase(store)

	refs, err := uc.FindCallers(context.Background(), "pkg.Foo", "0.1.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 1 || refs[0].FromID != "pkg.Bar" {
		t.Errorf("unexpected refs: %v", refs)
	}
}

func TestQueryCallGraphUseCase_FindCallers_Error(t *testing.T) {
	edgeErr := errors.New("edge db failure")
	uc := application.NewQueryCallGraphUseCase(&queryCGFakeStore{edgeErr: edgeErr})

	_, err := uc.FindCallers(context.Background(), "pkg.Foo", "0.1.0")
	if !errors.Is(err, edgeErr) {
		t.Errorf("got %v, want wrapping %v", err, edgeErr)
	}
}

func TestQueryCallGraphUseCase_FindCallees(t *testing.T) {
	store := &queryCGFakeStore{
		callees: map[string][]cgports.CallEdgeRef{
			"pkg.Foo": {{FromID: "pkg.Foo", ToID: "pkg.Bar", ModulePath: "example.com/mod"}},
		},
	}
	uc := application.NewQueryCallGraphUseCase(store)

	refs, err := uc.FindCallees(context.Background(), "pkg.Foo", "0.1.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 1 || refs[0].ToID != "pkg.Bar" {
		t.Errorf("unexpected refs: %v", refs)
	}
}

func TestQueryCallGraphUseCase_TraverseCallers(t *testing.T) {
	// A -> B -> C (caller direction: C calls B, B calls A)
	store := &queryCGFakeStore{
		callers: map[string][]cgports.CallEdgeRef{
			"A": {{FromID: "B", ToID: "A", ModulePath: "m"}},
			"B": {{FromID: "C", ToID: "B", ModulePath: "m"}},
		},
	}
	uc := application.NewQueryCallGraphUseCase(store)

	edges, nodes, err := uc.TraverseCallers(context.Background(), "A", "0.1.0", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 2 {
		t.Errorf("got %d nodes, want 2: %v", len(nodes), nodes)
	}
	if len(edges) != 2 {
		t.Errorf("got %d edges, want 2", len(edges))
	}
}

func TestQueryCallGraphUseCase_TraverseCallers_MaxDepth(t *testing.T) {
	store := &queryCGFakeStore{
		callers: map[string][]cgports.CallEdgeRef{
			"A": {{FromID: "B", ToID: "A", ModulePath: "m"}},
			"B": {{FromID: "C", ToID: "B", ModulePath: "m"}},
		},
	}
	uc := application.NewQueryCallGraphUseCase(store)

	_, nodes, err := uc.TraverseCallers(context.Background(), "A", "0.1.0", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 || nodes[0] != "B" {
		t.Errorf("got nodes %v, want [B]", nodes)
	}
}

func TestQueryCallGraphUseCase_TraverseCallees(t *testing.T) {
	store := &queryCGFakeStore{
		callees: map[string][]cgports.CallEdgeRef{
			"A": {{FromID: "A", ToID: "B", ModulePath: "m"}},
			"B": {{FromID: "B", ToID: "C", ModulePath: "m"}},
		},
	}
	uc := application.NewQueryCallGraphUseCase(store)

	edges, nodes, err := uc.TraverseCallees(context.Background(), "A", "0.1.0", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 2 {
		t.Errorf("got %d nodes, want 2: %v", len(nodes), nodes)
	}
	if len(edges) != 2 {
		t.Errorf("got %d edges, want 2", len(edges))
	}
}
