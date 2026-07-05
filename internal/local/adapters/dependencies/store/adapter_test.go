package store_test

import (
	"context"
	"errors"
	"testing"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/local/adapters/dependencies/store"
	"github.com/eitanity/kanonarion/internal/local/ports"
)

// fakeCallGraphStore is a minimal in-memory implementation of cgports.CallGraphStore.
type fakeCallGraphStore struct {
	records map[cgKey]callgraphdomain.CallGraphRecord
	getErr  error
}

type cgKey struct{ path, version, pipeline string }

func (s *fakeCallGraphStore) PutCallGraphRecord(_ context.Context, r callgraphdomain.CallGraphRecord) error {
	if s.records == nil {
		s.records = make(map[cgKey]callgraphdomain.CallGraphRecord)
	}
	s.records[cgKey{r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion}] = r
	return nil
}

func (s *fakeCallGraphStore) GetCallGraphRecord(_ context.Context, coord fetchdomain.ModuleCoordinate, pv string) (callgraphdomain.CallGraphRecord, bool, error) {
	if s.getErr != nil {
		return callgraphdomain.CallGraphRecord{}, false, s.getErr
	}
	if s.records == nil {
		return callgraphdomain.CallGraphRecord{}, false, nil
	}
	r, ok := s.records[cgKey{coord.Path, coord.Version, pv}]
	return r, ok, nil
}

func (s *fakeCallGraphStore) ListCallGraphRecords(_ context.Context, _ cgports.CallGraphFilter) ([]cgports.CallGraphSummary, error) {
	return nil, nil
}

func (s *fakeCallGraphStore) FindCallers(_ context.Context, _ string, _ string) ([]cgports.CallEdgeRef, error) {
	return nil, nil
}

func (s *fakeCallGraphStore) FindCallees(_ context.Context, _ string, _ string) ([]cgports.CallEdgeRef, error) {
	return nil, nil
}

// Compile-time checks.
var _ cgports.CallGraphStore = (*fakeCallGraphStore)(nil)
var _ ports.DependencyLoader = (*store.CallGraphStoreAdapter)(nil)

func coord(t *testing.T, path, ver string) fetchdomain.ModuleCoordinate {
	t.Helper()
	c, err := fetchdomain.NewModuleCoordinate(path, ver)
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	return c
}

func TestAdapter_LoadCallGraphRecords_Found(t *testing.T) {
	c := coord(t, "example.com/dep", "v1.0.0")
	fs := &fakeCallGraphStore{}
	rec := callgraphdomain.CallGraphRecord{
		Coordinate:      c,
		PipelineVersion: "0.1.0",
		OverallStatus:   callgraphdomain.CallGraphStatusExtracted,
	}
	if err := fs.PutCallGraphRecord(context.Background(), rec); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}

	a := store.New(fs)
	got, err := a.LoadCallGraphRecords(context.Background(), []fetchdomain.ModuleCoordinate{c}, "0.1.0")
	if err != nil {
		t.Fatalf("LoadCallGraphRecords: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Coordinate.Path != "example.com/dep" {
		t.Errorf("Coordinate.Path = %q, want %q", got[0].Coordinate.Path, "example.com/dep")
	}
}

func TestAdapter_LoadCallGraphRecords_NotFound_Omitted(t *testing.T) {
	a := store.New(&fakeCallGraphStore{})
	got, err := a.LoadCallGraphRecords(context.Background(), []fetchdomain.ModuleCoordinate{
		coord(t, "example.com/missing", "v1.0.0"),
	}, "0.1.0")
	if err != nil {
		t.Fatalf("LoadCallGraphRecords: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 records for missing coord, got %d", len(got))
	}
}

func TestAdapter_LoadCallGraphRecords_StoreError(t *testing.T) {
	storeErr := errors.New("database locked")
	fs := &fakeCallGraphStore{getErr: storeErr}
	a := store.New(fs)
	_, err := a.LoadCallGraphRecords(context.Background(), []fetchdomain.ModuleCoordinate{
		coord(t, "example.com/dep", "v1.0.0"),
	}, "0.1.0")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, storeErr) {
		t.Errorf("error = %v, want wrapping %v", err, storeErr)
	}
}

func TestAdapter_LoadCallGraphRecords_Empty(t *testing.T) {
	a := store.New(&fakeCallGraphStore{})
	got, err := a.LoadCallGraphRecords(context.Background(), nil, "0.1.0")
	if err != nil {
		t.Fatalf("LoadCallGraphRecords: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 records for nil coords, got %d", len(got))
	}
}

func TestAdapter_LoadCallGraphRecords_MixedFoundAndMissing(t *testing.T) {
	cFound := coord(t, "example.com/found", "v1.0.0")
	cMissing := coord(t, "example.com/missing", "v1.0.0")

	fs := &fakeCallGraphStore{}
	rec := callgraphdomain.CallGraphRecord{
		Coordinate:      cFound,
		PipelineVersion: "0.1.0",
		OverallStatus:   callgraphdomain.CallGraphStatusExtracted,
	}
	if err := fs.PutCallGraphRecord(context.Background(), rec); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}

	a := store.New(fs)
	got, err := a.LoadCallGraphRecords(context.Background(), []fetchdomain.ModuleCoordinate{cFound, cMissing}, "0.1.0")
	if err != nil {
		t.Fatalf("LoadCallGraphRecords: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1 (missing should be omitted)", len(got))
	}
	if got[0].Coordinate.Path != "example.com/found" {
		t.Errorf("wrong record returned: %q", got[0].Coordinate.Path)
	}
}
