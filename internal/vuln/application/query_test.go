package application_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// queryVulnFakeStore is a minimal VulnerabilityStore for query use-case tests.
type queryVulnFakeStore struct {
	record         domain.VulnerabilityRecord
	recordFound    bool
	latestRecord   domain.VulnerabilityRecord
	latestFound    bool
	walkRecords    []domain.VulnerabilityRecord
	moduleRecords  []domain.VulnerabilityRecord
	allGenRecords  []domain.VulnerabilityRecord
	findingRecords []domain.VulnerabilityRecord
	generations    []vulnports.VulnerabilityRecordGeneration
	scanRun        domain.WalkScanRun
	scanRunFound   bool
	walkRuns       []domain.WalkScanRun
	allRuns        []domain.WalkScanRun
	snapshots      []domain.DatabaseSnapshot
	storeErr       error
}

func (s *queryVulnFakeStore) PutVulnerabilityRecord(_ context.Context, _ domain.VulnerabilityRecord) error {
	return nil
}

func (s *queryVulnFakeStore) GetVulnerabilityRecord(_ context.Context, _ coordinate.ModuleCoordinate, _ string, _ domain.DatabaseSnapshot) (domain.VulnerabilityRecord, bool, error) {
	if s.storeErr != nil {
		return domain.VulnerabilityRecord{}, false, s.storeErr
	}
	return s.record, s.recordFound, nil
}

func (s *queryVulnFakeStore) GetLatestVulnerabilityRecord(_ context.Context, _ coordinate.ModuleCoordinate, _ string) (domain.VulnerabilityRecord, bool, error) {
	if s.storeErr != nil {
		return domain.VulnerabilityRecord{}, false, s.storeErr
	}
	return s.latestRecord, s.latestFound, nil
}

func (s *queryVulnFakeStore) ListVulnerabilityRecordsForModuleInWalk(_ context.Context, _ coordinate.ModuleCoordinate, _ string, _ string) ([]domain.VulnerabilityRecord, error) {
	if s.storeErr != nil {
		return nil, s.storeErr
	}
	return s.walkRecords, nil
}

func (s *queryVulnFakeStore) PutWalkScanRun(_ context.Context, _ domain.WalkScanRun) error {
	return nil
}

func (s *queryVulnFakeStore) GetWalkScanRun(_ context.Context, _ string) (domain.WalkScanRun, bool, error) {
	if s.storeErr != nil {
		return domain.WalkScanRun{}, false, s.storeErr
	}
	return s.scanRun, s.scanRunFound, nil
}

func (s *queryVulnFakeStore) ListWalkScanRuns(_ context.Context, _ string) ([]domain.WalkScanRun, error) {
	return s.walkRuns, s.storeErr
}

func (s *queryVulnFakeStore) ListAllWalkScanRuns(_ context.Context) ([]domain.WalkScanRun, error) {
	return s.allRuns, s.storeErr
}

func (s *queryVulnFakeStore) PutDatabaseSnapshot(_ context.Context, _ domain.DatabaseSnapshot, _ io.Reader) error {
	return nil
}

func (s *queryVulnFakeStore) GetDatabaseSnapshot(_ context.Context, _ domain.DatabaseSnapshot) (io.ReadCloser, error) {
	return nil, nil
}

func (s *queryVulnFakeStore) GetLatestDatabaseSnapshot(_ context.Context) (domain.DatabaseSnapshot, bool, error) {
	return domain.DatabaseSnapshot{}, false, nil
}

func (s *queryVulnFakeStore) ListDatabaseSnapshots(_ context.Context) ([]domain.DatabaseSnapshot, error) {
	return s.snapshots, s.storeErr
}

func (s *queryVulnFakeStore) ListVulnerabilityRecordsByFindingID(_ context.Context, _, _ string) ([]domain.VulnerabilityRecord, error) {
	return s.findingRecords, s.storeErr
}

func (s *queryVulnFakeStore) ListVulnerabilityRecords(_ context.Context, _ string) ([]domain.VulnerabilityRecord, error) {
	return nil, nil
}

func (s *queryVulnFakeStore) ListVulnerabilityRecordsForModule(_ context.Context, _ coordinate.ModuleCoordinate, _ string) ([]domain.VulnerabilityRecord, error) {
	return s.moduleRecords, s.storeErr
}

func (s *queryVulnFakeStore) ListVulnerabilityRecordsForModuleAllGenerations(_ context.Context, _ coordinate.ModuleCoordinate) ([]domain.VulnerabilityRecord, error) {
	return s.allGenRecords, s.storeErr
}

func (s *queryVulnFakeStore) ListVulnerabilityRecordGenerationsForModule(_ context.Context, _ coordinate.ModuleCoordinate) ([]vulnports.VulnerabilityRecordGeneration, error) {
	return s.generations, s.storeErr
}

var _ vulnports.VulnerabilityStore = (*queryVulnFakeStore)(nil)

// --- QueryVulnUseCase tests ---

func TestQueryVulnUseCase_GetRecord(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	want := domain.VulnerabilityRecord{Coordinate: coord, OverallStatus: domain.StatusClean}
	uc := application.NewQueryVulnUseCase(&queryVulnFakeStore{record: want, recordFound: true})

	got, found, err := uc.GetRecord(context.Background(), coord, "v1", domain.DatabaseSnapshot{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Fatal("expected record to be found")
	}
	if got.Coordinate != coord {
		t.Errorf("got %v, want %v", got.Coordinate, coord)
	}
}

func TestQueryVulnUseCase_GetRecord_Error(t *testing.T) {
	storeErr := errors.New("db failure")
	uc := application.NewQueryVulnUseCase(&queryVulnFakeStore{storeErr: storeErr})

	_, _, err := uc.GetRecord(context.Background(), coordinate.ModuleCoordinate{}, "v1", domain.DatabaseSnapshot{})
	if !errors.Is(err, storeErr) {
		t.Errorf("got %v, want wrapping %v", err, storeErr)
	}
}

func TestQueryVulnUseCase_GetLatestRecord(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	want := domain.VulnerabilityRecord{Coordinate: coord}
	uc := application.NewQueryVulnUseCase(&queryVulnFakeStore{latestRecord: want, latestFound: true})

	got, found, err := uc.GetLatestRecord(context.Background(), coord, "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Fatal("expected record to be found")
	}
	if got.Coordinate != coord {
		t.Errorf("got %v, want %v", got.Coordinate, coord)
	}
}

// The walk-scoped read hands back every candidate rather than one answer: the
// use case has no analysis frame to rank them with, and picking without one is
// what let a walk-pinned question be answered from another build's scan.
func TestQueryVulnUseCase_ListRecordsForModuleInWalk(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	want := []domain.VulnerabilityRecord{
		{Coordinate: coord, WalkID: "walk-1", Rooting: domain.RootingIsolated},
		{Coordinate: coord, WalkID: "walk-1", Rooting: domain.TargetRootedAt(coord)},
	}
	uc := application.NewQueryVulnUseCase(&queryVulnFakeStore{walkRecords: want})

	got, err := uc.ListRecordsForModuleInWalk(context.Background(), coord, "v1", "walk-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d candidate(s), want %d — the read must not rank or drop any", len(got), len(want))
	}
}

func TestQueryVulnUseCase_ListRecordsForModuleAllGenerations(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	recs := []domain.VulnerabilityRecord{
		{Coordinate: coord, PipelineVersion: "v20"},
		{Coordinate: coord, PipelineVersion: "v19"},
	}
	uc := application.NewQueryVulnUseCase(&queryVulnFakeStore{allGenRecords: recs})

	got, err := uc.ListRecordsForModuleAllGenerations(context.Background(), coord)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
	if got[0].PipelineVersion != "v20" || got[1].PipelineVersion != "v19" {
		t.Errorf("order not preserved: %s, %s", got[0].PipelineVersion, got[1].PipelineVersion)
	}
}

func TestQueryVulnUseCase_ListRecordsForModuleAllGenerations_StoreError(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	uc := application.NewQueryVulnUseCase(&queryVulnFakeStore{storeErr: errors.New("boom")})

	if _, err := uc.ListRecordsForModuleAllGenerations(context.Background(), coord); err == nil {
		t.Fatal("expected the store error to surface")
	}
}

func TestQueryVulnUseCase_ListRecordsForModule(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	recs := []domain.VulnerabilityRecord{{Coordinate: coord}, {Coordinate: coord}}
	uc := application.NewQueryVulnUseCase(&queryVulnFakeStore{moduleRecords: recs})

	got, err := uc.ListRecordsForModule(context.Background(), coord, "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d records, want 2", len(got))
	}
}

func TestQueryVulnUseCase_ListRecordsByFindingID(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	recs := []domain.VulnerabilityRecord{{Coordinate: coord}}
	uc := application.NewQueryVulnUseCase(&queryVulnFakeStore{findingRecords: recs})

	got, err := uc.ListRecordsByFindingID(context.Background(), "GO-2024-1234", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %d records, want 1", len(got))
	}
}

func TestQueryVulnUseCase_ListRecordsByFindingID_Error(t *testing.T) {
	storeErr := errors.New("db failure")
	uc := application.NewQueryVulnUseCase(&queryVulnFakeStore{storeErr: storeErr})

	_, err := uc.ListRecordsByFindingID(context.Background(), "GO-2024-1234", "")
	if !errors.Is(err, storeErr) {
		t.Errorf("got %v, want wrapping %v", err, storeErr)
	}
}

// --- QueryScanRunsUseCase tests ---

func TestQueryScanRunsUseCase_GetRun(t *testing.T) {
	run := domain.WalkScanRun{ID: "run-1", WalkID: "walk-1"}
	uc := application.NewQueryScanRunsUseCase(&queryVulnFakeStore{scanRun: run, scanRunFound: true}, fakeWalkPresence{})

	got, found, err := uc.GetRun(context.Background(), "run-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Fatal("expected run to be found")
	}
	if got.ID != "run-1" {
		t.Errorf("got ID %q, want run-1", got.ID)
	}
}

func TestQueryScanRunsUseCase_GetRun_NotFound(t *testing.T) {
	uc := application.NewQueryScanRunsUseCase(&queryVulnFakeStore{}, fakeWalkPresence{})

	_, found, err := uc.GetRun(context.Background(), "run-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("expected run not to be found")
	}
}

func TestQueryScanRunsUseCase_GetRun_Error(t *testing.T) {
	storeErr := errors.New("db failure")
	uc := application.NewQueryScanRunsUseCase(&queryVulnFakeStore{storeErr: storeErr}, fakeWalkPresence{})

	_, _, err := uc.GetRun(context.Background(), "run-1")
	if !errors.Is(err, storeErr) {
		t.Errorf("got %v, want wrapping %v", err, storeErr)
	}
}

func TestQueryScanRunsUseCase_ListRunsForWalk(t *testing.T) {
	runs := []domain.WalkScanRun{{ID: "run-1"}, {ID: "run-2"}}
	uc := application.NewQueryScanRunsUseCase(&queryVulnFakeStore{walkRuns: runs}, fakeWalkPresence{})

	got, err := uc.ListRunsForWalk(context.Background(), "walk-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d runs, want 2", len(got))
	}
}

func TestQueryScanRunsUseCase_ListAllRuns(t *testing.T) {
	runs := []domain.WalkScanRun{{ID: "run-1"}}
	uc := application.NewQueryScanRunsUseCase(&queryVulnFakeStore{allRuns: runs}, fakeWalkPresence{})

	got, err := uc.ListAllRuns(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %d runs, want 1", len(got))
	}
}

func TestQueryScanRunsUseCase_ListSnapshots(t *testing.T) {
	snaps := []domain.DatabaseSnapshot{
		vulntest.MustNewAt("govulndb", "v2024-01-01", time.Now()),
	}
	uc := application.NewQueryScanRunsUseCase(&queryVulnFakeStore{snapshots: snaps}, fakeWalkPresence{})

	got, err := uc.ListSnapshots(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Source() != "govulndb" {
		t.Errorf("unexpected snapshots: %v", got)
	}
}

func TestQueryScanRunsUseCase_ListSnapshots_Error(t *testing.T) {
	storeErr := errors.New("db failure")
	uc := application.NewQueryScanRunsUseCase(&queryVulnFakeStore{storeErr: storeErr}, fakeWalkPresence{})

	_, err := uc.ListSnapshots(context.Background())
	if !errors.Is(err, storeErr) {
		t.Errorf("got %v, want wrapping %v", err, storeErr)
	}
}

func (s *queryVulnFakeStore) GetVulnerabilityRecordAt(_ context.Context, _ coordinate.ModuleCoordinate, _ string, _ domain.DatabaseSnapshot, _ domain.Rooting) (domain.VulnerabilityRecord, bool, error) {
	if s.storeErr != nil {
		return domain.VulnerabilityRecord{}, false, s.storeErr
	}
	return s.record, s.recordFound, nil
}

func (s *queryVulnFakeStore) HasVulnerabilityRecord(_ context.Context, _ coordinate.ModuleCoordinate, _ string, _ domain.DatabaseSnapshot, _ string) (bool, error) {
	return s.recordFound, s.storeErr
}

// fakeWalkPresence answers the walk-presence probe. A walk is held unless it is
// named in absent, so the zero value is the healthy store every test above
// assumes.
type fakeWalkPresence struct {
	absent map[string]bool
	err    error
}

func (f fakeWalkPresence) PresentWalks(_ context.Context, ids []string) (map[string]bool, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = !f.absent[id]
	}
	return out, nil
}
