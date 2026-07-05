package application_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
)

// queryVulnFakeStore is a minimal VulnerabilityStore for query use-case tests.
type queryVulnFakeStore struct {
	record          domain.VulnerabilityRecord
	recordFound     bool
	latestRecord    domain.VulnerabilityRecord
	latestFound     bool
	latestForWalk   domain.VulnerabilityRecord
	latestForWalkOK bool
	moduleRecords   []domain.VulnerabilityRecord
	findingRecords  []domain.VulnerabilityRecord
	scanRun         domain.WalkScanRun
	scanRunFound    bool
	walkRuns        []domain.WalkScanRun
	allRuns         []domain.WalkScanRun
	snapshots       []domain.DatabaseSnapshot
	storeErr        error
}

func (s *queryVulnFakeStore) PutVulnerabilityRecord(_ context.Context, _ domain.VulnerabilityRecord) error {
	return nil
}

func (s *queryVulnFakeStore) GetVulnerabilityRecord(_ context.Context, _ fetchdomain.ModuleCoordinate, _ string, _ domain.DatabaseSnapshot) (domain.VulnerabilityRecord, bool, error) {
	if s.storeErr != nil {
		return domain.VulnerabilityRecord{}, false, s.storeErr
	}
	return s.record, s.recordFound, nil
}

func (s *queryVulnFakeStore) GetLatestVulnerabilityRecord(_ context.Context, _ fetchdomain.ModuleCoordinate, _ string) (domain.VulnerabilityRecord, bool, error) {
	if s.storeErr != nil {
		return domain.VulnerabilityRecord{}, false, s.storeErr
	}
	return s.latestRecord, s.latestFound, nil
}

func (s *queryVulnFakeStore) GetLatestVulnerabilityRecordForWalk(_ context.Context, _ fetchdomain.ModuleCoordinate, _ string, _ string) (domain.VulnerabilityRecord, bool, error) {
	if s.storeErr != nil {
		return domain.VulnerabilityRecord{}, false, s.storeErr
	}
	return s.latestForWalk, s.latestForWalkOK, nil
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

func (s *queryVulnFakeStore) ListVulnerabilityRecordsByFindingID(_ context.Context, _ string) ([]domain.VulnerabilityRecord, error) {
	return s.findingRecords, s.storeErr
}

func (s *queryVulnFakeStore) ListVulnerabilityRecords(_ context.Context, _ string) ([]domain.VulnerabilityRecord, error) {
	return nil, nil
}

func (s *queryVulnFakeStore) ListVulnerabilityRecordsForModule(_ context.Context, _ fetchdomain.ModuleCoordinate, _ string) ([]domain.VulnerabilityRecord, error) {
	return s.moduleRecords, s.storeErr
}

var _ vulnports.VulnerabilityStore = (*queryVulnFakeStore)(nil)

// --- QueryVulnUseCase tests ---

func TestQueryVulnUseCase_GetRecord(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
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

	_, _, err := uc.GetRecord(context.Background(), fetchdomain.ModuleCoordinate{}, "v1", domain.DatabaseSnapshot{})
	if !errors.Is(err, storeErr) {
		t.Errorf("got %v, want wrapping %v", err, storeErr)
	}
}

func TestQueryVulnUseCase_GetLatestRecord(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
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

func TestQueryVulnUseCase_GetLatestRecordForWalk(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
	want := domain.VulnerabilityRecord{Coordinate: coord, WalkID: "walk-1"}
	uc := application.NewQueryVulnUseCase(&queryVulnFakeStore{latestForWalk: want, latestForWalkOK: true})

	got, found, err := uc.GetLatestRecordForWalk(context.Background(), coord, "v1", "walk-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Fatal("expected record to be found")
	}
	if got.WalkID != "walk-1" {
		t.Errorf("got walk %q, want walk-1", got.WalkID)
	}
}

func TestQueryVulnUseCase_ListRecordsForModule(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
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
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
	recs := []domain.VulnerabilityRecord{{Coordinate: coord}}
	uc := application.NewQueryVulnUseCase(&queryVulnFakeStore{findingRecords: recs})

	got, err := uc.ListRecordsByFindingID(context.Background(), "GO-2024-1234")
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

	_, err := uc.ListRecordsByFindingID(context.Background(), "GO-2024-1234")
	if !errors.Is(err, storeErr) {
		t.Errorf("got %v, want wrapping %v", err, storeErr)
	}
}

// --- QueryScanRunsUseCase tests ---

func TestQueryScanRunsUseCase_GetRun(t *testing.T) {
	run := domain.WalkScanRun{ID: "run-1", WalkID: "walk-1"}
	uc := application.NewQueryScanRunsUseCase(&queryVulnFakeStore{scanRun: run, scanRunFound: true})

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
	uc := application.NewQueryScanRunsUseCase(&queryVulnFakeStore{})

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
	uc := application.NewQueryScanRunsUseCase(&queryVulnFakeStore{storeErr: storeErr})

	_, _, err := uc.GetRun(context.Background(), "run-1")
	if !errors.Is(err, storeErr) {
		t.Errorf("got %v, want wrapping %v", err, storeErr)
	}
}

func TestQueryScanRunsUseCase_ListRunsForWalk(t *testing.T) {
	runs := []domain.WalkScanRun{{ID: "run-1"}, {ID: "run-2"}}
	uc := application.NewQueryScanRunsUseCase(&queryVulnFakeStore{walkRuns: runs})

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
	uc := application.NewQueryScanRunsUseCase(&queryVulnFakeStore{allRuns: runs})

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
		{Source: "govulndb", Version: "v2024-01-01", RetrievedAt: time.Now()},
	}
	uc := application.NewQueryScanRunsUseCase(&queryVulnFakeStore{snapshots: snaps})

	got, err := uc.ListSnapshots(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Source != "govulndb" {
		t.Errorf("unexpected snapshots: %v", got)
	}
}

func TestQueryScanRunsUseCase_ListSnapshots_Error(t *testing.T) {
	storeErr := errors.New("db failure")
	uc := application.NewQueryScanRunsUseCase(&queryVulnFakeStore{storeErr: storeErr})

	_, err := uc.ListSnapshots(context.Background())
	if !errors.Is(err, storeErr) {
		t.Errorf("got %v, want wrapping %v", err, storeErr)
	}
}
