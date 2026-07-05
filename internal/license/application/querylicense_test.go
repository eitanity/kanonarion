package application_test

import (
	"context"
	"errors"
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/license/application"
	"github.com/eitanity/kanonarion/internal/license/domain"
	licenseports "github.com/eitanity/kanonarion/internal/license/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// queryLicFakeStore is a minimal LicenseStore for QueryLicenseUseCase tests.
type queryLicFakeStore struct {
	records   map[queryLicKey]domain.LicenseRecord
	summaries []licenseports.LicenseSummary
	getErr    error
	listErr   error
}

type queryLicKey struct{ path, version, pipeline string }

func (s *queryLicFakeStore) PutLicenseRecord(_ context.Context, r domain.LicenseRecord) error {
	if s.records == nil {
		s.records = make(map[queryLicKey]domain.LicenseRecord)
	}
	s.records[queryLicKey{r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion}] = r
	return nil
}

func (s *queryLicFakeStore) GetLicenseRecord(_ context.Context, coord fetchdomain.ModuleCoordinate, pv string) (domain.LicenseRecord, bool, error) {
	if s.getErr != nil {
		return domain.LicenseRecord{}, false, s.getErr
	}
	r, ok := s.records[queryLicKey{coord.Path, coord.Version, pv}]
	return r, ok, nil
}

func (s *queryLicFakeStore) ListLicenseRecords(_ context.Context, _ licenseports.LicenseFilter) ([]licenseports.LicenseSummary, error) {
	return s.summaries, s.listErr
}

var _ licenseports.LicenseStore = (*queryLicFakeStore)(nil)

func TestQueryLicenseUseCase_GetLicenseRecord(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
	store := &queryLicFakeStore{}
	_ = store.PutLicenseRecord(context.Background(), domain.LicenseRecord{
		Coordinate:      coord,
		PipelineVersion: "0.1.0",
	})

	uc := application.NewQueryLicenseUseCase(store)

	got, found, err := uc.GetLicenseRecord(context.Background(), coord, "0.1.0")
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

func TestQueryLicenseUseCase_GetLicenseRecord_NotFound(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
	uc := application.NewQueryLicenseUseCase(&queryLicFakeStore{})

	_, found, err := uc.GetLicenseRecord(context.Background(), coord, "0.1.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("expected record not to be found")
	}
}

func TestQueryLicenseUseCase_GetLicenseRecord_StoreError(t *testing.T) {
	storeErr := errors.New("db failure")
	uc := application.NewQueryLicenseUseCase(&queryLicFakeStore{getErr: storeErr})

	coord := fetchdomain.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
	_, _, err := uc.GetLicenseRecord(context.Background(), coord, "0.1.0")
	if !errors.Is(err, storeErr) {
		t.Errorf("got %v, want wrapping %v", err, storeErr)
	}
}

func TestQueryLicenseUseCase_ListLicenseRecords(t *testing.T) {
	store := &queryLicFakeStore{
		summaries: []licenseports.LicenseSummary{
			{ModulePath: "example.com/mod", ModuleVersion: "v1.0.0", PrimarySPDX: "MIT"},
		},
	}
	uc := application.NewQueryLicenseUseCase(store)

	sums, err := uc.ListLicenseRecords(context.Background(), licenseports.LicenseFilter{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sums) != 1 {
		t.Errorf("got %d summaries, want 1", len(sums))
	}
}

func TestQueryLicenseUseCase_ListLicenseRecords_Error(t *testing.T) {
	listErr := errors.New("db failure")
	uc := application.NewQueryLicenseUseCase(&queryLicFakeStore{listErr: listErr})

	_, err := uc.ListLicenseRecords(context.Background(), licenseports.LicenseFilter{})
	if !errors.Is(err, listErr) {
		t.Errorf("got %v, want wrapping %v", err, listErr)
	}
}

// queryLicFakeWalkStore is a minimal WalkStore for ResolveForWalk tests.
type queryLicFakeWalkStore struct {
	walk    walkdomain.WalkRecord
	walkErr error
}

func (s *queryLicFakeWalkStore) PutWalk(_ context.Context, _ walkdomain.WalkRecord) error {
	return nil
}

func (s *queryLicFakeWalkStore) GetWalk(_ context.Context, _ string) (walkdomain.WalkRecord, error) {
	return s.walk, s.walkErr
}

func (s *queryLicFakeWalkStore) ListWalks(_ context.Context, _ walkports.WalkFilter) ([]walkports.WalkSummary, error) {
	return nil, nil
}

var _ walkports.WalkStore = (*queryLicFakeWalkStore)(nil)

func TestQueryLicenseUseCase_ResolveForWalk_NoWalksStore(t *testing.T) {
	uc := application.NewQueryLicenseUseCase(&queryLicFakeStore{})
	_, err := uc.ResolveForWalk(context.Background(), "walk-1", fetchdomain.ModuleCoordinate{}, nil)
	if err == nil {
		t.Fatal("expected error when walks store not configured")
	}
}

func TestQueryLicenseUseCase_ResolveForWalk(t *testing.T) {
	target := fetchdomain.ModuleCoordinate{Path: "example.com/target", Version: "v1.0.0"}
	dep := fetchdomain.ModuleCoordinate{Path: "example.com/dep", Version: "v0.1.0"}

	walkStore := &queryLicFakeWalkStore{
		walk: walkdomain.WalkRecord{
			ID: "walk-1",
			Graph: walkdomain.Graph{
				Nodes: []walkdomain.GraphNode{
					{Coordinate: target},
					{Coordinate: dep},
				},
			},
		},
	}

	licenseStore := &queryLicFakeStore{}
	uc := application.NewQueryLicenseUseCaseWithWalks(licenseStore, walkStore)

	extractFn := func(_ context.Context, coord fetchdomain.ModuleCoordinate) (domain.LicenseRecord, error) {
		return domain.LicenseRecord{Coordinate: coord, PrimarySPDX: "MIT"}, nil
	}

	results, err := uc.ResolveForWalk(context.Background(), "walk-1", target, extractFn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Coordinate != dep {
		t.Errorf("got coord %v, want %v", results[0].Coordinate, dep)
	}
	if results[0].PrimarySPDX != "MIT" {
		t.Errorf("got SPDX %q, want MIT", results[0].PrimarySPDX)
	}
}

func TestQueryLicenseUseCase_ResolveForWalk_ExtractError(t *testing.T) {
	target := fetchdomain.ModuleCoordinate{Path: "example.com/target", Version: "v1.0.0"}
	dep := fetchdomain.ModuleCoordinate{Path: "example.com/dep", Version: "v0.1.0"}
	extractErr := errors.New("extract failure")

	walkStore := &queryLicFakeWalkStore{
		walk: walkdomain.WalkRecord{
			ID: "walk-1",
			Graph: walkdomain.Graph{
				Nodes: []walkdomain.GraphNode{
					{Coordinate: target},
					{Coordinate: dep},
				},
			},
		},
	}

	uc := application.NewQueryLicenseUseCaseWithWalks(&queryLicFakeStore{}, walkStore)
	extractFn := func(_ context.Context, _ fetchdomain.ModuleCoordinate) (domain.LicenseRecord, error) {
		return domain.LicenseRecord{}, extractErr
	}

	results, err := uc.ResolveForWalk(context.Background(), "walk-1", target, extractFn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if !errors.Is(results[0].Err, extractErr) {
		t.Errorf("got err %v, want wrapping %v", results[0].Err, extractErr)
	}
}

func TestQueryLicenseUseCase_ResolveForWalk_WalkError(t *testing.T) {
	walkErr := errors.New("walk db failure")
	walkStore := &queryLicFakeWalkStore{walkErr: walkErr}
	uc := application.NewQueryLicenseUseCaseWithWalks(&queryLicFakeStore{}, walkStore)

	_, err := uc.ResolveForWalk(context.Background(), "walk-1", fetchdomain.ModuleCoordinate{}, nil)
	if !errors.Is(err, walkErr) {
		t.Errorf("got %v, want wrapping %v", err, walkErr)
	}
}
