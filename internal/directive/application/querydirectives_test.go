package application_test

import (
	"context"
	"errors"
	"testing"

	"code.eitanity.com/kanonarion/internal/directive/application"
	"code.eitanity.com/kanonarion/internal/directive/domain"
)

// fakeDirectiveStore is a minimal in-process implementation of ports.DirectiveStore.
type fakeDirectiveStore struct {
	latest map[string]domain.Record
	byID   map[string]domain.Record
	scans  map[string][]domain.Record
	err    error
}

func newFakeDirectiveStore() *fakeDirectiveStore {
	return &fakeDirectiveStore{
		latest: make(map[string]domain.Record),
		byID:   make(map[string]domain.Record),
		scans:  make(map[string][]domain.Record),
	}
}

func (s *fakeDirectiveStore) PutDirectiveRecord(_ context.Context, r domain.Record) error {
	if s.err != nil {
		return s.err
	}
	s.latest[r.ProjectModulePath] = r
	s.byID[r.ID] = r
	s.scans[r.ProjectModulePath] = append(s.scans[r.ProjectModulePath], r)
	return nil
}

func (s *fakeDirectiveStore) GetDirectiveRecord(_ context.Context, path string) (domain.Record, bool, error) {
	if s.err != nil {
		return domain.Record{}, false, s.err
	}
	r, ok := s.latest[path]
	return r, ok, nil
}

func (s *fakeDirectiveStore) GetScanByID(_ context.Context, id string) (domain.Record, bool, error) {
	if s.err != nil {
		return domain.Record{}, false, s.err
	}
	r, ok := s.byID[id]
	return r, ok, nil
}

func (s *fakeDirectiveStore) ListScans(_ context.Context, path string, limit, _ int) ([]domain.Record, error) {
	if s.err != nil {
		return nil, s.err
	}
	all := s.scans[path]
	if limit > 0 && len(all) > limit {
		return all[:limit], nil
	}
	return all, nil
}

func (s *fakeDirectiveStore) CountScans(context.Context) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	var n int
	for _, scans := range s.scans {
		n += len(scans)
	}
	return n, nil
}

func TestQueryDirectives_GetFound(t *testing.T) {
	store := newFakeDirectiveStore()
	rec := domain.Record{ID: "S1", ProjectModulePath: "example.com/proj"}
	store.latest["example.com/proj"] = rec

	uc := application.NewQueryDirectivesUseCase(store)
	got, found, err := uc.Get(context.Background(), "example.com/proj")
	if err != nil || !found || got.ID != "S1" {
		t.Fatalf("Get: err=%v found=%v id=%s", err, found, got.ID)
	}
}

func TestQueryDirectives_GetNotFound(t *testing.T) {
	uc := application.NewQueryDirectivesUseCase(newFakeDirectiveStore())
	_, found, err := uc.Get(context.Background(), "example.com/missing")
	if err != nil || found {
		t.Fatalf("expected not-found: err=%v found=%v", err, found)
	}
}

func TestQueryDirectives_GetError(t *testing.T) {
	store := newFakeDirectiveStore()
	store.err = errors.New("db down")
	uc := application.NewQueryDirectivesUseCase(store)
	_, _, err := uc.Get(context.Background(), "example.com/proj")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestQueryDirectives_GetScanFound(t *testing.T) {
	store := newFakeDirectiveStore()
	rec := domain.Record{ID: "SC1", ProjectModulePath: "example.com/proj"}
	store.byID["SC1"] = rec

	uc := application.NewQueryDirectivesUseCase(store)
	got, found, err := uc.GetScan(context.Background(), "SC1")
	if err != nil || !found || got.ID != "SC1" {
		t.Fatalf("GetScan: err=%v found=%v id=%s", err, found, got.ID)
	}
}

func TestQueryDirectives_GetScanNotFound(t *testing.T) {
	uc := application.NewQueryDirectivesUseCase(newFakeDirectiveStore())
	_, found, err := uc.GetScan(context.Background(), "MISSING")
	if err != nil || found {
		t.Fatalf("expected not-found: err=%v found=%v", err, found)
	}
}

func TestQueryDirectives_GetScanError(t *testing.T) {
	store := newFakeDirectiveStore()
	store.err = errors.New("db down")
	uc := application.NewQueryDirectivesUseCase(store)
	_, _, err := uc.GetScan(context.Background(), "SC1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestQueryDirectives_ListScans(t *testing.T) {
	store := newFakeDirectiveStore()
	ctx := context.Background()
	for _, id := range []string{"S1", "S2", "S3"} {
		if err := store.PutDirectiveRecord(ctx, domain.Record{ID: id, ProjectModulePath: "example.com/proj"}); err != nil {
			t.Fatalf("PutDirectiveRecord: %v", err)
		}
	}

	uc := application.NewQueryDirectivesUseCase(store)
	all, err := uc.ListScans(ctx, "example.com/proj", 0, 0)
	if err != nil || len(all) != 3 {
		t.Fatalf("ListScans: err=%v len=%d", err, len(all))
	}

	limited, err := uc.ListScans(ctx, "example.com/proj", 2, 0)
	if err != nil || len(limited) != 2 {
		t.Fatalf("limited ListScans: err=%v len=%d", err, len(limited))
	}
}

func TestQueryDirectives_ListScansError(t *testing.T) {
	store := newFakeDirectiveStore()
	store.err = errors.New("db down")
	uc := application.NewQueryDirectivesUseCase(store)
	_, err := uc.ListScans(context.Background(), "example.com/proj", 0, 0)
	if err == nil {
		t.Fatal("expected error")
	}
}

// projectListingStore is a store that can also enumerate its projects.
type projectListingStore struct {
	*fakeDirectiveStore
	projects []string
	err      error
}

func (s projectListingStore) ListScanProjects(context.Context) ([]string, error) {
	return s.projects, s.err
}

// The project listing is read through the optional capability, and a store
// without it says so rather than answering that it holds none.
func TestQueryDirectives_ListScanProjects(t *testing.T) {
	ctx := context.Background()
	if _, ok, err := application.NewQueryDirectivesUseCase(newFakeDirectiveStore()).ListScanProjects(ctx); ok || err != nil {
		t.Errorf("a store without the capability: ok=%v err=%v, want false, nil", ok, err)
	}
	got, ok, err := application.NewQueryDirectivesUseCase(projectListingStore{newFakeDirectiveStore(), []string{"example.com/a"}, nil}).ListScanProjects(ctx)
	if !ok || err != nil || len(got) != 1 || got[0] != "example.com/a" {
		t.Errorf("got %v ok=%v err=%v", got, ok, err)
	}
	if _, _, err := application.NewQueryDirectivesUseCase(projectListingStore{newFakeDirectiveStore(), nil, errors.New("planted")}).ListScanProjects(ctx); err == nil {
		t.Error("a failed listing returned no error")
	}
}
