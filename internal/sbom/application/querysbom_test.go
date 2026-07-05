package application_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/sbom/application"
	"github.com/eitanity/kanonarion/internal/sbom/domain"
	sbomports "github.com/eitanity/kanonarion/internal/sbom/ports"
)

// querySBOMFakeStore is a minimal SBOMStore for QuerySBOMUseCase tests.
type querySBOMFakeStore struct {
	records map[string]domain.SBOMRecord
	getErr  error
	listErr error
}

func (s *querySBOMFakeStore) put(r domain.SBOMRecord) {
	if s.records == nil {
		s.records = make(map[string]domain.SBOMRecord)
	}
	s.records[r.ID] = r
}

func (s *querySBOMFakeStore) PutSBOMRecord(_ context.Context, r domain.SBOMRecord) error {
	s.put(r)
	return nil
}

func (s *querySBOMFakeStore) GetSBOMRecord(_ context.Context, id string) (domain.SBOMRecord, error) {
	if s.getErr != nil {
		return domain.SBOMRecord{}, s.getErr
	}
	r, ok := s.records[id]
	if !ok {
		return domain.SBOMRecord{}, sbomports.ErrSBOMNotFound
	}
	return r, nil
}

func (s *querySBOMFakeStore) ListSBOMRecords(_ context.Context, walkID string) ([]domain.SBOMRecord, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	var out []domain.SBOMRecord
	for _, r := range s.records {
		if r.WalkID == walkID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *querySBOMFakeStore) FindSBOMRecord(_ context.Context, _ string, _ *string, _ domain.SBOMFormat, _ string) (domain.SBOMRecord, bool, error) {
	return domain.SBOMRecord{}, false, nil
}

var _ sbomports.SBOMStore = (*querySBOMFakeStore)(nil)

func TestQuerySBOMUseCase_GetSBOMRecord(t *testing.T) {
	rec := domain.SBOMRecord{ID: "sbom-1", WalkID: "walk-1", GeneratedAt: time.Now()}
	store := &querySBOMFakeStore{}
	store.put(rec)

	uc := application.NewQuerySBOMUseCase(store)

	got, err := uc.GetSBOMRecord(context.Background(), "sbom-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != rec.ID {
		t.Errorf("got ID %q, want %q", got.ID, rec.ID)
	}
}

func TestQuerySBOMUseCase_GetSBOMRecord_NotFound(t *testing.T) {
	uc := application.NewQuerySBOMUseCase(&querySBOMFakeStore{})

	_, err := uc.GetSBOMRecord(context.Background(), "missing")
	if !errors.Is(err, sbomports.ErrSBOMNotFound) {
		t.Errorf("got %v, want wrapping ErrSBOMNotFound", err)
	}
}

func TestQuerySBOMUseCase_GetSBOMRecord_StoreError(t *testing.T) {
	storeErr := errors.New("db failure")
	uc := application.NewQuerySBOMUseCase(&querySBOMFakeStore{getErr: storeErr})

	_, err := uc.GetSBOMRecord(context.Background(), "sbom-1")
	if !errors.Is(err, storeErr) {
		t.Errorf("got %v, want wrapping %v", err, storeErr)
	}
}

func TestQuerySBOMUseCase_ListSBOMRecords(t *testing.T) {
	store := &querySBOMFakeStore{}
	store.put(domain.SBOMRecord{ID: "sbom-1", WalkID: "walk-1", GeneratedAt: time.Now()})
	store.put(domain.SBOMRecord{ID: "sbom-2", WalkID: "walk-1", GeneratedAt: time.Now()})
	store.put(domain.SBOMRecord{ID: "sbom-3", WalkID: "walk-2", GeneratedAt: time.Now()})

	uc := application.NewQuerySBOMUseCase(store)

	recs, err := uc.ListSBOMRecords(context.Background(), "walk-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 2 {
		t.Errorf("got %d records for walk-1, want 2", len(recs))
	}
}

func TestQuerySBOMUseCase_ListSBOMRecords_Error(t *testing.T) {
	listErr := errors.New("db failure")
	uc := application.NewQuerySBOMUseCase(&querySBOMFakeStore{listErr: listErr})

	_, err := uc.ListSBOMRecords(context.Background(), "walk-1")
	if !errors.Is(err, listErr) {
		t.Errorf("got %v, want wrapping %v", err, listErr)
	}
}
