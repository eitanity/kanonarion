package application_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/extract/application"
	"github.com/eitanity/kanonarion/internal/extract/domain"
	extractports "github.com/eitanity/kanonarion/internal/extract/ports"
)

// queryExtFakeStore is a minimal ExtractionStore for QueryExtractionUseCase tests.
type queryExtFakeStore struct {
	runs    map[string]domain.ExtractionRun
	getErr  error
	listErr error
}

func (s *queryExtFakeStore) PutExtractionRun(_ context.Context, run domain.ExtractionRun) error {
	if s.runs == nil {
		s.runs = make(map[string]domain.ExtractionRun)
	}
	s.runs[run.ID] = run
	return nil
}

func (s *queryExtFakeStore) GetExtractionRun(_ context.Context, id string) (domain.ExtractionRun, error) {
	if s.getErr != nil {
		return domain.ExtractionRun{}, s.getErr
	}
	run, ok := s.runs[id]
	if !ok {
		return domain.ExtractionRun{}, extractports.ErrExtractionRunNotFound
	}
	return run, nil
}

func (s *queryExtFakeStore) ListExtractionRuns(_ context.Context, _ extractports.ExtractionRunFilter) ([]extractports.ExtractionRunSummary, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	var out []extractports.ExtractionRunSummary
	for _, r := range s.runs {
		out = append(out, extractports.ExtractionRunSummary{
			ID:            r.ID,
			WalkID:        r.WalkID,
			StartedAt:     r.StartedAt,
			CompletedAt:   r.CompletedAt,
			OverallStatus: r.OverallStatus,
			ModuleCount:   len(r.PerModuleResults),
		})
	}
	return out, nil
}

var _ extractports.ExtractionStore = (*queryExtFakeStore)(nil)

func TestQueryExtractionUseCase_GetExtractionRun(t *testing.T) {
	run := domain.ExtractionRun{ID: "run-1", WalkID: "walk-1", StartedAt: time.Now()}
	store := &queryExtFakeStore{}
	_ = store.PutExtractionRun(context.Background(), run)

	uc := application.NewQueryExtractionUseCase(store)

	got, err := uc.GetExtractionRun(context.Background(), "run-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != run.ID {
		t.Errorf("got ID %q, want %q", got.ID, run.ID)
	}
}

func TestQueryExtractionUseCase_GetExtractionRun_NotFound(t *testing.T) {
	uc := application.NewQueryExtractionUseCase(&queryExtFakeStore{})

	_, err := uc.GetExtractionRun(context.Background(), "missing")
	if !errors.Is(err, extractports.ErrExtractionRunNotFound) {
		t.Errorf("got %v, want wrapping ErrExtractionRunNotFound", err)
	}
}

func TestQueryExtractionUseCase_GetExtractionRun_StoreError(t *testing.T) {
	storeErr := errors.New("db failure")
	uc := application.NewQueryExtractionUseCase(&queryExtFakeStore{getErr: storeErr})

	_, err := uc.GetExtractionRun(context.Background(), "run-1")
	if !errors.Is(err, storeErr) {
		t.Errorf("got %v, want wrapping %v", err, storeErr)
	}
}

func TestQueryExtractionUseCase_ListExtractionRuns(t *testing.T) {
	store := &queryExtFakeStore{}
	_ = store.PutExtractionRun(context.Background(), domain.ExtractionRun{ID: "run-1", WalkID: "walk-1", StartedAt: time.Now()})
	_ = store.PutExtractionRun(context.Background(), domain.ExtractionRun{ID: "run-2", WalkID: "walk-1", StartedAt: time.Now()})

	uc := application.NewQueryExtractionUseCase(store)

	sums, err := uc.ListExtractionRuns(context.Background(), extractports.ExtractionRunFilter{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sums) != 2 {
		t.Errorf("got %d summaries, want 2", len(sums))
	}
}

func TestQueryExtractionUseCase_ListExtractionRuns_Error(t *testing.T) {
	listErr := errors.New("db failure")
	uc := application.NewQueryExtractionUseCase(&queryExtFakeStore{listErr: listErr})

	_, err := uc.ListExtractionRuns(context.Background(), extractports.ExtractionRunFilter{})
	if !errors.Is(err, listErr) {
		t.Errorf("got %v, want wrapping %v", err, listErr)
	}
}
