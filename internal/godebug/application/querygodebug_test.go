package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/godebug/application"
	"github.com/eitanity/kanonarion/internal/godebug/domain"
)

type fakeGoDebugStore struct {
	records map[string]domain.Record
	err     error
}

func newFakeGoDebugStore() *fakeGoDebugStore {
	return &fakeGoDebugStore{records: make(map[string]domain.Record)}
}

func (s *fakeGoDebugStore) PutGoDebugRecord(_ context.Context, r domain.Record) error {
	if s.err != nil {
		return s.err
	}
	s.records[r.ProjectModulePath] = r
	return nil
}

func (s *fakeGoDebugStore) GetGoDebugRecord(_ context.Context, path string) (domain.Record, bool, error) {
	if s.err != nil {
		return domain.Record{}, false, s.err
	}
	r, ok := s.records[path]
	return r, ok, nil
}

func TestQueryGoDebug_GetFound(t *testing.T) {
	store := newFakeGoDebugStore()
	store.records["example.com/proj"] = domain.Record{
		ProjectModulePath: "example.com/proj",
		ContentHash:       "sha256:test",
	}
	uc := application.NewQueryGoDebugUseCase(store)
	got, found, err := uc.Get(context.Background(), "example.com/proj")
	if err != nil || !found || got.ContentHash != "sha256:test" {
		t.Fatalf("Get: err=%v found=%v hash=%s", err, found, got.ContentHash)
	}
}

func TestQueryGoDebug_GetNotFound(t *testing.T) {
	uc := application.NewQueryGoDebugUseCase(newFakeGoDebugStore())
	_, found, err := uc.Get(context.Background(), "example.com/never-scanned")
	if err != nil || found {
		t.Fatalf("expected not-found: err=%v found=%v", err, found)
	}
}

func TestQueryGoDebug_GetError(t *testing.T) {
	store := newFakeGoDebugStore()
	store.err = errors.New("db unavailable")
	uc := application.NewQueryGoDebugUseCase(store)
	_, _, err := uc.Get(context.Background(), "example.com/proj")
	if err == nil {
		t.Fatal("expected error from store")
	}
}
