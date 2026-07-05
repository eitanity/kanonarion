package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/vendortree/application"
	"github.com/eitanity/kanonarion/internal/vendortree/domain"
)

type fakeVendorStore struct {
	records map[string]domain.Record
	err     error
}

func newFakeVendorStore() *fakeVendorStore {
	return &fakeVendorStore{records: make(map[string]domain.Record)}
}

func (s *fakeVendorStore) PutVendorRecord(_ context.Context, r domain.Record) error {
	if s.err != nil {
		return s.err
	}
	s.records[r.ProjectModulePath] = r
	return nil
}

func (s *fakeVendorStore) GetVendorRecord(_ context.Context, path string) (domain.Record, bool, error) {
	if s.err != nil {
		return domain.Record{}, false, s.err
	}
	r, ok := s.records[path]
	return r, ok, nil
}

func TestQueryVendor_GetFound(t *testing.T) {
	store := newFakeVendorStore()
	store.records["example.com/proj"] = domain.Record{
		ProjectModulePath: "example.com/proj",
		ContentHash:       "sha256:abc",
	}
	uc := application.NewQueryVendorUseCase(store)
	got, found, err := uc.Get(context.Background(), "example.com/proj")
	if err != nil || !found || got.ContentHash != "sha256:abc" {
		t.Fatalf("Get: err=%v found=%v hash=%s", err, found, got.ContentHash)
	}
}

func TestQueryVendor_GetNotFound(t *testing.T) {
	uc := application.NewQueryVendorUseCase(newFakeVendorStore())
	_, found, err := uc.Get(context.Background(), "example.com/never-scanned")
	if err != nil || found {
		t.Fatalf("expected not-found: err=%v found=%v", err, found)
	}
}

func TestQueryVendor_GetError(t *testing.T) {
	store := newFakeVendorStore()
	store.err = errors.New("db unavailable")
	uc := application.NewQueryVendorUseCase(store)
	_, _, err := uc.Get(context.Background(), "example.com/proj")
	if err == nil {
		t.Fatal("expected error from store")
	}
}
