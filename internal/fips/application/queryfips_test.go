package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/fips/application"
	"github.com/eitanity/kanonarion/internal/fips/domain"
)

// TestQueryFIPS_GetFound: a stored record is returned with found=true.
func TestQueryFIPS_GetFound(t *testing.T) {
	store := &fakeStore{}
	rec := domain.Record{ProjectModulePath: "example.com/proj", ToolchainCapable: true, ToolchainVariant: "boringcrypto"}
	store.put = &rec

	uc := application.NewQueryFIPSUseCase(store)
	got, found, err := uc.Get(context.Background(), "example.com/proj")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !found {
		t.Fatal("expected found=true")
	}
	if got.ToolchainVariant != "boringcrypto" {
		t.Errorf("variant = %q, want boringcrypto", got.ToolchainVariant)
	}
}

// TestQueryFIPS_GetNotFound: a project never scanned returns found=false with
// no error — the "not analysed" state.
func TestQueryFIPS_GetNotFound(t *testing.T) {
	store := &fakeStore{}
	uc := application.NewQueryFIPSUseCase(store)
	_, found, err := uc.Get(context.Background(), "example.com/never-scanned")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if found {
		t.Error("expected found=false for un-scanned project")
	}
}

// TestQueryFIPS_GetStoreError: store errors are wrapped and surfaced.
func TestQueryFIPS_GetStoreError(t *testing.T) {
	store := &errStore{err: errors.New("db unavailable")}
	uc := application.NewQueryFIPSUseCase(store)
	_, _, err := uc.Get(context.Background(), "example.com/proj")
	if err == nil {
		t.Fatal("expected error from store")
	}
}

type errStore struct{ err error }

func (s *errStore) PutFIPSRecord(_ context.Context, _ domain.Record) error { return s.err }
func (s *errStore) GetFIPSRecord(_ context.Context, _ string) (domain.Record, bool, error) {
	return domain.Record{}, false, s.err
}
