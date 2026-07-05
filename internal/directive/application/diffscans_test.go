package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/directive/application"
	"github.com/eitanity/kanonarion/internal/directive/domain"
)

type diffFakeStore struct{ records map[string]domain.Record }

func (s *diffFakeStore) PutDirectiveRecord(context.Context, domain.Record) error { return nil }
func (s *diffFakeStore) GetDirectiveRecord(context.Context, string) (domain.Record, bool, error) {
	return domain.Record{}, false, nil
}
func (s *diffFakeStore) GetScanByID(_ context.Context, scanID string) (domain.Record, bool, error) {
	r, ok := s.records[scanID]
	return r, ok, nil
}
func (s *diffFakeStore) ListScans(context.Context, string, int) ([]domain.Record, error) {
	return nil, nil
}

// DiffScansUseCase loads two scans by ID and returns the deterministic
// delta. A missing scan ID yields *ErrScanNotFound so the CLI can map to an
// actionable exit code rather than a generic error.
func TestDiffScansUseCase_DeltaAndMissing(t *testing.T) {
	scanA := domain.Record{ID: "01A", ProjectModulePath: "example.com/proj"}
	scanB := domain.Record{ID: "01B", ProjectModulePath: "example.com/proj",
		Directives: []domain.Directive{{Kind: domain.KindReplace, Source: "go.mod", Line: 7,
			OldPath: "example.com/foo", NewPath: "example.com/fork", NewVersion: "v1", Class: domain.RiskHigh}}}

	store := &diffFakeStore{records: map[string]domain.Record{"01A": scanA, "01B": scanB}}
	uc := application.NewDiffScansUseCase(store)

	t.Run("delta", func(t *testing.T) {
		diff, err := uc.Diff(context.Background(), "01A", "01B")
		if err != nil {
			t.Fatalf("Diff: %v", err)
		}
		if len(diff.Added) != 1 {
			t.Fatalf("Added = %d, want 1", len(diff.Added))
		}
	})

	t.Run("missing scan ID surfaces ErrScanNotFound", func(t *testing.T) {
		_, err := uc.Diff(context.Background(), "01A", "DOESNOTEXIST")
		var notFound *application.ErrScanNotFound
		if !errors.As(err, &notFound) {
			t.Fatalf("err = %v, want *ErrScanNotFound", err)
		}
		if notFound.ScanID != "DOESNOTEXIST" {
			t.Errorf("ScanID = %q, want DOESNOTEXIST", notFound.ScanID)
		}
	})

	t.Run("different projects rejected", func(t *testing.T) {
		store.records["other"] = domain.Record{ID: "other", ProjectModulePath: "example.com/different"}
		_, err := uc.Diff(context.Background(), "01A", "other")
		if err == nil {
			t.Fatal("expected error for cross-project diff, got nil")
		}
	})

	t.Run("missing scan A surfaces ErrScanNotFound", func(t *testing.T) {
		_, err := uc.Diff(context.Background(), "MISSING_A", "01B")
		var notFound *application.ErrScanNotFound
		if !errors.As(err, &notFound) {
			t.Fatalf("err = %v, want *ErrScanNotFound", err)
		}
		if notFound.ScanID != "MISSING_A" {
			t.Errorf("ScanID = %q, want MISSING_A", notFound.ScanID)
		}
	})
}

func TestErrScanNotFound_Error(t *testing.T) {
	e := &application.ErrScanNotFound{ScanID: "abc-123"}
	if e.Error() == "" {
		t.Fatal("Error() returned empty string")
	}
}
