package sqlite_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/example/domain"
)

// TestRefusesZeroCoordinate pins the value-object rule at this store.
func TestRefusesZeroCoordinate(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	coordinatetest.AssertRefusesZeroCoordinate(t, "PutExampleRecord", func() error {
		return s.PutExampleRecord(ctx, domain.ExampleRecord{})
	})
	coordinatetest.AssertRefusesZeroCoordinate(t, "GetExampleRecord", func() error {
		_, _, err := s.GetExampleRecord(ctx, zeroCoordinate(), "0.1.0")
		if err != nil {
			return fmt.Errorf("GetExampleRecord: %w", err)
		}
		return nil
	})
	coordinatetest.AssertRefusesZeroCoordinate(t, "FindBySymbolInModule", func() error {
		_, err := s.FindBySymbolInModule(ctx, zeroCoordinate(), "Sym", "0.1.0")
		if err != nil {
			return fmt.Errorf("FindBySymbolInModule: %w", err)
		}
		return nil
	})
}
