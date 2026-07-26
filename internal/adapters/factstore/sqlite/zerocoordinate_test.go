package sqlite_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

// TestRefusesZeroCoordinate pins the value-object rule on the fact store's read
// legs. The write leg is already closed by domain.ErrUnsealedRecord, which the
// zero SealedRecord trips first — a record that seals nothing is refused before
// anything asks what module it describes.
func TestRefusesZeroCoordinate(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()
	zero := coordinate.ModuleCoordinate{}

	coordinatetest.AssertRefusesZeroCoordinate(t, "GetFetchRecord", func() error {
		_, _, err := s.GetFetchRecord(ctx, zero, "0.1.0")
		if err != nil {
			return fmt.Errorf("GetFetchRecord: %w", err)
		}
		return nil
	})
	coordinatetest.AssertRefusesZeroCoordinate(t, "ListFetchRecords", func() error {
		_, err := s.ListFetchRecords(ctx, zero, "0.1.0")
		if err != nil {
			return fmt.Errorf("ListFetchRecords: %w", err)
		}
		return nil
	})
	coordinatetest.AssertRefusesZeroCoordinate(t, "ListAttestations", func() error {
		_, err := s.ListAttestations(ctx, zero, "0.1.0")
		if err != nil {
			return fmt.Errorf("ListAttestations: %w", err)
		}
		return nil
	})
}
