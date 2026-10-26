package sqlite_test

import (
	"context"
	"fmt"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	"code.eitanity.com/kanonarion/internal/iface/domain"
)

// TestRefusesZeroCoordinate pins the value-object rule at this store.
func TestRefusesZeroCoordinate(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()

	coordinatetest.AssertRefusesZeroCoordinate(t, "PutInterfaceRecord", func() error {
		return s.PutInterfaceRecord(ctx, domain.InterfaceRecord{})
	})
	coordinatetest.AssertRefusesZeroCoordinate(t, "GetInterfaceRecord", func() error {
		_, _, err := s.GetInterfaceRecord(ctx, zeroCoordinate(), "0.1.0")
		if err != nil {
			return fmt.Errorf("GetInterfaceRecord: %w", err)
		}
		return nil
	})
}
