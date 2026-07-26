package sqlite_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/license/domain"
)

// TestRefusesZeroCoordinate pins the value-object rule at this store. A licence
// record is the one this matters most for: an all-empty row would read back as
// a genuine licence measurement of a module that does not exist.
func TestRefusesZeroCoordinate(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	coordinatetest.AssertRefusesZeroCoordinate(t, "PutLicenseRecord", func() error {
		return s.PutLicenseRecord(ctx, domain.LicenseRecord{})
	})
	coordinatetest.AssertRefusesZeroCoordinate(t, "GetLicenseRecord", func() error {
		_, _, err := s.GetLicenseRecord(ctx, zeroCoordinate(), "0.1.0")
		if err != nil {
			return fmt.Errorf("GetLicenseRecord: %w", err)
		}
		return nil
	})
}
