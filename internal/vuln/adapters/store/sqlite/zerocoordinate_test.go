package sqlite_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestRefusesZeroCoordinate pins the value-object rule at this store.
func TestRefusesZeroCoordinate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	coordinatetest.AssertRefusesZeroCoordinate(t, "PutVulnerabilityRecord", func() error {
		return s.PutVulnerabilityRecord(ctx, domain.VulnerabilityRecord{})
	})
	coordinatetest.AssertRefusesZeroCoordinate(t, "GetLatestVulnerabilityRecord", func() error {
		_, _, err := s.GetLatestVulnerabilityRecord(ctx, zeroCoordinate(), "0.1.0")
		if err != nil {
			return fmt.Errorf("GetLatestVulnerabilityRecord: %w", err)
		}
		return nil
	})
	coordinatetest.AssertRefusesZeroCoordinate(t, "ListVulnerabilityRecordsForModule", func() error {
		_, err := s.ListVulnerabilityRecordsForModule(ctx, zeroCoordinate(), "0.1.0")
		if err != nil {
			return fmt.Errorf("ListVulnerabilityRecordsForModule: %w", err)
		}
		return nil
	})
	coordinatetest.AssertRefusesZeroCoordinate(t, "ListVulnerabilityRecordsForModuleAllGenerations", func() error {
		_, err := s.ListVulnerabilityRecordsForModuleAllGenerations(ctx, zeroCoordinate())
		if err != nil {
			return fmt.Errorf("ListVulnerabilityRecordsForModuleAllGenerations: %w", err)
		}
		return nil
	})
}
