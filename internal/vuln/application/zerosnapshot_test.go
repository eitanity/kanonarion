package application_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// TestFakeVulnStoreRefusesZeroSnapshot holds the fake to the same contract the
// real store keeps.
//
// A fake that accepts the zero snapshot lets a use-case test here go green on a
// call the sqlite store rejects — the application layer would then be shipped
// having only ever been exercised against a store that tolerated the one value
// the ledger cannot key on.
func TestFakeVulnStoreRefusesZeroSnapshot(t *testing.T) {
	ctx := context.Background()
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	zero := domain.DatabaseSnapshot{}

	vulntest.AssertRefusesZeroSnapshot(t, "PutVulnerabilityRecord", func() error {
		return newFakeVulnStore().PutVulnerabilityRecord(ctx, domain.VulnerabilityRecord{Coordinate: coord})
	})
	vulntest.AssertRefusesZeroSnapshot(t, "GetVulnerabilityRecord", func() error {
		_, _, err := newFakeVulnStore().GetVulnerabilityRecord(ctx, coord, "0.1.0", zero)
		if err != nil {
			return fmt.Errorf("GetVulnerabilityRecord: %w", err)
		}
		return nil
	})
	vulntest.AssertRefusesZeroSnapshot(t, "GetVulnerabilityRecordAt", func() error {
		_, _, err := newFakeVulnStore().GetVulnerabilityRecordAt(ctx, coord, "0.1.0", zero, domain.RootingIsolated)
		if err != nil {
			return fmt.Errorf("GetVulnerabilityRecordAt: %w", err)
		}
		return nil
	})
	vulntest.AssertRefusesZeroSnapshot(t, "HasVulnerabilityRecord", func() error {
		_, err := newFakeVulnStore().HasVulnerabilityRecord(ctx, coord, "0.1.0", zero, "abc")
		if err != nil {
			return fmt.Errorf("HasVulnerabilityRecord: %w", err)
		}
		return nil
	})
	vulntest.AssertRefusesZeroSnapshot(t, "PutDatabaseSnapshot", func() error {
		return newFakeVulnStore().PutDatabaseSnapshot(ctx, zero, strings.NewReader("advisories"))
	})
	vulntest.AssertRefusesZeroSnapshot(t, "GetDatabaseSnapshot", func() error {
		_, err := newFakeVulnStore().GetDatabaseSnapshot(ctx, zero)
		if err != nil {
			return fmt.Errorf("GetDatabaseSnapshot: %w", err)
		}
		return nil
	})
}
