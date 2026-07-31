package sqlite_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// TestRefusesZeroSnapshot pins the value-object rule on the other identity axis
// at this store: every method that takes a snapshot refuses the zero one, on
// both legs.
//
// The write leg because vulnerability_records composes on (coordinate, pipeline
// version, snapshot) and an admitted row joins the group holding every other
// record that named no snapshot; the read legs because absence is the wrong
// answer to a question about no advisory database, and because such a read would
// serve precisely that collided group.
func TestRefusesZeroSnapshot(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")

	vulntest.AssertRefusesZeroSnapshot(t, "PutVulnerabilityRecord", func() error {
		rec := seal(t, domain.VulnerabilityRecord{
			Coordinate:      coord,
			PipelineVersion: "0.1.0",
			OverallStatus:   domain.StatusClean,
		})
		return s.PutVulnerabilityRecord(ctx, rec)
	})
	vulntest.AssertRefusesZeroSnapshot(t, "GetVulnerabilityRecord", func() error {
		_, _, err := s.GetVulnerabilityRecord(ctx, coord, "0.1.0", domain.DatabaseSnapshot{})
		if err != nil {
			return fmt.Errorf("GetVulnerabilityRecord: %w", err)
		}
		return nil
	})
	vulntest.AssertRefusesZeroSnapshot(t, "GetVulnerabilityRecordAt", func() error {
		_, _, err := s.GetVulnerabilityRecordAt(ctx, coord, "0.1.0", domain.DatabaseSnapshot{}, domain.RootingIsolated)
		if err != nil {
			return fmt.Errorf("GetVulnerabilityRecordAt: %w", err)
		}
		return nil
	})
	vulntest.AssertRefusesZeroSnapshot(t, "HasVulnerabilityRecord", func() error {
		_, err := s.HasVulnerabilityRecord(ctx, coord, "0.1.0", domain.DatabaseSnapshot{}, "abc")
		if err != nil {
			return fmt.Errorf("HasVulnerabilityRecord: %w", err)
		}
		return nil
	})
	vulntest.AssertRefusesZeroSnapshot(t, "PutDatabaseSnapshot", func() error {
		return s.PutDatabaseSnapshot(ctx, domain.DatabaseSnapshot{}, strings.NewReader("advisories"))
	})
	vulntest.AssertRefusesZeroSnapshot(t, "GetDatabaseSnapshot", func() error {
		_, err := s.GetDatabaseSnapshot(ctx, domain.DatabaseSnapshot{})
		if err != nil {
			return fmt.Errorf("GetDatabaseSnapshot: %w", err)
		}
		return nil
	})
}

// TestPutDatabaseSnapshot_RefusalLeavesTheTableUntouched is the leg the shared
// assertion deliberately does not cover: that the refusal happened before the
// write, not after it. A guard placed after the insert would satisfy every
// assertion above and still have keyed a row on the empty pin.
func TestPutDatabaseSnapshot_RefusalLeavesTheTableUntouched(t *testing.T) {
	ctx := t.Context()
	s := newTestStore(t)

	if err := s.PutDatabaseSnapshot(ctx, domain.DatabaseSnapshot{}, strings.NewReader("advisories")); err == nil {
		t.Fatal("PutDatabaseSnapshot(zero) = nil, want a refusal")
	}

	snapshots, err := s.ListDatabaseSnapshots(ctx)
	if err != nil {
		t.Fatalf("ListDatabaseSnapshots: %v", err)
	}
	if len(snapshots) != 0 {
		t.Fatalf("the refused write left %d snapshot(s) behind: %v", len(snapshots), snapshots)
	}
}
