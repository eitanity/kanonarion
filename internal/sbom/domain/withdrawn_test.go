package domain_test

import (
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/sbom/domain"
)

var sbomWithdrawnAt = time.Date(2026, 4, 8, 13, 33, 56, 0, time.UTC)

func bboltRef() domain.ModuleRef {
	return domain.ModuleRef{Path: "go.etcd.io/bbolt", Version: "v1.4.3"}
}

// TestAggregateVulnerabilities_CarriesTheRetraction is the SBOM half of the
// withdrawn-advisory fix. The aggregation is the last place the timestamp can be
// lost before the document is written, and losing it there publishes a retracted
// report to every consumer of the SBOM as a live vulnerability of the component.
func TestAggregateVulnerabilities_CarriesTheRetraction(t *testing.T) {
	got := domain.AggregateVulnerabilities([]domain.FindingInput{{
		Module:      bboltRef(),
		ID:          "GO-2026-4923",
		Summary:     "WITHDRAWN: out-of-range-index in go.etcd.io/bbolt",
		WithdrawnAt: sbomWithdrawnAt,
	}})

	if len(got) != 1 {
		t.Fatalf("aggregated %d vulnerabilities, want 1", len(got))
	}
	if !got[0].IsWithdrawn() {
		t.Error("aggregated vulnerability does not report the retraction")
	}
	if !got[0].WithdrawnAt.Equal(sbomWithdrawnAt) {
		t.Errorf("WithdrawnAt = %s, want %s", got[0].WithdrawnAt, sbomWithdrawnAt)
	}
}

// TestAggregateVulnerabilities_LiveAdvisoryCarriesNoRetraction is the control.
// Without it a change that marked everything withdrawn would pass the test above,
// and marking a live advisory retracted is the more dangerous direction of the two.
func TestAggregateVulnerabilities_LiveAdvisoryCarriesNoRetraction(t *testing.T) {
	got := domain.AggregateVulnerabilities([]domain.FindingInput{{
		Module:  domain.ModuleRef{Path: "golang.org/x/text", Version: "v0.37.0"},
		ID:      "GO-2026-5970",
		Summary: "Infinite loop on invalid input in golang.org/x/text",
	}})

	if len(got) != 1 {
		t.Fatalf("aggregated %d vulnerabilities, want 1", len(got))
	}
	if got[0].IsWithdrawn() {
		t.Errorf("a live advisory reports as withdrawn at %s", got[0].WithdrawnAt)
	}
}

// TestAggregateVulnerabilities_FirstOccurrenceWithoutADateDoesNotWin covers the
// rule that differs from the one summary and severity follow. Occurrences of one
// advisory cannot legitimately disagree about whether it was retracted — but one
// may have been written by a generation that never read the field, and a zero
// there means "not asked", never "confirmed live". Taking the first occurrence
// outright would let that older record republish the advisory as live.
func TestAggregateVulnerabilities_FirstOccurrenceWithoutADateDoesNotWin(t *testing.T) {
	got := domain.AggregateVulnerabilities([]domain.FindingInput{
		{
			Module:  bboltRef(),
			ID:      "GO-2026-4923",
			Summary: "WITHDRAWN: out-of-range-index in go.etcd.io/bbolt",
		},
		{
			Module:      domain.ModuleRef{Path: "go.etcd.io/bbolt", Version: "v1.4.2"},
			ID:          "GO-2026-4923",
			Summary:     "WITHDRAWN: out-of-range-index in go.etcd.io/bbolt",
			WithdrawnAt: sbomWithdrawnAt,
		},
	})

	if len(got) != 1 {
		t.Fatalf("aggregated %d vulnerabilities, want 1 (same ID)", len(got))
	}
	if !got[0].IsWithdrawn() {
		t.Error("a retraction recorded on a later occurrence was dropped by the first, which never read the field")
	}
	if len(got[0].Affected) != 2 {
		t.Errorf("affected modules = %d, want both occurrences retained", len(got[0].Affected))
	}
}
