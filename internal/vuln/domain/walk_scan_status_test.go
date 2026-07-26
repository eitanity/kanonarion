package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

func TestDetermineWalkScanStatus(t *testing.T) {
	tests := []struct {
		name                          string
		failed, affected, unscannable int
		total                         int
		want                          domain.WalkScanStatus
	}{
		{"all failed -> Failed", 5, 0, 0, 5, domain.WalkStatusFailed},
		{"failed==total takes priority over affected", 3, 2, 0, 3, domain.WalkStatusFailed},
		{"zero modules -> Failed (failed==total boundary)", 0, 0, 0, 0, domain.WalkStatusFailed},
		{"any affected, everything else scanned -> Affected", 0, 1, 0, 4, domain.WalkStatusAffected},
		// Regression: incomplete coverage must not be concealed by a finding.
		// A run that both found something and could not analyse part of the build
		// list is not a complete run, and reporting Affected asserted a coverage
		// the run never had. Findings are still listed in the output; it is the
		// one-word status that must stop over-claiming.
		{"affected with some failed -> Partial, not Affected", 1, 2, 0, 5, domain.WalkStatusPartial},
		{"affected with some unscannable -> Partial, not Affected", 0, 7, 112, 285, domain.WalkStatusPartial},
		{"affected with both failed and unscannable -> Partial", 1, 2, 3, 9, domain.WalkStatusPartial},
		{"some failed, none affected -> Partial", 2, 0, 0, 5, domain.WalkStatusPartial},
		{"some unscannable, none affected -> Partial", 0, 0, 3, 5, domain.WalkStatusPartial},
		{"failed and unscannable, none affected -> Partial", 1, 0, 2, 5, domain.WalkStatusPartial},
		{"clean -> AllClean", 0, 0, 0, 5, domain.WalkStatusAllClean},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := domain.DetermineWalkScanStatus(tt.failed, tt.affected, tt.unscannable, tt.total)
			if got != tt.want {
				t.Errorf("DetermineWalkScanStatus(failed=%d, affected=%d, unscannable=%d, total=%d) = %q, want %q",
					tt.failed, tt.affected, tt.unscannable, tt.total, got, tt.want)
			}
		})
	}
}

func TestDetermineCoverageStatus(t *testing.T) {
	tests := []struct {
		name                string
		failed, unscannable int
		total               int
		want                domain.CoverageStatus
	}{
		{"all failed -> Failed", 5, 0, 5, domain.CoverageFailed},
		{"zero modules -> Failed (failed==total boundary)", 0, 0, 0, domain.CoverageFailed},
		{"some failed -> Partial", 2, 0, 5, domain.CoveragePartial},
		{"some unscannable -> Partial", 0, 3, 5, domain.CoveragePartial},
		{"failed and unscannable -> Partial", 1, 2, 5, domain.CoveragePartial},
		{"none unanalysed -> Complete", 0, 0, 5, domain.CoverageComplete},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := domain.DetermineCoverageStatus(tt.failed, tt.unscannable, tt.total); got != tt.want {
				t.Errorf("DetermineCoverageStatus(failed=%d, unscannable=%d, total=%d) = %q, want %q",
					tt.failed, tt.unscannable, tt.total, got, tt.want)
			}
		})
	}
}

func TestDetermineFindingsStatus(t *testing.T) {
	if got := domain.DetermineFindingsStatus(0); got != domain.FindingsClean {
		t.Errorf("DetermineFindingsStatus(0) = %q, want %q", got, domain.FindingsClean)
	}
	if got := domain.DetermineFindingsStatus(1); got != domain.FindingsAffected {
		t.Errorf("DetermineFindingsStatus(1) = %q, want %q", got, domain.FindingsAffected)
	}
}

// TestDetermineStatus_AxesIndependent pins the axis-independence invariant: coverage and
// findings are independent, so every combination is representable — including
// the two the single collapsed word cannot carry at once.
func TestDetermineStatus_AxesIndependent(t *testing.T) {
	// A run that both found something (affected=7) and left modules unanalysed
	// (unscannable=112) collapses to Partial, yet both axes retain their fact.
	if got := domain.DetermineWalkScanStatus(0, 7, 112, 285); got != domain.WalkStatusPartial {
		t.Fatalf("collapsed status = %q, want Partial", got)
	}
	if got := domain.DetermineCoverageStatus(0, 112, 285); got != domain.CoveragePartial {
		t.Errorf("coverage = %q, want Partial", got)
	}
	if got := domain.DetermineFindingsStatus(7); got != domain.FindingsAffected {
		t.Errorf("findings = %q, want Affected — the fact the collapsed word discards", got)
	}
}
