package application

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// DiffScanRunsUseCase compares two WalkScanRuns of the same walk.
type DiffScanRunsUseCase struct {
	vulnStore ports.VulnerabilityStore
}

// NewDiffScanRunsUseCase returns a new DiffScanRunsUseCase.
func NewDiffScanRunsUseCase(vulnStore ports.VulnerabilityStore) *DiffScanRunsUseCase {
	return &DiffScanRunsUseCase{vulnStore: vulnStore}
}

// Diff loads scan runs A and B plus their vulnerability records, then delegates
// the comparison to domain.DiffScanRuns.
func (uc *DiffScanRunsUseCase) Diff(ctx context.Context, runIDA, runIDB string) (domain.ScanRunDiff, error) {
	runA, foundA, err := uc.vulnStore.GetWalkScanRun(ctx, runIDA)
	if err != nil {
		return domain.ScanRunDiff{}, fmt.Errorf("getting scan run A %q: %w", runIDA, err)
	}
	if !foundA {
		return domain.ScanRunDiff{}, fmt.Errorf("scan run not found: %s", runIDA)
	}

	runB, foundB, err := uc.vulnStore.GetWalkScanRun(ctx, runIDB)
	if err != nil {
		return domain.ScanRunDiff{}, fmt.Errorf("getting scan run B %q: %w", runIDB, err)
	}
	if !foundB {
		return domain.ScanRunDiff{}, fmt.Errorf("scan run not found: %s", runIDB)
	}

	if runA.WalkID != runB.WalkID {
		return domain.ScanRunDiff{}, fmt.Errorf("scan runs belong to different walks: %s vs %s", runA.WalkID, runB.WalkID)
	}

	// Generations this build cannot reproduce are left out of both sides and
	// returned beside the diff, which was computed without them; an altered row
	// still refuses.
	var aside []recordseal.SetAsideRow
	recsA, err := uc.vulnStore.ListVulnerabilityRecords(ctx, runIDA)
	if aside, _ = recordseal.MergeSetAside(aside, err); err != nil && !isSetAside(err) {
		return domain.ScanRunDiff{}, fmt.Errorf("listing vulnerability records for run A: %w", err)
	}
	recsB, err := uc.vulnStore.ListVulnerabilityRecords(ctx, runIDB)
	if aside, _ = recordseal.MergeSetAside(aside, err); err != nil && !isSetAside(err) {
		return domain.ScanRunDiff{}, fmt.Errorf("listing vulnerability records for run B: %w", err)
	}

	diff := domain.DiffScanRuns(runA, runB, recsA, recsB)
	if len(aside) > 0 {
		return diff, &recordseal.SetAside{Rows: aside}
	}
	return diff, nil
}

// isSetAside reports whether err is the store's report of generations it set
// aside, the one error a read returns beside a complete answer.
func isSetAside(err error) bool { return recordseal.IsSetAside(err) }
