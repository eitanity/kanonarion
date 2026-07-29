package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestDiffScanRuns_WithdrawalIsAttributedNotResolved is the diff half of the fix.
//
// The "resolved / no longer known" bucket collapsed three different histories —
// upstream fixed it, we upgraded, the advisory was retracted — into one green
// label, and a review acted on the wrong one. A retraction now has its own bucket,
// so the diff attributes the transition instead of merely detecting it.
func TestDiffScanRuns_WithdrawalIsAttributedNotResolved(t *testing.T) {
	c := coord("go.etcd.io/bbolt")
	runA := domain.WalkScanRun{ID: "a", WalkID: "walk-1"}
	runB := domain.WalkScanRun{ID: "b", WalkID: "walk-1"}

	live := domain.VulnerabilityFinding{ID: "GO-2026-4923", Summary: "out-of-range-index"}
	retracted := domain.VulnerabilityFinding{
		ID:          "GO-2026-4923",
		Summary:     "WITHDRAWN: out-of-range-index",
		WithdrawnAt: withdrawnAt,
	}

	diff := domain.DiffScanRuns(runA, runB,
		[]domain.VulnerabilityRecord{record(c, live)},
		[]domain.VulnerabilityRecord{record(c, retracted)},
	)

	if len(diff.WithdrawnFindings) != 1 || diff.WithdrawnFindings[0].Finding.ID != "GO-2026-4923" {
		t.Fatalf("WithdrawnFindings = %+v, want the retraction attributed", diff.WithdrawnFindings)
	}
	if !diff.WithdrawnFindings[0].Finding.WithdrawnAt.Equal(withdrawnAt) {
		t.Errorf("withdrawal date = %v, want %v: the bucket exists to carry the reason",
			diff.WithdrawnFindings[0].Finding.WithdrawnAt, withdrawnAt)
	}
	// It is not any of the other three verdicts. In particular it is not resolved:
	// the finding is still in B, retained as the historical fact, so the old bucket
	// would never have seen it once the retraction became readable.
	if len(diff.ResolvedFindings) != 0 {
		t.Errorf("ResolvedFindings = %+v, want empty — a retraction is attributed, not resolved", diff.ResolvedFindings)
	}
	if len(diff.NewFindings) != 0 || len(diff.ReachabilityChanges) != 0 || len(diff.UnresolvedFindings) != 0 {
		t.Errorf("unexpected other deltas: new=%+v reach=%+v unresolved=%+v",
			diff.NewFindings, diff.ReachabilityChanges, diff.UnresolvedFindings)
	}
}

// A finding A already knew was retracted, and B no longer reports at all, is
// attributed to the withdrawal rather than to an unexplained disappearance. The
// reason is a fact on the finding, so it does not need to be inferred from the
// absence — which is what the fidelity guard exists to refuse to do.
func TestDiffScanRuns_AlreadyWithdrawnAndAbsentFromBIsAttributed(t *testing.T) {
	c := coord("go.etcd.io/bbolt")
	runA := domain.WalkScanRun{ID: "a", WalkID: "walk-1"}
	runB := domain.WalkScanRun{ID: "b", WalkID: "walk-1"}

	retracted := domain.VulnerabilityFinding{ID: "GO-2026-4923", WithdrawnAt: withdrawnAt}

	diff := domain.DiffScanRuns(runA, runB,
		[]domain.VulnerabilityRecord{record(c, retracted)},
		[]domain.VulnerabilityRecord{record(c)},
	)

	if len(diff.WithdrawnFindings) != 1 {
		t.Fatalf("WithdrawnFindings = %+v, want 1", diff.WithdrawnFindings)
	}
	if len(diff.ResolvedFindings) != 0 {
		t.Errorf("ResolvedFindings = %+v, want empty", diff.ResolvedFindings)
	}
}

// The unattributed disappearance still goes to ResolvedFindings. The bucket is not
// gone — it is narrower, and now means only what its name says: no longer
// reported, with no reason recorded. That is the honest label for the case, and
// keeping it distinct from the withdrawal is the whole point of the split.
func TestDiffScanRuns_UnexplainedDisappearanceStaysResolved(t *testing.T) {
	c := coord("github.com/foo/bar")
	runA := domain.WalkScanRun{ID: "a", WalkID: "walk-1"}
	runB := domain.WalkScanRun{ID: "b", WalkID: "walk-1"}

	diff := domain.DiffScanRuns(runA, runB,
		[]domain.VulnerabilityRecord{record(c, finding("VULN-OLD"))},
		[]domain.VulnerabilityRecord{record(c)},
	)

	if len(diff.ResolvedFindings) != 1 || diff.ResolvedFindings[0].Finding.ID != "VULN-OLD" {
		t.Fatalf("ResolvedFindings = %+v, want VULN-OLD", diff.ResolvedFindings)
	}
	if len(diff.WithdrawnFindings) != 0 {
		t.Errorf("WithdrawnFindings = %+v, want empty: nothing recorded a retraction", diff.WithdrawnFindings)
	}
}
