package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestUnscanReason_ExpectedOutOfToolchain confirms only the version-not-in-toolchain
// reason reads as an expected metadata-only outcome; every genuine fault does not.
func TestUnscanReason_ExpectedOutOfToolchain(t *testing.T) {
	if !domain.UnscanReasonVersionNotInToolchain.ExpectedOutOfToolchain() {
		t.Errorf("version-not-in-toolchain must be expected out-of-toolchain")
	}
	for _, r := range []domain.UnscanReason{
		domain.UnscanReasonNoGoMod,
		domain.UnscanReason(""),
	} {
		if r.ExpectedOutOfToolchain() {
			t.Errorf("%q must not read as expected out-of-toolchain", r)
		}
	}
}

// TestSnapshotAgeDays covers a normal lag, a zero retrieved-at, and clock skew
// where validation precedes retrieval — the last two both clamp to zero.
func TestSnapshotAgeDays(t *testing.T) {
	retrieved := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	validated := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	if got := domain.SnapshotAgeDays(validated, retrieved); got != 3 {
		t.Errorf("age = %d, want 3 whole days", got)
	}
	if got := domain.SnapshotAgeDays(validated, time.Time{}); got != 0 {
		t.Errorf("zero retrieved-at must clamp to 0, got %d", got)
	}
	if got := domain.SnapshotAgeDays(retrieved, validated); got != 0 {
		t.Errorf("validated-before-retrieved must clamp to 0, got %d", got)
	}
}

// TestVulnerabilityRecord_UnmarshalJSON_Malformed covers the decode-error path:
// invalid JSON is a hard error, not a silently empty record.
func TestVulnerabilityRecord_UnmarshalJSON_Malformed(t *testing.T) {
	var r domain.VulnerabilityRecord
	if err := r.UnmarshalJSON([]byte(`{not json`)); err == nil {
		t.Fatalf("malformed JSON must error")
	}
}

// TestVulnerabilityRecord_UnmarshalJSON_ForeignEcosystem covers the fail-closed
// rejection of a non-Go ecosystem value.
func TestVulnerabilityRecord_UnmarshalJSON_ForeignEcosystem(t *testing.T) {
	var r domain.VulnerabilityRecord
	err := r.UnmarshalJSON([]byte(`{"ecosystem":"npm","coordinate":{"path":"x","version":"v1.0.0"}}`))
	if !errors.Is(err, fetchdomain.ErrUnsupportedEcosystem) {
		t.Fatalf("foreign ecosystem must be rejected, got %v", err)
	}
}

// TestCompareFindingDelta_IDTiebreak covers the finding-ID tiebreak, the last
// discriminator when module path and version are identical.
func TestCompareFindingDelta_IDTiebreak(t *testing.T) {
	c := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	a := domain.FindingDelta{Coordinate: c, Finding: domain.VulnerabilityFinding{ID: "GO-1"}}
	b := domain.FindingDelta{Coordinate: c, Finding: domain.VulnerabilityFinding{ID: "GO-2"}}
	if got := domain.CompareFindingDelta(a, b); got != -1 {
		t.Errorf("GO-1 vs GO-2: got %d, want -1", got)
	}
	if got := domain.CompareFindingDelta(b, a); got != 1 {
		t.Errorf("GO-2 vs GO-1: got %d, want 1", got)
	}

	// Path comparison in the greater-than direction (a > b → 1).
	pz := domain.FindingDelta{Coordinate: coordinate.ModuleCoordinate{Path: "github.com/zzz/pkg", Version: "v1.0.0"}}
	pa := domain.FindingDelta{Coordinate: coordinate.ModuleCoordinate{Path: "github.com/aaa/pkg", Version: "v1.0.0"}}
	if got := domain.CompareFindingDelta(pz, pa); got != 1 {
		t.Errorf("zzz vs aaa: got %d, want 1", got)
	}
}

// TestDiffScanRuns_TwoReachabilityChangesSorted forces the reachability-change
// sort comparator to run: two findings flip reachability, so SortFunc must order
// more than one element and the comparator closure is exercised.
func TestDiffScanRuns_TwoReachabilityChangesSorted(t *testing.T) {
	cz := coordinate.ModuleCoordinate{Path: "github.com/zzz/mod", Version: "v1.0.0"}
	ca := coordinate.ModuleCoordinate{Path: "github.com/aaa/mod", Version: "v1.0.0"}
	before := []domain.VulnerabilityRecord{
		{Coordinate: cz, WalkID: "walk-1", Findings: []domain.VulnerabilityFinding{{ID: "VULN-Z", Reachable: &domain.ReachabilityResult{IsReachable: false}}}},
		{Coordinate: ca, WalkID: "walk-1", Findings: []domain.VulnerabilityFinding{{ID: "VULN-A", Reachable: &domain.ReachabilityResult{IsReachable: false}}}},
	}
	after := []domain.VulnerabilityRecord{
		{Coordinate: cz, WalkID: "walk-1", Findings: []domain.VulnerabilityFinding{{ID: "VULN-Z", Reachable: &domain.ReachabilityResult{IsReachable: true}}}},
		{Coordinate: ca, WalkID: "walk-1", Findings: []domain.VulnerabilityFinding{{ID: "VULN-A", Reachable: &domain.ReachabilityResult{IsReachable: true}}}},
	}

	diff := domain.DiffScanRuns(
		domain.WalkScanRun{ID: "a", WalkID: "walk-1"},
		domain.WalkScanRun{ID: "b", WalkID: "walk-1"},
		before, after,
	)

	if len(diff.ReachabilityChanges) != 2 {
		t.Fatalf("expected two reachability changes, got %+v", diff.ReachabilityChanges)
	}
	// Deterministic order: aaa/mod sorts before zzz/mod.
	if diff.ReachabilityChanges[0].Coordinate.Path != "github.com/aaa/mod" {
		t.Errorf("reachability changes not sorted by module path: %+v", diff.ReachabilityChanges)
	}
}

// TestDiffScanRuns_ModuleAppearsAndDisappears covers the whole-coordinate arms of
// both diff loops: a module present only in B contributes new findings, and a
// module present only in A contributes resolved findings.
func TestDiffScanRuns_ModuleAppearsAndDisappears(t *testing.T) {
	only := func(path string) coordinate.ModuleCoordinate {
		return coordinate.ModuleCoordinate{Path: path, Version: "v1.0.0"}
	}
	added := only("github.com/added/mod")
	removed := only("github.com/removed/mod")
	mk := func(c coordinate.ModuleCoordinate, id string) domain.VulnerabilityRecord {
		return domain.VulnerabilityRecord{Coordinate: c, WalkID: "walk-1", Findings: []domain.VulnerabilityFinding{{ID: id}}}
	}

	diff := domain.DiffScanRuns(
		domain.WalkScanRun{ID: "a", WalkID: "walk-1"},
		domain.WalkScanRun{ID: "b", WalkID: "walk-1"},
		[]domain.VulnerabilityRecord{mk(removed, "VULN-REMOVED")},
		[]domain.VulnerabilityRecord{mk(added, "VULN-ADDED")},
	)

	if len(diff.NewFindings) != 1 || diff.NewFindings[0].Finding.ID != "VULN-ADDED" {
		t.Errorf("expected VULN-ADDED as new, got %+v", diff.NewFindings)
	}
	if len(diff.ResolvedFindings) != 1 || diff.ResolvedFindings[0].Finding.ID != "VULN-REMOVED" {
		t.Errorf("expected VULN-REMOVED as resolved, got %+v", diff.ResolvedFindings)
	}
}

// TestDiffScanRuns_PresentBothNilReachability covers reachabilityChanged's
// both-nil branch: a finding present in both runs with no reachability verdict on
// either side is not a reachability change.
func TestDiffScanRuns_PresentBothNilReachability(t *testing.T) {
	c := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	rec := domain.VulnerabilityRecord{
		Coordinate: c, WalkID: "walk-1",
		Findings: []domain.VulnerabilityFinding{{ID: "VULN-1"}}, // nil Reachable
	}
	diff := domain.DiffScanRuns(
		domain.WalkScanRun{ID: "a", WalkID: "walk-1"},
		domain.WalkScanRun{ID: "b", WalkID: "walk-1"},
		[]domain.VulnerabilityRecord{rec},
		[]domain.VulnerabilityRecord{rec},
	)
	if len(diff.NewFindings) != 0 || len(diff.ResolvedFindings) != 0 || len(diff.ReachabilityChanges) != 0 {
		t.Errorf("both-nil reachability must produce empty diff, got %+v", diff)
	}
}
