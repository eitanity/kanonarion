package domain_test

import (
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

func coord(path string) fetchdomain.ModuleCoordinate {
	return fetchdomain.ModuleCoordinate{Path: path, Version: "v1.0.0"}
}

func record(c fetchdomain.ModuleCoordinate, findings ...domain.VulnerabilityFinding) domain.VulnerabilityRecord {
	return domain.VulnerabilityRecord{Coordinate: c, WalkID: "walk-1", Findings: findings}
}

func finding(id string) domain.VulnerabilityFinding {
	return domain.VulnerabilityFinding{ID: id, Summary: id}
}

func findingReach(id string, reachable bool) domain.VulnerabilityFinding {
	return domain.VulnerabilityFinding{
		ID:        id,
		Summary:   id,
		Reachable: &domain.ReachabilityResult{IsReachable: reachable},
	}
}

func TestDiffScanRuns_NewFinding(t *testing.T) {
	c := coord("github.com/foo/bar")
	runA := domain.WalkScanRun{ID: "a", WalkID: "walk-1"}
	runB := domain.WalkScanRun{ID: "b", WalkID: "walk-1"}

	diff := domain.DiffScanRuns(runA, runB,
		[]domain.VulnerabilityRecord{record(c)},
		[]domain.VulnerabilityRecord{record(c, finding("VULN-2"))},
	)

	if len(diff.NewFindings) != 1 || diff.NewFindings[0].Finding.ID != "VULN-2" {
		t.Fatalf("expected one new finding VULN-2, got %+v", diff.NewFindings)
	}
	if len(diff.ResolvedFindings) != 0 || len(diff.ReachabilityChanges) != 0 {
		t.Errorf("unexpected resolved/reachability deltas: %+v", diff)
	}
}

func TestDiffScanRuns_ResolvedFinding(t *testing.T) {
	c := coord("github.com/foo/bar")
	runA := domain.WalkScanRun{ID: "a", WalkID: "walk-1"}
	runB := domain.WalkScanRun{ID: "b", WalkID: "walk-1"}

	diff := domain.DiffScanRuns(runA, runB,
		[]domain.VulnerabilityRecord{record(c, finding("VULN-OLD"))},
		[]domain.VulnerabilityRecord{record(c)},
	)

	if len(diff.ResolvedFindings) != 1 || diff.ResolvedFindings[0].Finding.ID != "VULN-OLD" {
		t.Fatalf("expected one resolved finding VULN-OLD, got %+v", diff.ResolvedFindings)
	}
	if len(diff.NewFindings) != 0 {
		t.Errorf("expected no new findings, got %+v", diff.NewFindings)
	}
}

func TestDiffScanRuns_ReachabilityChange_NilToNonNil(t *testing.T) {
	c := coord("github.com/foo/bar")
	runA := domain.WalkScanRun{ID: "a", WalkID: "walk-1"}
	runB := domain.WalkScanRun{ID: "b", WalkID: "walk-1"}

	diff := domain.DiffScanRuns(runA, runB,
		[]domain.VulnerabilityRecord{record(c, finding("VULN-X"))},            // nil reachability
		[]domain.VulnerabilityRecord{record(c, findingReach("VULN-X", true))}, // non-nil, reachable
	)

	if len(diff.ReachabilityChanges) != 1 {
		t.Fatalf("expected one reachability change, got %+v", diff.ReachabilityChanges)
	}
	ch := diff.ReachabilityChanges[0]
	if ch.WasReachable || !ch.IsReachable {
		t.Errorf("expected was=false is=true, got was=%v is=%v", ch.WasReachable, ch.IsReachable)
	}
	if len(diff.NewFindings) != 0 || len(diff.ResolvedFindings) != 0 {
		t.Errorf("reachability change must not be reported as new/resolved: %+v", diff)
	}
}

func TestDiffScanRuns_ReachabilityFlip(t *testing.T) {
	c := coord("github.com/foo/bar")
	diff := domain.DiffScanRuns(
		domain.WalkScanRun{ID: "a", WalkID: "walk-1"},
		domain.WalkScanRun{ID: "b", WalkID: "walk-1"},
		[]domain.VulnerabilityRecord{record(c, findingReach("VULN-3", false))},
		[]domain.VulnerabilityRecord{record(c, findingReach("VULN-3", true))},
	)

	if len(diff.ReachabilityChanges) != 1 {
		t.Fatalf("expected one reachability change, got %+v", diff.ReachabilityChanges)
	}
	if diff.ReachabilityChanges[0].WasReachable || !diff.ReachabilityChanges[0].IsReachable {
		t.Errorf("expected was=false is=true, got %+v", diff.ReachabilityChanges[0])
	}
}

func TestDiffScanRuns_PresentAndUnchanged(t *testing.T) {
	c := coord("github.com/foo/bar")
	rec := record(c, findingReach("VULN-1", true))

	diff := domain.DiffScanRuns(
		domain.WalkScanRun{ID: "a", WalkID: "walk-1"},
		domain.WalkScanRun{ID: "b", WalkID: "walk-1"},
		[]domain.VulnerabilityRecord{rec},
		[]domain.VulnerabilityRecord{rec},
	)

	if len(diff.NewFindings) != 0 || len(diff.ResolvedFindings) != 0 || len(diff.ReachabilityChanges) != 0 {
		t.Errorf("unchanged finding must produce empty diff, got %+v", diff)
	}
}

func TestCompareFindingDelta_VersionTiebreak(t *testing.T) {
	mk := func(path, version, id string) domain.FindingDelta {
		return domain.FindingDelta{
			Coordinate: fetchdomain.ModuleCoordinate{Path: path, Version: version},
			Finding:    domain.VulnerabilityFinding{ID: id},
		}
	}
	v1 := mk("github.com/foo/bar", "v1.0.0", "VULN-1")
	v2 := mk("github.com/foo/bar", "v2.0.0", "VULN-1")

	// Same path and finding ID, differing only on version: the comparator must
	// impose a stable, non-zero order rather than treating them as equal.
	if got := domain.CompareFindingDelta(v1, v2); got != -1 {
		t.Errorf("v1.0.0 vs v2.0.0: got %d, want -1", got)
	}
	if got := domain.CompareFindingDelta(v2, v1); got != 1 {
		t.Errorf("v2.0.0 vs v1.0.0: got %d, want 1", got)
	}
	if got := domain.CompareFindingDelta(v1, v1); got != 0 {
		t.Errorf("identical deltas: got %d, want 0", got)
	}

	// Path still dominates version.
	pa := mk("github.com/aaa/pkg", "v9.0.0", "VULN-1")
	pz := mk("github.com/zzz/pkg", "v1.0.0", "VULN-1")
	if got := domain.CompareFindingDelta(pa, pz); got != -1 {
		t.Errorf("path dominates version: got %d, want -1", got)
	}
}

func TestDiffScanRuns_SameModuleTwoVersionsStableOrder(t *testing.T) {
	runA := domain.WalkScanRun{ID: "a", WalkID: "walk-1"}
	runB := domain.WalkScanRun{ID: "b", WalkID: "walk-1"}

	v2 := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v2.0.0"}
	v1 := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	diff := domain.DiffScanRuns(runA, runB,
		[]domain.VulnerabilityRecord{},
		[]domain.VulnerabilityRecord{
			record(v2, finding("VULN-1")),
			record(v1, finding("VULN-1")),
		},
	)

	if len(diff.NewFindings) != 2 {
		t.Fatalf("expected 2 new findings, got %d", len(diff.NewFindings))
	}
	if diff.NewFindings[0].Coordinate.Version != "v1.0.0" {
		t.Errorf("expected v1.0.0 first, got %s", diff.NewFindings[0].Coordinate.Version)
	}
	if diff.NewFindings[1].Coordinate.Version != "v2.0.0" {
		t.Errorf("expected v2.0.0 second, got %s", diff.NewFindings[1].Coordinate.Version)
	}
}

func TestDiffScanRuns_DeterministicSort(t *testing.T) {
	runA := domain.WalkScanRun{ID: "a", WalkID: "walk-1"}
	runB := domain.WalkScanRun{ID: "b", WalkID: "walk-1"}

	diff := domain.DiffScanRuns(runA, runB,
		[]domain.VulnerabilityRecord{},
		[]domain.VulnerabilityRecord{
			record(coord("github.com/zzz/pkg"), finding("VULN-Z")),
			record(coord("github.com/aaa/pkg"), finding("VULN-B"), finding("VULN-A")),
		},
	)

	if len(diff.NewFindings) != 3 {
		t.Fatalf("expected 3 new findings, got %d", len(diff.NewFindings))
	}
	want := []struct{ path, id string }{
		{"github.com/aaa/pkg", "VULN-A"},
		{"github.com/aaa/pkg", "VULN-B"},
		{"github.com/zzz/pkg", "VULN-Z"},
	}
	for i, w := range want {
		got := diff.NewFindings[i]
		if got.Coordinate.Path != w.path || got.Finding.ID != w.id {
			t.Errorf("position %d: got %s/%s, want %s/%s", i, got.Coordinate.Path, got.Finding.ID, w.path, w.id)
		}
	}
}
