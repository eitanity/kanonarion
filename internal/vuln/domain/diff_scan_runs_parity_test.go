package domain_test

import (
	"strings"
	"testing"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// recordFidelity is `record` with a call-graph fidelity signature stamped, so a
// diff can assert completeness parity across the two runs.
func recordFidelity(c fetchdomain.ModuleCoordinate, completeness string, findings ...domain.VulnerabilityFinding) domain.VulnerabilityRecord {
	r := record(c, findings...)
	r.CallGraphCompleteness = completeness
	r.CallGraphAlgorithm = string(callgraphdomain.AlgorithmCHA)
	return r
}

// allLevels is every completeness level a record can carry, including the
// Unknown zero value, so the parity table covers each pairing.
var allLevels = []string{
	string(callgraphdomain.CompletenessBuiltWithBodies),
	string(callgraphdomain.CompletenessTypeOnly),
	string(callgraphdomain.CompletenessMetadataOnly),
	string(callgraphdomain.CompletenessFailed),
	string(callgraphdomain.CompletenessVersionNotInToolchain),
	string(callgraphdomain.CompletenessUnknown),
}

// TestDiffScanRuns_ResolvedParity_AllLevelPairings crafts a resolved finding
// (present in A, absent in B) for every (before, after) completeness pairing and
// asserts: equal levels report a confident RESOLVED, unequal levels are held
// back as UNRESOLVED with the mismatch named. This is the ticket's verification:
// vOLD=BUILT_WITH_BODIES, vNEW=METADATA_ONLY must report UNRESOLVED, not resolved.
func TestDiffScanRuns_ResolvedParity_AllLevelPairings(t *testing.T) {
	c := coord("github.com/foo/bar")
	runA := domain.WalkScanRun{ID: "a", WalkID: "walk-1"}
	runB := domain.WalkScanRun{ID: "b", WalkID: "walk-1"}

	for _, before := range allLevels {
		for _, after := range allLevels {
			before, after := before, after
			name := labelLevel(before) + "_vs_" + labelLevel(after)
			t.Run(name, func(t *testing.T) {
				diff := domain.DiffScanRuns(runA, runB,
					[]domain.VulnerabilityRecord{recordFidelity(c, before, finding("VULN-OLD"))},
					[]domain.VulnerabilityRecord{recordFidelity(c, after)},
				)

				if before == after {
					if len(diff.ResolvedFindings) != 1 || len(diff.UnresolvedFindings) != 0 {
						t.Fatalf("equal fidelity %q must report RESOLVED, got resolved=%+v unresolved=%+v",
							before, diff.ResolvedFindings, diff.UnresolvedFindings)
					}
					return
				}

				if len(diff.ResolvedFindings) != 0 {
					t.Fatalf("mismatched fidelity %q/%q must NOT report resolved, got %+v", before, after, diff.ResolvedFindings)
				}
				if len(diff.UnresolvedFindings) != 1 {
					t.Fatalf("mismatched fidelity %q/%q must report one UNRESOLVED, got %+v", before, after, diff.UnresolvedFindings)
				}
				u := diff.UnresolvedFindings[0]
				if u.Kind != domain.UnresolvedKindResolved || u.Finding.ID != "VULN-OLD" {
					t.Fatalf("unexpected unresolved entry: %+v", u)
				}
				if !strings.Contains(u.Reason, "completeness level differs") {
					t.Fatalf("reason must name the completeness mismatch, got %q", u.Reason)
				}
				if !strings.Contains(u.Reason, labelLevel(before)) || !strings.Contains(u.Reason, labelLevel(after)) {
					t.Fatalf("reason must name both levels %q/%q, got %q", before, after, u.Reason)
				}
			})
		}
	}
}

// TestDiffScanRuns_ReachabilityFlipParity holds back a reachable→not-reachable
// flip (a green "now unaffected") when the two runs were built at unequal
// fidelity, but lets it stand when fidelity matches.
func TestDiffScanRuns_ReachabilityFlipParity(t *testing.T) {
	c := coord("github.com/foo/bar")
	runA := domain.WalkScanRun{ID: "a", WalkID: "walk-1"}
	runB := domain.WalkScanRun{ID: "b", WalkID: "walk-1"}

	built := string(callgraphdomain.CompletenessBuiltWithBodies)
	meta := string(callgraphdomain.CompletenessMetadataOnly)

	t.Run("mismatch_withholds_unaffected", func(t *testing.T) {
		diff := domain.DiffScanRuns(runA, runB,
			[]domain.VulnerabilityRecord{recordFidelity(c, built, findingReach("V", true))},
			[]domain.VulnerabilityRecord{recordFidelity(c, meta, findingReach("V", false))},
		)
		if len(diff.ReachabilityChanges) != 0 {
			t.Fatalf("expected no reachability change, got %+v", diff.ReachabilityChanges)
		}
		if len(diff.UnresolvedFindings) != 1 || diff.UnresolvedFindings[0].Kind != domain.UnresolvedKindReachability {
			t.Fatalf("expected one reachability UNRESOLVED, got %+v", diff.UnresolvedFindings)
		}
	})

	t.Run("match_reports_change", func(t *testing.T) {
		diff := domain.DiffScanRuns(runA, runB,
			[]domain.VulnerabilityRecord{recordFidelity(c, built, findingReach("V", true))},
			[]domain.VulnerabilityRecord{recordFidelity(c, built, findingReach("V", false))},
		)
		if len(diff.UnresolvedFindings) != 0 {
			t.Fatalf("equal fidelity must not withhold, got %+v", diff.UnresolvedFindings)
		}
		if len(diff.ReachabilityChanges) != 1 {
			t.Fatalf("expected one reachability change, got %+v", diff.ReachabilityChanges)
		}
	})

	t.Run("newly_reachable_stands_even_on_mismatch", func(t *testing.T) {
		// A not-reachable→reachable flip is not a green result, so it is reported
		// as a normal change even across mismatched fidelity.
		diff := domain.DiffScanRuns(runA, runB,
			[]domain.VulnerabilityRecord{recordFidelity(c, built, findingReach("V", false))},
			[]domain.VulnerabilityRecord{recordFidelity(c, meta, findingReach("V", true))},
		)
		if len(diff.UnresolvedFindings) != 0 {
			t.Fatalf("newly-reachable flip must not be withheld, got %+v", diff.UnresolvedFindings)
		}
		if len(diff.ReachabilityChanges) != 1 {
			t.Fatalf("expected one reachability change, got %+v", diff.ReachabilityChanges)
		}
	})
}

// TestDiffScanRuns_ModuleAbsentInB_StaysResolved keeps a finding resolved when
// its module is entirely absent from run B: there is no B-side fidelity to
// compare, so that is a coverage change, not a fidelity flip.
func TestDiffScanRuns_ModuleAbsentInB_StaysResolved(t *testing.T) {
	c := coord("github.com/foo/bar")
	runA := domain.WalkScanRun{ID: "a", WalkID: "walk-1"}
	runB := domain.WalkScanRun{ID: "b", WalkID: "walk-1"}

	diff := domain.DiffScanRuns(runA, runB,
		[]domain.VulnerabilityRecord{recordFidelity(c, string(callgraphdomain.CompletenessBuiltWithBodies), finding("VULN-OLD"))},
		[]domain.VulnerabilityRecord{},
	)
	if len(diff.ResolvedFindings) != 1 || len(diff.UnresolvedFindings) != 0 {
		t.Fatalf("module absent in B must stay resolved, got resolved=%+v unresolved=%+v",
			diff.ResolvedFindings, diff.UnresolvedFindings)
	}
}

// TestDiffScanRuns_AlgorithmMismatch withholds a resolved verdict when the two
// runs match on completeness level but differ in algorithm/devirt tier.
func TestDiffScanRuns_AlgorithmMismatch(t *testing.T) {
	c := coord("github.com/foo/bar")
	runA := domain.WalkScanRun{ID: "a", WalkID: "walk-1"}
	runB := domain.WalkScanRun{ID: "b", WalkID: "walk-1"}

	recA := recordFidelity(c, string(callgraphdomain.CompletenessBuiltWithBodies), finding("VULN-OLD"))
	recB := recordFidelity(c, string(callgraphdomain.CompletenessBuiltWithBodies))
	recB.CallGraphAlgorithm = string(callgraphdomain.AlgorithmRTA)

	diff := domain.DiffScanRuns(runA, runB,
		[]domain.VulnerabilityRecord{recA},
		[]domain.VulnerabilityRecord{recB},
	)
	if len(diff.ResolvedFindings) != 0 || len(diff.UnresolvedFindings) != 1 {
		t.Fatalf("algorithm mismatch must withhold, got resolved=%+v unresolved=%+v",
			diff.ResolvedFindings, diff.UnresolvedFindings)
	}
	if !strings.Contains(diff.UnresolvedFindings[0].Reason, "algorithm/devirt tier differs") {
		t.Fatalf("reason must name the algorithm mismatch, got %q", diff.UnresolvedFindings[0].Reason)
	}
}

// TestDiffScanRuns_UnresolvedSortedDeterministically checks that multiple
// withheld findings come back ordered by coordinate then finding ID.
func TestDiffScanRuns_UnresolvedSortedDeterministically(t *testing.T) {
	c1 := coord("github.com/foo/bar")
	c2 := coord("github.com/foo/baz")
	runA := domain.WalkScanRun{ID: "a", WalkID: "walk-1"}
	runB := domain.WalkScanRun{ID: "b", WalkID: "walk-1"}
	built := string(callgraphdomain.CompletenessBuiltWithBodies)
	meta := string(callgraphdomain.CompletenessMetadataOnly)

	diff := domain.DiffScanRuns(runA, runB,
		[]domain.VulnerabilityRecord{
			recordFidelity(c2, built, finding("VULN-2"), finding("VULN-1")),
			recordFidelity(c1, built, finding("VULN-9")),
		},
		[]domain.VulnerabilityRecord{
			recordFidelity(c2, meta),
			recordFidelity(c1, meta),
		},
	)
	if len(diff.UnresolvedFindings) != 3 {
		t.Fatalf("expected 3 withheld findings, got %+v", diff.UnresolvedFindings)
	}
	got := []string{
		diff.UnresolvedFindings[0].Coordinate.Path + "/" + diff.UnresolvedFindings[0].Finding.ID,
		diff.UnresolvedFindings[1].Coordinate.Path + "/" + diff.UnresolvedFindings[1].Finding.ID,
		diff.UnresolvedFindings[2].Coordinate.Path + "/" + diff.UnresolvedFindings[2].Finding.ID,
	}
	want := []string{
		"github.com/foo/bar/VULN-9",
		"github.com/foo/baz/VULN-1",
		"github.com/foo/baz/VULN-2",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unresolved not sorted: got %v want %v", got, want)
		}
	}
}

func labelLevel(s string) string {
	if s == "" {
		return "Unknown"
	}
	return s
}
