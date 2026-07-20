package domain

import (
	"fmt"
	"slices"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// DiffScanRuns compares two scan runs of the same walk and returns the delta.
// runA/runB carry the run metadata; recsA/recsB are the per-module
// vulnerability records for each run. The result is sorted deterministically.
//
// This is the pure classification of what counts as a new finding, a resolved
// finding, and a reachability change. It performs no I/O; loading the runs and
// records is the caller's responsibility.
func DiffScanRuns(runA, runB WalkScanRun, recsA, recsB []VulnerabilityRecord) ScanRunDiff {
	indexA := indexByCoordinate(recsA)
	indexB := indexByCoordinate(recsB)

	diff := ScanRunDiff{RunA: runA, RunB: runB}

	// Findings in B not in A → newly known.
	for coord, recB := range indexB {
		recA, inA := indexA[coord]
		for _, fB := range recB.Findings {
			if !inA || !containsFinding(recA.Findings, fB.ID) {
				diff.NewFindings = append(diff.NewFindings, FindingDelta{Coordinate: coord, Finding: fB})
			} else if inA {
				// Both runs have this finding — check for reachability change.
				fA, ok := findByID(recA.Findings, fB.ID)
				if ok && reachabilityChanged(fA, fB) {
					wasReachable, isReachable := reachableFlag(fA), reachableFlag(fB)
					// A reachable→not-reachable flip is a green "now unaffected"
					// verdict. If the two runs analysed the module at unequal
					// fidelity, that flip may be an artefact of dropped fidelity,
					// not a fix — hold it back as UNRESOLVED. The reverse flip
					// (newly reachable) is not a green result, so it stands.
					if wasReachable && !isReachable {
						if mismatch, reason := completenessMismatch(recA, recB); mismatch {
							diff.UnresolvedFindings = append(diff.UnresolvedFindings, UnresolvedFinding{
								Coordinate: coord, Finding: fB, Kind: UnresolvedKindReachability, Reason: reason,
							})
							continue
						}
					}
					diff.ReachabilityChanges = append(diff.ReachabilityChanges, ReachabilityChange{
						Coordinate:   coord,
						Finding:      fB,
						WasReachable: wasReachable,
						IsReachable:  isReachable,
					})
				}
			}
		}
	}

	// Findings in A not in B → resolved / no longer known.
	for coord, recA := range indexA {
		recB, inB := indexB[coord]
		for _, fA := range recA.Findings {
			if !inB || !containsFinding(recB.Findings, fA.ID) {
				// A finding that disappears from a module still present in B is a
				// green "resolved" verdict. If B analysed the module at lower
				// fidelity than A, the finding may have vanished because the scan
				// saw less, not because it was fixed — hold it back as UNRESOLVED.
				// When the module is absent from B entirely there is no B-side
				// fidelity to compare, so that coverage change stays resolved.
				if inB {
					if mismatch, reason := completenessMismatch(recA, recB); mismatch {
						diff.UnresolvedFindings = append(diff.UnresolvedFindings, UnresolvedFinding{
							Coordinate: coord, Finding: fA, Kind: UnresolvedKindResolved, Reason: reason,
						})
						continue
					}
				}
				diff.ResolvedFindings = append(diff.ResolvedFindings, FindingDelta{Coordinate: coord, Finding: fA})
			}
		}
	}

	// Sort for deterministic output.
	slices.SortFunc(diff.NewFindings, CompareFindingDelta)
	slices.SortFunc(diff.ResolvedFindings, CompareFindingDelta)
	// A given (coordinate, finding) is either "in both runs" or "in A only", never
	// both, so it can produce at most one UnresolvedFinding — ordering by
	// coordinate+finding is already total and deterministic.
	slices.SortFunc(diff.UnresolvedFindings, func(a, b UnresolvedFinding) int {
		return CompareFindingDelta(
			FindingDelta{Coordinate: a.Coordinate, Finding: a.Finding},
			FindingDelta{Coordinate: b.Coordinate, Finding: b.Finding},
		)
	})
	slices.SortFunc(diff.ReachabilityChanges, func(a, b ReachabilityChange) int {
		return CompareFindingDelta(
			FindingDelta{Coordinate: a.Coordinate, Finding: a.Finding},
			FindingDelta{Coordinate: b.Coordinate, Finding: b.Finding},
		)
	})

	return diff
}

func indexByCoordinate(recs []VulnerabilityRecord) map[coordinate.ModuleCoordinate]VulnerabilityRecord {
	m := make(map[coordinate.ModuleCoordinate]VulnerabilityRecord, len(recs))
	for _, r := range recs {
		m[r.Coordinate] = r
	}
	return m
}

func containsFinding(findings []VulnerabilityFinding, id string) bool {
	return slices.ContainsFunc(findings, func(f VulnerabilityFinding) bool { return f.ID == id })
}

func findByID(findings []VulnerabilityFinding, id string) (VulnerabilityFinding, bool) {
	idx := slices.IndexFunc(findings, func(f VulnerabilityFinding) bool { return f.ID == id })
	if idx < 0 {
		return VulnerabilityFinding{}, false
	}
	return findings[idx], true
}

// completenessMismatch reports whether two records analysed their module at
// unequal call-graph fidelity, and names the differing axis. It compares the
// completeness level and the algorithm/devirt tier — together "same completeness
// level, same in-toolchain status, same algorithm/devirt tier", since the
// VERSION_NOT_IN_TOOLCHAIN level folds in in-toolchain status. Two records that
// both consulted no call graph (both empty) are trivially in parity.
func completenessMismatch(a, b VulnerabilityRecord) (bool, string) {
	if a.CallGraphCompleteness != b.CallGraphCompleteness {
		return true, fmt.Sprintf("completeness level differs: before=%s after=%s",
			completenessName(a.CallGraphCompleteness), completenessName(b.CallGraphCompleteness))
	}
	if a.CallGraphAlgorithm != b.CallGraphAlgorithm {
		return true, fmt.Sprintf("algorithm/devirt tier differs: before=%s after=%s",
			completenessName(a.CallGraphAlgorithm), completenessName(b.CallGraphAlgorithm))
	}
	return false, ""
}

// completenessName renders an empty fidelity string as "Unknown" for messages.
func completenessName(s string) string {
	if s == "" {
		return "Unknown"
	}
	return s
}

func reachabilityChanged(a, b VulnerabilityFinding) bool {
	if a.Reachable == nil && b.Reachable == nil {
		return false
	}
	if a.Reachable == nil || b.Reachable == nil {
		return true
	}
	return a.Reachable.IsReachable != b.Reachable.IsReachable
}

func reachableFlag(f VulnerabilityFinding) bool {
	return f.Reachable != nil && f.Reachable.IsReachable
}

// CompareFindingDelta is the canonical deterministic ordering for finding
// deltas in scan-run diff output: by module path, then module version, then
// finding ID. Version is part of the tiebreak because a single walk can
// contain the same module path at multiple versions, and ordering by path+ID
// alone leaves those ties unstable.
func CompareFindingDelta(a, b FindingDelta) int {
	if a.Coordinate.Path != b.Coordinate.Path {
		if a.Coordinate.Path < b.Coordinate.Path {
			return -1
		}
		return 1
	}
	if a.Coordinate.Version != b.Coordinate.Version {
		if a.Coordinate.Version < b.Coordinate.Version {
			return -1
		}
		return 1
	}
	if a.Finding.ID < b.Finding.ID {
		return -1
	}
	if a.Finding.ID > b.Finding.ID {
		return 1
	}
	return 0
}
