package domain

import (
	"slices"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
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
					diff.ReachabilityChanges = append(diff.ReachabilityChanges, ReachabilityChange{
						Coordinate:   coord,
						Finding:      fB,
						WasReachable: reachableFlag(fA),
						IsReachable:  reachableFlag(fB),
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
				diff.ResolvedFindings = append(diff.ResolvedFindings, FindingDelta{Coordinate: coord, Finding: fA})
			}
		}
	}

	// Sort for deterministic output.
	slices.SortFunc(diff.NewFindings, CompareFindingDelta)
	slices.SortFunc(diff.ResolvedFindings, CompareFindingDelta)
	slices.SortFunc(diff.ReachabilityChanges, func(a, b ReachabilityChange) int {
		return CompareFindingDelta(
			FindingDelta{Coordinate: a.Coordinate, Finding: a.Finding},
			FindingDelta{Coordinate: b.Coordinate, Finding: b.Finding},
		)
	})

	return diff
}

func indexByCoordinate(recs []VulnerabilityRecord) map[fetchdomain.ModuleCoordinate]VulnerabilityRecord {
	m := make(map[fetchdomain.ModuleCoordinate]VulnerabilityRecord, len(recs))
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
