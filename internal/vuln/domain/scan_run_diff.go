package domain

import (
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// ScanRunDiff is the result of comparing two WalkScanRuns of the same walk.
type ScanRunDiff struct {
	RunA WalkScanRun
	RunB WalkScanRun

	// NewFindings contains findings present in B but not in A (newly known).
	NewFindings []FindingDelta
	// ResolvedFindings contains findings present in A but not in B (no longer known).
	ResolvedFindings []FindingDelta
	// ReachabilityChanges contains findings present in both runs whose reachability
	// determination changed between A and B.
	ReachabilityChanges []ReachabilityChange
	// UnresolvedFindings contains verdicts a naive diff would have reported green
	// — a finding resolved, or a finding no longer reachable — but which are held
	// back because the two runs analysed the module at unequal call-graph fidelity.
	// A green result from an asymmetric comparison is worse than no answer, so these
	// are surfaced as UNRESOLVED with the parity mismatch named rather than folded
	// into ResolvedFindings/ReachabilityChanges.
	UnresolvedFindings []UnresolvedFinding
}

// FindingDelta associates a vulnerability finding with the module it affects.
type FindingDelta struct {
	Coordinate fetchdomain.ModuleCoordinate
	Finding    VulnerabilityFinding
}

// ReachabilityChange records a finding whose reachability status changed.
type ReachabilityChange struct {
	Coordinate fetchdomain.ModuleCoordinate
	Finding    VulnerabilityFinding
	// WasReachable is the reachability in run A; IsReachable is the reachability in run B.
	WasReachable bool
	IsReachable  bool
}

// UnresolvedFinding is a would-be green verdict withheld because the two runs
// analysed the finding's module at unequal call-graph fidelity.
type UnresolvedFinding struct {
	Coordinate fetchdomain.ModuleCoordinate
	Finding    VulnerabilityFinding
	// Kind names the verdict that was withheld: "resolved" (the finding
	// disappeared from run B) or "reachability" (it became not-reachable in B).
	Kind string
	// Reason names the fidelity mismatch, e.g. "completeness level differs:
	// before=BUILT_WITH_BODIES after=METADATA_ONLY".
	Reason string
}

// UnresolvedKindResolved and UnresolvedKindReachability are the two withheld
// verdict kinds an UnresolvedFinding can carry.
const (
	UnresolvedKindResolved     = "resolved"
	UnresolvedKindReachability = "reachability"
)
