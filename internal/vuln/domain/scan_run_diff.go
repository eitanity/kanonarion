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
