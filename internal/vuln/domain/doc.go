// Package domain defines the types and invariants for vulnerability scanning.
//
// There are two aggregate roots:
//
// - VulnerabilityRecord — the result of scanning a single module: its
// findings, overall status, the database snapshot the scan was performed
// against, and a content hash over the canonical record.
// - WalkScanRun — the aggregate result of scanning every module in a walk:
// per-module result hashes, the shared snapshot, and the rolled-up
// overall status.
//
// Invariants enforced here (the –127 anemic-domain remediation):
//
// - Collection ordering is canonical and deterministic — SealedCollections
// classifies every slice on the sealed record shape as a set or as an ordered
// statement, and the seal step puts the sets into the one order each has, so
// two scans of the same inputs produce records that differ only where the two
// scans genuinely differ. It is not byte-identity: ScannedAt is on the wire,
// so the content hash of a re-scanned record moves even when the verdict does
// not. A route is the one collection whose order IS the fact, and it is never
// sorted.
// - WalkScanRun's verdict fields are never assembled ad hoc by callers. Its two
// independent axes are derived solely via DetermineCoverageStatus and
// DetermineFindingsStatus from the module counts, and OverallStatus — a stored
// compatibility summary that collapses both into one word — via
// DetermineWalkScanStatus from the same counts.
// - Scan-run comparison is domain logic: DiffScanRuns / CompareFindingDelta
// define how two runs differ, independent of storage or presentation.
//
// The package is pure: no I/O, no clock, no execution of scanned code. It
// reuses coordinate.ModuleCoordinate as the module identity rather than
// redefining it.
package domain
