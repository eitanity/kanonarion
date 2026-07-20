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
// - Finding ordering is canonical and deterministic — findings are sorted by
// a single domain comparator (ID, then a semantic-version tiebreak), so
// two scans of the same inputs produce byte-identical records and hashes.
// - WalkScanRun.OverallStatus is never assembled ad hoc by callers; it is
// derived solely via DetermineWalkScanStatus from the (failed, affected,
// unscannable, total) counts.
// - Scan-run comparison is domain logic: DiffScanRuns / CompareFindingDelta
// define how two runs differ, independent of storage or presentation.
//
// The package is pure: no I/O, no clock, no execution of scanned code. It
// reuses coordinate.ModuleCoordinate as the module identity rather than
// redefining it.
package domain
