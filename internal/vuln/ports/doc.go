// Package ports defines the interfaces the vuln application layer requires
// from the outside world.
//
// The driven ports are:
//
// - VulnerabilityStore — persistence for VulnerabilityRecord and WalkScanRun.
// - VulnerabilityScanner — runs a scan for one module (govulncheck adapter).
// - VulnerabilityDatabase — pins and serves OSV database snapshots.
// - ModuleFetcher — pre-fetches modules missing from the fact store.
// - ReachabilityAnalyser — decides whether a finding is reachable.
// - CallGraphLoader — supplies the call graph for reachability.
//
// Boundary rationale: the vuln context reuses fetch/domain.ModuleCoordinate
// directly; it does not re-declare module identity. CallGraphLoader returns a
// local CallGraphProjection rather than callgraph/domain.CallGraphRecord, so a
// callgraph schema change cannot ripple into this context — the mapping is the
// adapter's responsibility, not this package's.
package ports
