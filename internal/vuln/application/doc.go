// Package application orchestrates vulnerability scanning use cases.
//
// It contains:
//
// - ScanModuleUseCase — scans a single module: blob retrieval, snapshot
// resolution, scanner invocation, optional reachability, hashing, and
// persistence.
// - ScanWalkUseCase — scans every module in a walk. It runs a fail-fast
// scanner pre-flight, resolves and pre-extracts the database snapshot,
// pre-populates a shared GOMODCACHE, then dispatches a bounded worker
// pool. vuln-scan-rescan delegates here against a fresh snapshot.
// - Query/diff use cases — read-only access and scan-run comparison.
//
// The layer depends only on the interfaces in vuln/ports and on pure
// vuln/domain logic for status aggregation and finding ordering; it performs
// no AST/zip parsing or external process execution itself — those are adapter
// concerns behind ports.VulnerabilityScanner.
package application
