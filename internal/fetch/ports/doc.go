// Package ports defines the interfaces the fetch application layer requires
// from the outside world. All I/O — proxy access, git operations, blob and
// fact persistence, and wall-clock time — is accessed through these
// interfaces so the application layer remains fully testable without real
// I/O. Adapters in the adapters/ subtree implement them for specific
// backends; tests use in-memory fakes.
//
// The driven ports are SumDBClient, ModuleProxy, VCSClient, BlobStore,
// FactStore, Clock, and Stopwatch/Lap.
//
// fetch is the root context: BlobStore, FactStore, and Clock are *defined*
// here and reused by the other contexts (iface, callgraph, example, license,
// extract, vuln, sbom) rather than re-declared in their own ports packages.
// Module identity is coordinate.ModuleCoordinate.
package ports
