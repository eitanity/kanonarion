// Package domain defines the types and invariants for call graph extraction.
//
// The aggregate root is CallGraphRecord: the static call graph of a module,
// composed of CallNode and CallEdge value objects plus extraction metadata
// and a content hash.
//
// Invariants:
//
// - Determinism: CallGraphRecord.Sort establishes a canonical ordering of
// Nodes and Edges. Sort MUST be called before the content hash is
// computed (CallGraphRecordHasher hashes the canonical JSON with
// ContentHash zeroed), so two analyses of the same module produce
// byte-identical records and the same hash regardless of the order the
// analyser emitted nodes/edges.
// - Integrity: a record read back from storage is rejected unless its
// recomputed canonical hash matches the stored ContentHash.
//
// The package is pure: no I/O, no toolchain invocation, no clock. It reuses
// coordinate.ModuleCoordinate as the module identity.
package domain
