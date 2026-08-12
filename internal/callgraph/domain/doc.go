// Package domain defines the types and invariants for call graph extraction.
//
// The aggregate root is CallGraphRecord: the static call graph of a module,
// composed of CallNode and CallEdge value objects plus extraction metadata
// and a content hash.
//
// Invariants:
//
// - Determinism: the canonical marshalling owns the ordering of every
// collection. It sorts copies with the comparators in ordering.go, each
// keyed on every field its collection puts on the wire, so two analyses of
// the same module produce byte-identical records and the same hash
// regardless of the order the analyser emitted nodes/edges. Nothing has to
// be called first for that to hold; CallGraphRecord.Sort applies the same
// order in place, for callers that want it in memory.
// - Integrity: a record read back from storage is rejected unless its
// recomputed canonical hash matches the stored ContentHash.
//
// The package is pure: no I/O, no toolchain invocation, no clock. It reuses
// coordinate.ModuleCoordinate as the module identity.
package domain
