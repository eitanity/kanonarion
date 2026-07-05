// Package domain defines the walk bounded context's core model: the dependency
// graph produced by resolving a target module's complete transitive closure
// under Go's minimum version selection (MVS), and the WalkRecord aggregate root
// that persists a completed walk as a tamper-evident fact.
//
// Invariants:
// - Graph.Nodes and Graph.Edges are always sorted lexicographically by
// module path then version. Callers must invoke Graph.Sort after construction.
// - A partial graph (Graph.Partial == true) always carries a non-empty PartialReason.
// - ParsedGoMod is a pure value object; GoModParser produces it and GraphResolver
// consumes it. It has no behaviour.
// - ResolutionSource describes how a node's version was selected. Nodes with
// fetch_failed or parse_failed sources carry a non-empty ErrorDetail.
// - WalkRecord.ContentHash is computed over canonical JSON with the field zeroed;
// call WalkRecordHasher.SetContentHash after construction, before persisting.
// - WalkRecord.PerNodeResults serialises as a sorted array (by coordinate); the
// hasher enforces this regardless of map iteration order.
//
// This package imports fetch/domain for the shared ModuleCoordinate and FactRecord
// value objects. No other cross-context imports are permitted here.
package domain
