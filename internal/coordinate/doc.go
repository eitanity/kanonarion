// Package coordinate is a Shared Kernel: it holds ModuleCoordinate, the one
// value object with genuine cross-context fan-out (module identity — path
// and version). It must stay small, stable, and dependency-free: no imports
// of other bounded contexts, no infrastructure. Everything else that used to
// live alongside it in fetch/domain (CanonicalHasher, FactRecord,
// ForkProvenance, digests) is domain-specific to fetch and stays there.
package coordinate
