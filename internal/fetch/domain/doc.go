// Package domain contains the core model for the fetch bounded context.
//
// Invariants:
// - ModuleCoordinate is immutable once constructed; use NewModuleCoordinate.
// - FactRecord.ContentHash must be zeroed before computing the canonical hash
// (see CanonicalHasher); storing it with a hash over itself would be circular.
// - VerificationStatus is set by the application layer after cross-verification;
// the domain provides the enum values but not the verification logic itself.
// - All times stored in FactRecord are UTC; adapters must convert before
// constructing domain objects.
//
// This package has zero I/O and zero third-party dependencies beyond
// golang.org/x/mod (module hash utilities). It is fully testable without mocks.
package domain
