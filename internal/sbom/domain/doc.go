// Package domain defines the types and policy for Software Bill of Materials
// generation.
//
// The aggregate root is SBOMRecord: a content-addressed SBOM document plus
// provenance (the walk and optional scan run it was generated from, pipeline
// version, operator, generated-at, and the SHA-256 over the document bytes).
// The document bytes are opaque here — their format is an adapter concern.
//
// This domain is intentionally thin, and that is a deliberate, audited
// disposition: the walk/license/vuln -> CycloneDX mapping is
// serialisation and lives behind ports.SBOMGenerator, NOT here. What *is*
// domain policy was extracted into this package by and lives in
// assembly.go: component inclusion and deterministic ordering, the
// license-attach rule, the LicensesIncomplete determination, and
// vulnerability dedup/aggregation. Those are pure functions over
// sbom-domain-owned input types so no foreign context leaks in.
//
// The package is pure: no I/O, no clock, no CycloneDX types. It reuses
// fetch/domain.ModuleCoordinate as the module identity.
package domain
