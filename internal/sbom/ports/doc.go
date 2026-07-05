// Package ports defines the interfaces the sbom application layer requires
// from the outside world.
//
// The driven ports are:
//
// - SBOMGenerator — produces the SBOM document bytes from walk facts,
// licenses, and vulnerabilities. This is the format seam: it keeps the
// domain and application free of CycloneDX (or any other format); the
// cyclonedx adapter is the only place that format lives.
// - SBOMStore — persistence and lookup for the SBOMRecord aggregate.
//
// The sbom context reuses fetch/domain.ModuleCoordinate as the module
// identity. Read access to walk, license, and vulnerability facts is consumed
// in the application through those contexts' own ports (WalkStore,
// LicenseStore, VulnerabilityStore), not re-declared here.
package ports
