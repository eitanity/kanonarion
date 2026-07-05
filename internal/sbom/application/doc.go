// Package application contains the SBOM use cases.
//
// - GenerateSBOMUseCase orchestrates generation: cache lookup by
// (walk, scan run, format, pipeline version); load the walk, its license
// records, and optionally a scan run's vulnerabilities through their
// contexts' ports; delegate document production to ports.SBOMGenerator;
// then hash and persist the SBOMRecord. All timestamps come from an
// injected fetch/ports.Clock so generation is reproducible.
// - QuerySBOMUseCase provides read-only access (get by id, list by walk).
//
// The layer performs no format marshalling and contains no CycloneDX types;
// it depends only on ports and the pure assembly policy in sbom/domain.
package application
