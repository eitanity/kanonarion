package kanonarion

import (
	callgraphports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	configports "github.com/eitanity/kanonarion/internal/config/ports"
	exampleports "github.com/eitanity/kanonarion/internal/example/ports"
	extractports "github.com/eitanity/kanonarion/internal/extract/ports"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
	licenseports "github.com/eitanity/kanonarion/internal/license/ports"
	sbomports "github.com/eitanity/kanonarion/internal/sbom/ports"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// Substitution ports (implemented by consumers). Each is a TYPE ALIAS to the
// internal port interface, re-exporting exactly the seams the enterprise build
// must replace — persistence, blob, config, and the network clients (
// §2.3). The AST/parse-coupled and infrastructure-leaning ports
// (Extractor, InterfaceExtractor, CallGraphAnalyser, ReachabilityAnalyser,
// GoModParser, ExampleParser, LicenseDetector, SBOMGenerator, ZipFS) and every
// *Hasher type are deliberately NOT re-exported (§3): enterprise reuses
// core's implementations of those via the DI container.
//
// Port-asymmetry rule (§4): a port is implemented by consumers, so
// ADDING A METHOD to any port below is a BREAKING change — it fails every
// external implementer at compile time. Within a major version these interfaces
// evolve only by introducing a NEW OPTIONAL interface that core type-asserts for
// (as BlobPathOptimizer does for BlobStore), never by widening the published
// interface. Every Stability line below restates this constraint.

// FactStore persists and retrieves FactRecords — the fetch fact persistence
// seam the enterprise build replaces with its own backend.
//
// Stability: substitution port (implemented by consumers); unstable pre-v1.
// Grows only by a new optional interface, never by adding a method (§4).
type FactStore = fetchports.FactStore

// WalkStore persists and retrieves WalkRecords — the dependency-walk
// persistence seam the enterprise build replaces with its own backend.
//
// Stability: substitution port (implemented by consumers); unstable pre-v1.
// Grows only by a new optional interface, never by adding a method (§4).
type WalkStore = walkports.WalkStore

// LicenseStore persists and retrieves LicenseRecords — the license persistence
// seam the enterprise build replaces with its own backend.
//
// Stability: substitution port (implemented by consumers); unstable pre-v1.
// Grows only by a new optional interface, never by adding a method (§4).
type LicenseStore = licenseports.LicenseStore

// InterfaceStore persists and retrieves InterfaceRecords — the public-API
// persistence seam the enterprise build replaces with its own backend.
//
// Stability: substitution port (implemented by consumers); unstable pre-v1.
// Grows only by a new optional interface, never by adding a method (§4).
type InterfaceStore = ifaceports.InterfaceStore

// CallGraphStore persists and retrieves CallGraphRecords — the call-graph
// persistence seam the enterprise build replaces with its own backend.
//
// Stability: substitution port (implemented by consumers); unstable pre-v1.
// Grows only by a new optional interface, never by adding a method (§4).
type CallGraphStore = callgraphports.CallGraphStore

// ExampleStore persists and retrieves ExampleRecords — the example-harvest
// persistence seam the enterprise build replaces with its own backend.
//
// Stability: substitution port (implemented by consumers); unstable pre-v1.
// Grows only by a new optional interface, never by adding a method (§4).
type ExampleStore = exampleports.ExampleStore

// ExtractionStore persists and retrieves ExtractionRuns — the extraction-run
// persistence seam the enterprise build replaces with its own backend.
//
// Stability: substitution port (implemented by consumers); unstable pre-v1.
// Grows only by a new optional interface, never by adding a method (§4).
type ExtractionStore = extractports.ExtractionStore

// VulnerabilityStore persists and retrieves VulnerabilityRecords — the
// vulnerability persistence seam the enterprise build replaces with its own
// backend.
//
// Stability: substitution port (implemented by consumers); unstable pre-v1.
// Grows only by a new optional interface, never by adding a method (§4).
type VulnerabilityStore = vulnports.VulnerabilityStore

// SBOMStore persists and retrieves SBOMRecords — the SBOM persistence seam the
// enterprise build replaces with its own backend.
//
// Stability: substitution port (implemented by consumers); unstable pre-v1.
// Grows only by a new optional interface, never by adding a method (§4).
type SBOMStore = sbomports.SBOMStore

// BlobStore persists opaque, content-addressed binary artefacts (module zips and
// go.mod files). It is reshaped to its minimal core — Put/Get/Exists — with the
// filesystem-path capability split out into the optional BlobPathOptimizer so an
// object-store backend (e.g. S3) can satisfy BlobStore without faking a local
// path.
//
// Stability: substitution port (implemented by consumers); unstable pre-v1.
// Grows only by a new optional interface, never by adding a method (§4).
type BlobStore = fetchports.BlobStore

// BlobPathOptimizer is the optional capability a BlobStore may also implement
// when it can hand back a local filesystem path to a blob. Callers type-assert
// for it and degrade gracefully (materialise the bytes) when it is absent. It is
// the concrete example of the port-asymmetry rule: capability is added by this
// separate optional interface, not by widening BlobStore.
//
// Stability: optional substitution port (implemented by consumers); unstable
// pre-v1. It is itself the additive-extension mechanism (§4).
type BlobPathOptimizer = fetchports.BlobPathOptimizer

// BlobHandle is the opaque reference Put returns and Get/Exists/GetPath accept.
// It is a supporting type of the BlobStore seam, exported so an external
// implementer can name it in their method signatures; treat it as an identifier,
// never as a filesystem path.
//
// Stability: supporting type of the BlobStore port; unstable pre-v1.
type BlobHandle = fetchports.BlobHandle

// ConfigStore reads and writes persisted configuration values — the config
// persistence seam the enterprise build replaces with its own backend.
//
// Stability: substitution port (implemented by consumers); unstable pre-v1.
// Grows only by a new optional interface, never by adding a method (§4).
type ConfigStore = configports.ConfigStore

// Clock supplies wall-clock time. It is injected wherever a domain-relevant
// timestamp is recorded so tests (and alternative deployments) can pin the
// instant; it is the time seam the enterprise build may replace.
//
// Stability: substitution port (implemented by consumers); unstable pre-v1.
// Grows only by a new optional interface, never by adding a method (§4).
type Clock = fetchports.Clock

// ModuleProxy retrieves modules over the Go module proxy protocol — the proxy
// network seam the enterprise build replaces (e.g. with an internal mirror).
//
// Stability: substitution port (implemented by consumers); unstable pre-v1.
// Grows only by a new optional interface, never by adding a method (§4).
type ModuleProxy = fetchports.ModuleProxy

// VCSClient performs git operations on source repositories — the VCS network
// seam the enterprise build replaces (e.g. with an internal git mirror).
//
// Stability: substitution port (implemented by consumers); unstable pre-v1.
// Grows only by a new optional interface, never by adding a method (§4).
type VCSClient = fetchports.VCSClient

// SumDBClient queries the Go checksum database — the transparency-log network
// seam the enterprise build replaces (e.g. with a private GOSUMDB).
//
// Stability: substitution port (implemented by consumers); unstable pre-v1.
// Grows only by a new optional interface, never by adding a method (§4).
type SumDBClient = fetchports.SumDBClient
