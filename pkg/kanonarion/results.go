package kanonarion

import (
	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	directivedomain "github.com/eitanity/kanonarion/internal/directive/domain"
	exampledomain "github.com/eitanity/kanonarion/internal/example/domain"
	extractdomain "github.com/eitanity/kanonarion/internal/extract/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fipsdomain "github.com/eitanity/kanonarion/internal/fips/domain"
	godebugdomain "github.com/eitanity/kanonarion/internal/godebug/domain"
	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
	sbomdomain "github.com/eitanity/kanonarion/internal/sbom/domain"
	vendordomain "github.com/eitanity/kanonarion/internal/vendortree/domain"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// Result types (received by consumers). Each is a TYPE ALIAS to the internal
// serialized record so the Go type and its JSON projection cannot drift
// (§2.1): there is exactly one definition, and the façade re-exports it
// by reference rather than copying its shape. Consumers receive these from the
// query use cases; they MUST ignore unknown fields and MUST NOT construct them
// positionally or assume field exhaustiveness — within a major version a field
// may be added (a minor change), but removing or retyping one is breaking
// (§4).

// ModuleCoordinate uniquely identifies a Go module at a specific version
// (path + version). It is the coordinate every other result type is keyed by.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major; consumers must not assume field exhaustiveness
// (§4).
type ModuleCoordinate = coordinate.ModuleCoordinate

// FactRecord is the persisted, tamper-evident fetch result for a module: its
// hashes, git provenance, and verification outcome. It is the read-shaped,
// serialized projection of the fetch aggregate (the FetchedModule aggregate root
// stays internal); all fields are exported primitives with stable JSON tags.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major; consumers must not assume field exhaustiveness
// (§4).
type FactRecord = fetchdomain.FactRecord

// WalkRecord is the persisted result of a dependency-graph walk: the resolved
// graph, per-node fetch results, and overall status for a target module.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major; consumers must not assume field exhaustiveness
// (§4).
type WalkRecord = walkdomain.WalkRecord

// LicenseRecord is the persisted result of a module's license extraction: the
// SPDX expression, per-file and per-package findings, and copyright provenance.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major; consumers must not assume field exhaustiveness
// (§4).
type LicenseRecord = licensedomain.LicenseRecord

// InterfaceRecord is the persisted result of a module's public-API extraction:
// the exported types, funcs, consts, and vars of every package.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major; consumers must not assume field exhaustiveness
// (§4).
type InterfaceRecord = ifacedomain.InterfaceRecord

// CallGraphRecord is the persisted result of a module's call-graph extraction:
// the nodes and edges, plus the exclusion policy in force at extraction time.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major; consumers must not assume field exhaustiveness
// (§4).
type CallGraphRecord = callgraphdomain.CallGraphRecord

// ExampleRecord is the persisted result of a module's Example* function harvest,
// each example associated with the symbol it documents.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major; consumers must not assume field exhaustiveness
// (§4).
type ExampleRecord = exampledomain.ExampleRecord

// ExtractionRun is the persisted result of a coordinated extraction operation
// over a walk: per-module stage outcomes and the pipeline versions that ran.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major; consumers must not assume field exhaustiveness
// (§4).
type ExtractionRun = extractdomain.ExtractionRun

// VulnerabilityRecord is the aggregated result of a module's vulnerability scan:
// the findings, scan status, and the database snapshot scanned against.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major; consumers must not assume field exhaustiveness
// (§4).
type VulnerabilityRecord = vulndomain.VulnerabilityRecord

// WalkScanRun is the aggregated result of scanning every module in a walk: the
// per-module record references, overall status, and the snapshot scanned against.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major; consumers must not assume field exhaustiveness
// (§4).
type WalkScanRun = vulndomain.WalkScanRun

// SBOMRecord is the persisted SBOM document for a walk: the canonical document
// bytes, their format, and the content digest that identifies them.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major; consumers must not assume field exhaustiveness
// (§4).
type SBOMRecord = sbomdomain.SBOMRecord

// Component is one resolved SBOM component: the module it identifies and the
// SPDX license and copyright attached to it.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major; consumers must not assume field exhaustiveness
// (§4).
type Component = sbomdomain.Component

// DirectiveRecord is the persisted result of a project directive scan: the
// classified replace/exclude directives of a go.mod/go.work, the resolved
// versions used for classification, and the scan's identity and timing.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major; consumers must not assume field exhaustiveness
// (§4).
type DirectiveRecord = directivedomain.Record

// GoDebugRecord is the persisted result of a project godebug scan: the
// detected //go:debug settings classified under a versioned taxonomy.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major; consumers must not assume field exhaustiveness
// (§4).
type GoDebugRecord = godebugdomain.Record

// VendorRecord is the persisted result of a vendored-closure scan: the
// reconciled vendor/ modules, drift and inconsistency findings, and the
// overall status.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major; consumers must not assume field exhaustiveness
// (§4).
type VendorRecord = vendordomain.Record

// FIPSRecord is the persisted result of a project FIPS assessment: the
// toolchain capability headline, non-FIPS algorithm and cgo-crypto findings,
// and the eligibility-vs-validation-caveated compliance assessment.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major; consumers must not assume field exhaustiveness
// (§4).
type FIPSRecord = fipsdomain.Record
