package kanonarion

import (
	"fmt"

	callgraphports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	configports "github.com/eitanity/kanonarion/internal/config/ports"
	exampleports "github.com/eitanity/kanonarion/internal/example/ports"
	extractports "github.com/eitanity/kanonarion/internal/extract/ports"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
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
//
// Pre-v1 amendment, made deliberately rather than broken silently: BlobStore's
// method SIGNATURES and FactStore's have been reshaped, which the rule above
// would otherwise forbid. Both changes remove a defect the contract itself
// permitted — a store-chosen opaque blob handle persisted into a fact record,
// and a fact store keyed so that every re-measurement destroyed its predecessor.
// Neither could be fixed additively, because in both cases the wrong thing was
// the signature. The affected doc comments say so individually. This licence is
// spent, not standing: it applies to these two ports in this change, and the
// rule is otherwise in force.

// FactStore persists and retrieves fetch facts as an append-only ledger — the
// fetch fact persistence seam the enterprise build replaces with its own
// backend.
//
// PutFetchRecord appends a SealedRecord and never overwrites; GetFetchRecord
// returns the CompositeRecord composed from every measurement of an artefact.
// Both signatures changed under the pre-v1 amendment above: the port previously
// took and returned a bare FactRecord, which let an unhashed record reach
// storage and let each write destroy the evidence of the one before it.
//
// Stability: substitution port (implemented by consumers); unstable pre-v1.
// Grows only by a new optional interface, never by adding a method (§4).
type FactStore = fetchports.FactStore

// FactRecordLister is the optional capability a FactStore may also implement to
// return the individual measurements behind a composed record. Core
// type-asserts for it and degrades to the composed read when it is absent; the
// fetch pipeline uses it to inherit validation legs from earlier measurements.
//
// Stability: optional substitution port (implemented by consumers); unstable
// pre-v1. It is the additive-extension mechanism (§4) applied to FactStore.
type FactRecordLister = fetchports.FactRecordLister

// SealedRecord is a fact record that has been shown to carry its own content
// hash. It is the only shape FactStore accepts for writing, so a record whose
// hash does not describe its contents cannot reach storage. Obtain one from the
// fetch domain's Seal (from a fresh measurement) or Rehydrate (from persisted
// fields, verifying and failing closed).
//
// Stability: supporting type of the FactStore port; unstable pre-v1.
type SealedRecord = fetchdomain.SealedRecord

// CompositeRecord is the artefact as the ledger knows it: the identity every
// measurement of it shares, when it was first seen, the measurement being
// served, and the validation legs any measurement established. It is what
// GetFetchRecord returns and what domains outside fetch receive.
//
// The served FactRecord is embedded, so field reads mean what they always
// meant. Read FirstFetchedAt, not the embedded FetchedAt, for "when was this
// module fetched": the embedded record's own time is the time of the
// measurement being served, which for a revalidation is later than first sight.
//
// Stability: supporting type of the FactStore port; unstable pre-v1.
type CompositeRecord = fetchdomain.CompositeRecord

// ComposeFetchRecords folds the measurements of one artefact into the
// CompositeRecord GetFetchRecord returns. An external FactStore implementer
// needs it for the same reason SealedRecord is exported: the port's return type
// is a composition, so an implementer must be able to produce one rather than
// reverse-engineer the folding rules.
//
// The rules are not cosmetic. The record it serves is the strongest ELIGIBLE
// measurement, never simply the most recent — serving the newest would let a
// record whose checksum-database lookup failed, appended after a good one,
// become the answer on every subsequent run until an operator forced a
// re-measurement.
//
// Stability: supporting function of the FactStore port; unstable pre-v1.
func ComposeFetchRecords(records []FactRecord) (CompositeRecord, error) {
	composed, err := fetchdomain.Compose(records)
	if err != nil {
		return CompositeRecord{}, fmt.Errorf("composing fetch records: %w", err)
	}
	return composed, nil
}

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

// BlobStore persists binary artefacts (module zips and go.mod files) under an
// address chosen by their content. Its core is Put/Get/Exists, with the
// filesystem-path capability split out into the optional BlobPathOptimizer so an
// object-store backend (e.g. S3) can satisfy BlobStore without faking a local
// path.
//
// Every method takes a BlobIdentity. The store does not choose addresses: it
// used to, and the handle it chose was persisted into fact records, so a record
// described where one run had put the bytes rather than what the bytes were and
// the same artefact acquired two ways produced two irreconcilable records. That
// signature change is made under the pre-v1 amendment at the top of this file.
//
// An implementation must address by identity, verify before serving (produce
// bytes matching the requested identity or report absence), decline
// BlobPathOptimizer rather than fake a path, and guarantee only that after Put,
// Exists is true — how the bytes arrive is entirely its own business.
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

// BlobIdentity is the content-chosen address Put, Get, Exists and GetPath all
// accept. It is derived from the fetch measurement — the artefact's h1 hash plus
// which artefact of the module it names — never invented by a store, so two
// stores asked for the same artefact are asked with the same value. It replaces
// the opaque BlobHandle a store used to return.
//
// Stability: supporting type of the BlobStore port; unstable pre-v1.
type BlobIdentity = fetchports.BlobIdentity

// BlobKind names which artefact of a module version a BlobIdentity addresses:
// the module zip or the standalone go.mod. It exists so the two cannot collide
// in a store that holds both, since a go.mod-only measurement records the
// go.mod's hash as the artefact identity.
//
// Stability: supporting type of the BlobStore port; unstable pre-v1.
type BlobKind = fetchports.BlobKind

// ModuleHash is the h1 hash of a module zip or go.mod, the value a BlobIdentity
// is built from. It is exported for the same reason the kinds below are: an
// external implementer cannot construct an identity without naming one.
//
// Stability: supporting type of the BlobStore port; unstable pre-v1.
type ModuleHash = fetchdomain.ModuleHash

// BlobKindZip and BlobKindGoMod are the two artefacts of a module version a
// BlobIdentity can address. They are exported alongside BlobKind because an
// external implementer cannot construct an identity without naming one.
//
// Stability: supporting constants of the BlobStore port; unstable pre-v1.
const (
	BlobKindZip   = fetchports.BlobKindZip
	BlobKindGoMod = fetchports.BlobKindGoMod
)

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
