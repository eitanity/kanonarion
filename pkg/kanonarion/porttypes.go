package kanonarion

import (
	"github.com/eitanity/kanonarion/internal/audit"
	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	callgraphports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	directivedomain "github.com/eitanity/kanonarion/internal/directive/domain"
	exampledomain "github.com/eitanity/kanonarion/internal/example/domain"
	exampleports "github.com/eitanity/kanonarion/internal/example/ports"
	extractdomain "github.com/eitanity/kanonarion/internal/extract/domain"
	extractports "github.com/eitanity/kanonarion/internal/extract/ports"
	"github.com/eitanity/kanonarion/internal/failurecause"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	fipsdomain "github.com/eitanity/kanonarion/internal/fips/domain"
	godebugdomain "github.com/eitanity/kanonarion/internal/godebug/domain"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
	licenseports "github.com/eitanity/kanonarion/internal/license/ports"
	nativedomain "github.com/eitanity/kanonarion/internal/native/domain"
	sbomdomain "github.com/eitanity/kanonarion/internal/sbom/domain"
	stalenessdomain "github.com/eitanity/kanonarion/internal/staleness/domain"
	stdlibdomain "github.com/eitanity/kanonarion/internal/stdlib/domain"
	vendordomain "github.com/eitanity/kanonarion/internal/vendortree/domain"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// Supporting types of the published ports. Every type a substitution port in
// this package names, followed through exported struct fields and interface
// methods, is aliased here so another module can implement the port without
// importing internal/. TestPublishedPortsNameOnlyPublishedTypes keeps the set
// closed.

// AdvisoryReference is one link an advisory publishes about itself: the OSV
// {type, url} pair, carried whole.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type AdvisoryReference = vulndomain.AdvisoryReference

// AnalyserIdentity is what a stored row says about the library that parsed
// the module, together with how it came to say it.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type AnalyserIdentity = callgraphdomain.AnalyserIdentity

// AnalyserLimit is a load refused because the source is newer than the Go the
// analysing binary was compiled with.
//
// Stability: supporting type of the ExampleStore and InterfaceStore ports;
// unstable pre-v1. Fields may be added within a major version (§4).
type AnalyserLimit = gotoolchain.AnalyserLimit

// AnalyserProvenance says HOW the store came to state an analyser version,
// and it travels with the version rather than beside it.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type AnalyserProvenance = callgraphdomain.AnalyserProvenance

// AnalyserVersion is the golang.org/x/tools version that type-checked a
// module and built the SSA a call graph was computed over.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type AnalyserVersion = callgraphdomain.AnalyserVersion

// AnalysisSource names what an analysis read to build a call graph.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type AnalysisSource = callgraphdomain.AnalysisSource

// AnalysisSurface names which copy of a module's source a scan measured.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type AnalysisSurface = vulndomain.AnalysisSurface

// ArtefactIdentity is the content-chosen address of the artefact a fact
// record describes.
//
// Stability: supporting type of the FactStore and WalkStore ports; unstable
// pre-v1. Fields may be added within a major version (§4).
type ArtefactIdentity = fetchdomain.ArtefactIdentity

// ArtifactDigests holds the raw content digests of a downloaded artefact (a
// module zip, or the stdlib source tarball) computed over the exact bytes
// received at acquisition time.
//
// Stability: supporting type of the ModuleProxy, StdlibStore and WalkStore
// ports; unstable pre-v1. Fields may be added within a major version (§4).
type ArtifactDigests = fetchdomain.ArtifactDigests

// ArtifactKind describes what the analysed module is, which decides how
// reachability roots are chosen.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type ArtifactKind = callgraphdomain.ArtifactKind

// AttestationRecord is an additive provenance record: a signature over a
// subject digest taken from core's canonical identity, persisted alongside
// the fact it attests without altering it.
//
// Stability: supporting type of the AttestationStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type AttestationRecord = fetchdomain.AttestationRecord

// AuditEventType is the discriminator stored as the `event_type` field of
// every audit envelope.
//
// Stability: supporting type of the AuditSink port; unstable pre-v1. Values
// may be added within a major version (§4).
type AuditEventType = audit.EventType

// BuildEnvFilter names the target platform a walk was resolved for, as
// WalkFilter.BuildEnv matches it.
//
// Stability: supporting type of the WalkStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type BuildEnvFilter = walkports.BuildEnvFilter

// BuildFrame is the platform a call graph was extracted under, which every
// call-graph read selects on.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type BuildFrame = callgraphdomain.BuildFrame

// CallEdge is a directed call relationship between two nodes.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type CallEdge = callgraphdomain.CallEdge

// CallEdgeRef identifies a single call edge in the store, returned by
// FindCallers/FindCallees.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type CallEdgeRef = callgraphports.CallEdgeRef

// CallGraphAlgorithm names the static analysis algorithm used to produce the
// call graph.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type CallGraphAlgorithm = callgraphdomain.CallGraphAlgorithm

// CallGraphFilter constrains ListCallGraphRecords results.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type CallGraphFilter = callgraphports.CallGraphFilter

// CallGraphOutcome is what one call-graph generation states about itself: the
// seal it was written under and what it says the analysis came to.
//
// Stability: supporting type of the CallGraphOutcomeReader port; unstable
// pre-v1. Fields may be added within a major version (§4).
type CallGraphOutcome = callgraphports.CallGraphOutcome

// CallGraphSourcePosition identifies a location in a source file.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type CallGraphSourcePosition = callgraphdomain.SourcePosition

// CallGraphStatus describes the outcome of call graph extraction.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type CallGraphStatus = callgraphdomain.CallGraphStatus

// CallGraphSummary is a lightweight projection of a CallGraphRecord for list
// views.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type CallGraphSummary = callgraphports.CallGraphSummary

// CallNode is a function or method node in the call graph.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type CallNode = callgraphdomain.CallNode

// CallgraphConfig holds call-graph extraction settings.
//
// Stability: supporting type of the ConfigStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type CallgraphConfig = configdomain.CallgraphConfig

// ChainOfTitleConfidence describes how well-evidenced the module's license
// chain of title is, combining contribution-licensing signals with copyright
// extraction results.
//
// Stability: supporting type of the LicenseStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type ChainOfTitleConfidence = licensedomain.ChainOfTitleConfidence

// CompletenessLevel records the fidelity at which a module's call graph was
// analysed.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type CompletenessLevel = callgraphdomain.CompletenessLevel

// Config is the root configuration type loaded from <store-root>/config.yaml.
//
// Stability: supporting type of the ConfigStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type Config = configdomain.Config

// ConfigPreferences holds sticky per-user output preferences.
//
// Stability: supporting type of the ConfigStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type ConfigPreferences = configdomain.Preferences

// CopyrightDeclaration is one operator-recorded copyright line for a module
// the copyright extractor found nothing in.
//
// Stability: supporting type of the ConfigStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type CopyrightDeclaration = configdomain.CopyrightDeclaration

// CopyrightStatement is a single copyright notice identified in a file.
//
// Stability: supporting type of the LicenseStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type CopyrightStatement = licensedomain.CopyrightStatement

// CopyrightStatus describes whether copyright extraction has been performed
// and whether any statements were found.
//
// Stability: supporting type of the LicenseStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type CopyrightStatus = licensedomain.CopyrightStatus

// CoverageStatus answers "was every module in the build list analysed?" — one
// of the two axes WalkScanStatus conflates.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type CoverageStatus = vulndomain.CoverageStatus

// Directive is one detected `replace`/`exclude` with its provenance,
// classification and policy verdict.
//
// Stability: supporting type of the DirectiveStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type Directive = directivedomain.Directive

// DirectiveKind is the directive type.
//
// Stability: supporting type of the DirectiveStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type DirectiveKind = directivedomain.Kind

// DirectivePolicy governs go.mod/go.work replace & exclude directives by risk
// classification.
//
// Stability: supporting type of the ConfigStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type DirectivePolicy = configdomain.DirectivePolicy

// DispatchKind names how control reached one hop of a route.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type DispatchKind = vulndomain.DispatchKind

// DroppedReplace names one replace directive an analysis removed from an
// extracted module's own go.mod before loading it.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type DroppedReplace = callgraphdomain.DroppedReplace

// EdgeConfidence describes how a call edge was resolved, so consumers can
// weight edges by resolution tier and the verdict layer can key soundness
// decisions off the tag.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type EdgeConfidence = callgraphdomain.EdgeConfidence

// EdgeKind names what an edge records: a call, or a reference to a function
// as a value.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type EdgeKind = callgraphdomain.EdgeKind

// EdgeQueryOptions narrows a caller/callee query.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type EdgeQueryOptions = callgraphports.EdgeQueryOptions

// EffectiveLicenseSet captures the union of root-level and embedded-component
// licenses for a module.
//
// Stability: supporting type of the LicenseStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type EffectiveLicenseSet = licensedomain.EffectiveLicenseSet

// EmbeddedComponent represents a distinct third-party component bundled
// within a module, with the licence it carries.
//
// Stability: supporting type of the LicenseStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type EmbeddedComponent = licensedomain.EmbeddedComponent

// ExampleEntry records a single Example* function found in a _test.go file.
//
// Stability: supporting type of the ExampleStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type ExampleEntry = exampledomain.ExampleEntry

// ExampleFilter constrains ListExampleRecords results.
//
// Stability: supporting type of the ExampleStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type ExampleFilter = exampleports.ExampleFilter

// ExampleParseFailure records a _test.go file that could not be parsed.
//
// Stability: supporting type of the ExampleStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type ExampleParseFailure = exampledomain.ParseFailure

// ExampleRef identifies a specific example in the index, returned by
// FindBySymbol.
//
// Stability: supporting type of the ExampleStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type ExampleRef = exampleports.ExampleRef

// ExampleSourcePosition identifies a location in a source file.
//
// Stability: supporting type of the ExampleStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type ExampleSourcePosition = exampledomain.SourcePosition

// ExampleStatus describes the outcome of example extraction for a module.
//
// Stability: supporting type of the ExampleStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type ExampleStatus = exampledomain.ExampleStatus

// ExampleSummary is a lightweight projection of an ExampleRecord for list
// views.
//
// Stability: supporting type of the ExampleStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type ExampleSummary = exampleports.ExampleSummary

// ExportDirective is the directive that hands a package-level function to a
// caller outside Go.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type ExportDirective = callgraphdomain.ExportDirective

// ExportKind names who calls a function from outside Go.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type ExportKind = callgraphdomain.ExportKind

// HandlerKind names the call that installs a function as a hardware interrupt
// handler by value.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type HandlerKind = callgraphdomain.HandlerKind

// InterruptHandler records that a function is installed as a hardware interrupt
// handler by value, and where.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type InterruptHandler = callgraphdomain.InterruptHandler

// ExtractionRunFilter constrains ListExtractionRuns results.
//
// Stability: supporting type of the ExtractionStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type ExtractionRunFilter = extractports.ExtractionRunFilter

// ExtractionRunStatus summarises the overall outcome of an ExtractionRun.
//
// Stability: supporting type of the ExtractionStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type ExtractionRunStatus = extractdomain.ExtractionRunStatus

// ExtractionRunSummary is a lightweight projection of an ExtractionRun for
// list views.
//
// Stability: supporting type of the ExtractionStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type ExtractionRunSummary = extractports.ExtractionRunSummary

// FIPSCategory is the policy-category token (FIPSCompliant / FIPSDeviation /
// FIPSUnknown in config domain) a finding maps to.
//
// Stability: supporting type of the FIPSStore port; unstable pre-v1. Values
// may be added within a major version (§4).
type FIPSCategory = fipsdomain.Category

// FIPSFinding is one assessed fact about FIPS eligibility.
//
// Stability: supporting type of the FIPSStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type FIPSFinding = fipsdomain.Finding

// FIPSFindingKind classifies one assessed fact about FIPS eligibility.
//
// Stability: supporting type of the FIPSStore port; unstable pre-v1. Values
// may be added within a major version (§4).
type FIPSFindingKind = fipsdomain.FindingKind

// FIPSPolicy governs FIPS eligibility assessment.
//
// Stability: supporting type of the ConfigStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type FIPSPolicy = configdomain.FIPSPolicy

// FailureCause says where a recorded failure lies: unrecorded, in the module,
// or in this environment.
//
// Stability: supporting type of the CallGraphStore, ExtractionStore and
// VulnerabilityStore ports; unstable pre-v1. Values may be added within a
// major version (§4).
type FailureCause = failurecause.Cause

// FetchPolicy governs the fetch stage's cross-verification posture.
//
// Stability: supporting type of the ConfigStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type FetchPolicy = configdomain.FetchPolicy

// FindingsStatus answers "did the analysis find vulnerabilities?" — the other
// axis WalkScanStatus conflates.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type FindingsStatus = vulndomain.FindingsStatus

// ForeignModule names a module OTHER than the analysed one whose packages
// this analysis built with bodies, at the version resolution gave it.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type ForeignModule = callgraphdomain.ForeignModule

// GateOutcome says what the reuse gate did for the run that appended this
// generation.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type GateOutcome = callgraphdomain.GateOutcome

// GenerationDerivation states why a generation exists, as distinct from what
// it measured.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type GenerationDerivation = callgraphdomain.GenerationDerivation

// GoDebugPolicy governs GODEBUG / //go:debug settings by the versioned
// taxonomy tier assigned in red (security-weakening), amber
// (behaviour-modifying with security implications), green (benign).
//
// Stability: supporting type of the ConfigStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type GoDebugPolicy = configdomain.GoDebugPolicy

// GoDebugSetting is one detected //go:debug setting with its provenance,
// classification and policy verdict.
//
// Stability: supporting type of the GoDebugStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type GoDebugSetting = godebugdomain.Setting

// GoDebugTier is the security risk tier the versioned taxonomy assigns a
// setting.
//
// Stability: supporting type of the GoDebugStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type GoDebugTier = godebugdomain.Tier

// GoModDownload carries the standalone go.mod artefact from a proxy
// go.mod-only download.
//
// Stability: supporting type of the ModuleProxy port; unstable pre-v1. Fields
// may be added within a major version (§4).
type GoModDownload = fetchports.GoModDownload

// GraphEdge is a directed dependency relationship between two modules.
//
// Stability: supporting type of the WalkStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type GraphEdge = walkdomain.GraphEdge

// GraphNode is a single module in the dependency graph.
//
// Stability: supporting type of the WalkStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type GraphNode = walkdomain.GraphNode

// HopDispatch states how control reached one hop of a route, read off the
// call-graph edge that reaches it.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type HopDispatch = vulndomain.HopDispatch

// ImplementedMethod binds one interface method name to the concrete
// call-graph node that satisfies it, so the per-method form of an
// implementers query answers with node IDs the edge queries also accept.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type ImplementedMethod = callgraphdomain.ImplementedMethod

// InterfaceBuildFrame names the build configuration a public API was measured
// in.
//
// Stability: supporting type of the InterfaceStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type InterfaceBuildFrame = ifacedomain.BuildFrame

// InterfaceFieldDecl describes an exported struct field.
//
// Stability: supporting type of the InterfaceStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type InterfaceFieldDecl = ifacedomain.FieldDecl

// InterfaceFilter constrains ListInterfaceRecords results.
//
// Stability: supporting type of the InterfaceStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type InterfaceFilter = ifaceports.InterfaceFilter

// InterfaceFuncDecl describes an exported package-level function (not a
// method).
//
// Stability: supporting type of the InterfaceStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type InterfaceFuncDecl = ifacedomain.FuncDecl

// InterfaceImplementation records that a concrete named type in the analysed
// module satisfies an interface the module declares.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type InterfaceImplementation = callgraphdomain.InterfaceImplementation

// InterfaceMethodDecl describes an exported method on a type.
//
// Stability: supporting type of the InterfaceStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type InterfaceMethodDecl = ifacedomain.MethodDecl

// InterfaceParseFailure records a source file that could not be parsed.
//
// Stability: supporting type of the InterfaceStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type InterfaceParseFailure = ifacedomain.ParseFailure

// InterfaceSourcePosition identifies a location in a source file.
//
// Stability: supporting type of the InterfaceStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type InterfaceSourcePosition = ifacedomain.SourcePosition

// InterfaceStatus describes the outcome of interface extraction for a module.
//
// Stability: supporting type of the InterfaceStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type InterfaceStatus = ifacedomain.InterfaceStatus

// InterfaceSummary is a lightweight projection of an InterfaceRecord for list
// views.
//
// Stability: supporting type of the InterfaceStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type InterfaceSummary = ifaceports.InterfaceSummary

// InterfaceType is an interface declared in the analysed module, made
// addressable so a port-signature change can ask the type question — which
// concrete method sets must change together — rather than the edge question.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type InterfaceType = callgraphdomain.InterfaceType

// InterfaceTypeDecl describes an exported type.
//
// Stability: supporting type of the InterfaceStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type InterfaceTypeDecl = ifacedomain.TypeDecl

// InterfaceTypeKind classifies the form of a type declaration.
//
// Stability: supporting type of the InterfaceStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type InterfaceTypeKind = ifacedomain.TypeKind

// InterfaceTypeParam represents a type parameter in a generic declaration.
//
// Stability: supporting type of the InterfaceStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type InterfaceTypeParam = ifacedomain.TypeParam

// InterfaceValueDecl describes an exported constant or variable.
//
// Stability: supporting type of the InterfaceStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type InterfaceValueDecl = ifacedomain.ValueDecl

// LegProvenance discriminates a check performed by this measurement from one
// carried forward.
//
// Stability: supporting type of the FactStore and WalkStore ports; unstable
// pre-v1. Values may be added within a major version (§4).
type LegProvenance = fetchdomain.LegProvenance

// LicenseAltMatch is an alternative license identification for a file,
// reported when the detector produced multiple candidates.
//
// Stability: supporting type of the LicenseStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type LicenseAltMatch = licensedomain.AltMatch

// LicenseCoverage says what one identified licence governs inside a module:
// the module's own Go code, documentation shipped beside it, or third-party
// material the module carries.
//
// Stability: supporting type of the LicenseStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type LicenseCoverage = licensedomain.LicenseCoverage

// LicenseFileEntry records a single license-named file found in a module zip.
//
// Stability: supporting type of the LicenseStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type LicenseFileEntry = licensedomain.LicenseFileEntry

// LicenseFilter constrains ListLicenceRecords results.
//
// Stability: supporting type of the LicenseStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type LicenseFilter = licenseports.LicenseFilter

// LicenseOverride is one operator-recorded licence determination: the SPDX
// identifier a person asserts for a module, and optionally who determined it,
// when, and what they read.
//
// Stability: supporting type of the ConfigStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type LicenseOverride = configdomain.LicenseOverride

// LicensePolicy defines named license categories and scope-based rules.
//
// Stability: supporting type of the ConfigStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type LicensePolicy = configdomain.LicensePolicy

// LicensePolicyRule maps category names to outcomes for a given dependency
// scope.
//
// Stability: supporting type of the ConfigStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type LicensePolicyRule = configdomain.LicensePolicyRule

// LicenseStatus describes the outcome of license extraction for a module.
//
// Stability: supporting type of the LicenseStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type LicenseStatus = licensedomain.LicenseStatus

// LicenseSummary is a lightweight projection of a LicenceRecord for list
// views.
//
// Stability: supporting type of the LicenseStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type LicenseSummary = licenseports.LicenseSummary

// ModuleDownload carries the artefacts from a proxy download.
//
// Stability: supporting type of the ModuleProxy port; unstable pre-v1. Fields
// may be added within a major version (§4).
type ModuleDownload = fetchports.ModuleDownload

// ModuleExtractionResult summarizes which stages were run for a single
// module.
//
// Stability: supporting type of the ExtractionStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type ModuleExtractionResult = extractdomain.ModuleExtractionResult

// ModuleInfo is the parsed response from a proxy.info endpoint.
//
// Stability: supporting type of the ModuleProxy port; unstable pre-v1. Fields
// may be added within a major version (§4).
type ModuleInfo = fetchports.ModuleInfo

// ModuleOrigin carries VCS provenance from a proxy.info response.
//
// Stability: supporting type of the ModuleProxy port; unstable pre-v1. Fields
// may be added within a major version (§4).
type ModuleOrigin = fetchports.ModuleOrigin

// ModuleSet is a set of module coordinates naming the resolved version set of
// one build — the answer to "which module@version pairs are actually in this
// binary", as opposed to "which ones does the store happen to hold".
//
// Stability: supporting type of the CallGraphStore, ExampleStore and
// InterfaceStore ports; unstable pre-v1. Fields may be added within a major
// version (§4).
type ModuleSet = coordinate.ModuleSet

// NativeComponent is one third-party native library compiled into the host
// module.
//
// Stability: supporting type of the NativeStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type NativeComponent = nativedomain.Component

// NativeConfidence states how a component's version was established.
//
// Stability: supporting type of the NativeStore port; unstable pre-v1. Values
// may be added within a major version (§4).
type NativeConfidence = nativedomain.Confidence

// NativeEvidence is one declaration a recipe matched, and where it was read.
//
// Stability: supporting type of the NativeStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type NativeEvidence = nativedomain.Evidence

// NativeLinkedLibrary is one native library a cgo directive names as linked
// into the binary, recorded whether or not the artefact ships its source.
//
// Stability: supporting type of the NativeStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type NativeLinkedLibrary = nativedomain.LinkedLibrary

// NativeLinkedLibraryKind separates the C runtime a cgo binary links by
// construction from a named component that comes from outside the module.
//
// Stability: supporting type of the NativeStore port; unstable pre-v1. Values
// may be added within a major version (§4).
type NativeLinkedLibraryKind = nativedomain.LinkedLibraryKind

// NativePresence is what the artefact was found to carry.
//
// Stability: supporting type of the NativeStore port; unstable pre-v1. Values
// may be added within a major version (§4).
type NativePresence = nativedomain.Presence

// NativeRecord is the persisted result of examining one module artefact for
// embedded native components.
//
// Stability: supporting type of the NativeStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type NativeRecord = nativedomain.Record

// NativeSource is one native file the build compiles, recorded whether or not
// a recipe matched it.
//
// Stability: supporting type of the NativeStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type NativeSource = nativedomain.Source

// NegativeSearch is the result of running kanonarion's own call-graph search
// for a finding whose recorded negative rests on another analyser's silence.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type NegativeSearch = vulndomain.NegativeSearch

// NodeResult is the per-module outcome of a Walk operation.
//
// Stability: supporting type of the WalkStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type NodeResult = walkdomain.NodeResult

// NodeStatus summarises the fetch outcome for a single module in the graph.
//
// Stability: supporting type of the WalkStore port; unstable pre-v1. Values
// may be added within a major version (§4).
type NodeStatus = walkdomain.NodeStatus

// PackageInterface captures the full exported API of a single package.
//
// Stability: supporting type of the InterfaceStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type PackageInterface = ifacedomain.PackageInterface

// PackageLicense describes the license that governs a specific non-root
// sub-package directory within the module (first-party code, not vendored).
//
// Stability: supporting type of the LicenseStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type PackageLicense = licensedomain.PackageLicense

// PolicyOutcome is the result of evaluating a license against a policy rule.
//
// Stability: supporting type of the ConfigStore port; unstable pre-v1. Values
// may be added within a major version (§4).
type PolicyOutcome = configdomain.PolicyOutcome

// ProvenanceSignal is a single artifact-discoverable contribution-licensing
// signal found in the module zip.
//
// Stability: supporting type of the LicenseStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type ProvenanceSignal = licensedomain.ProvenanceSignal

// ProvenanceSummary is the contribution-licensing provenance extracted from
// the module zip.
//
// Stability: supporting type of the LicenseStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type ProvenanceSummary = licensedomain.ProvenanceSummary

// ReachabilityInstrument names the instrument that produced a reachability
// answer.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type ReachabilityInstrument = vulndomain.ReachabilityAnalyser

// ReachabilityConfidence describes the confidence level of a reachability
// determination.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type ReachabilityConfidence = vulndomain.ReachabilityConfidence

// ReachabilityDerivation states how a reachability answer was reached.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type ReachabilityDerivation = vulndomain.ReachabilityDerivation

// ReachabilityFrame is one hop on the route from an entry point to a
// vulnerable symbol.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type ReachabilityFrame = vulndomain.ReachabilityFrame

// ReachabilityResult captures whether a vulnerability is reachable from the
// analysed entry points, the routes that reach it, and how the answer was
// derived.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type ReachabilityResult = vulndomain.ReachabilityResult

// ReachabilityRoute is one path from an entry point to the vulnerable symbol,
// ordered ENTRY POINT FIRST and vulnerable symbol last.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type ReachabilityRoute = vulndomain.ReachabilityRoute

// RecordCoverageStatus answers "was this module analysed?" — one of the two
// axes VulnerabilityStatus conflates, at the per-module level where
// WalkScanRun's CoverageStatus answers it for a whole run.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type RecordCoverageStatus = vulndomain.RecordCoverageStatus

// RecordFindingsStatus answers "did the analysis report a vulnerability?" —
// the other axis, mirroring WalkScanRun's FindingsStatus.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type RecordFindingsStatus = vulndomain.RecordFindingsStatus

// ReferenceScope records whether an analysis looked for reference edges at
// all.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type ReferenceScope = callgraphdomain.ReferenceScope

// ReflectiveDispatchSite is one call the search could not follow: a call site
// in the graph searched whose callee picks what runs at run time.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type ReflectiveDispatchSite = vulndomain.ReflectiveDispatchSite

// ResolutionSource describes how a node's version was selected during MVS
// resolution.
//
// Stability: supporting type of the WalkStore port; unstable pre-v1. Values
// may be added within a major version (§4).
type ResolutionSource = walkdomain.ResolutionSource

// ReuseGate names the check a run consults before appending a generation:
// whether the ledger already holds this analysis.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type ReuseGate = callgraphdomain.ReuseGate

// RiskClass is the security risk a directive carries.
//
// Stability: supporting type of the DirectiveStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type RiskClass = directivedomain.RiskClass

// SBOMFormat identifies the serialisation format of an SBOM document.
//
// Stability: supporting type of the SBOMStore port; unstable pre-v1. Values
// may be added within a major version (§4).
type SBOMFormat = sbomdomain.SBOMFormat

// StageDepth holds the traversal parameters for a single pipeline stage.
//
// Stability: supporting type of the WalkStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type StageDepth = walkdomain.StageDepth

// StageResult captures the outcome and record ID of a single stage.
//
// Stability: supporting type of the ExtractionStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type StageResult = extractdomain.StageResult

// StageStatus reflects the outcome of a single extraction stage for a module.
//
// Stability: supporting type of the ExtractionStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type StageStatus = extractdomain.StageStatus

// StalenessConfig governs the store-backed ledger of latest-version lookups.
//
// Stability: supporting type of the ConfigStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type StalenessConfig = configdomain.StalenessConfig

// StorageConfig is the storage section of config.yaml.
//
// Stability: supporting type of the ConfigStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type StorageConfig = configdomain.StorageConfig

// StalenessDeprecation is the module's own deprecation notice — the `//
// Deprecated:` comment on the `module` directive in its go.mod, which the go
// command reports alongside the latest-version answer.
//
// Stability: supporting type of the StalenessLedger port; unstable pre-v1.
// Fields may be added within a major version (§4).
type StalenessDeprecation = stalenessdomain.Deprecation

// StalenessNewerMajor is the result of probing major-suffixed paths ABOVE the
// pinned major.
//
// Stability: supporting type of the StalenessLedger port; unstable pre-v1.
// Fields may be added within a major version (§4).
type StalenessNewerMajor = stalenessdomain.NewerMajor

// StalenessRecord is one module path's cached upstream-latest facts.
//
// Stability: supporting type of the StalenessLedger port; unstable pre-v1.
// Fields may be added within a major version (§4).
type StalenessRecord = stalenessdomain.Record

// StalenessRepublication is the module's own major published at its /vN path
// — the answer to the extra question a +incompatible pin asks before the
// upward walk.
//
// Stability: supporting type of the StalenessLedger port; unstable pre-v1.
// Fields may be added within a major version (§4).
type StalenessRepublication = stalenessdomain.Republication

// StdlibAcquisitionRoute names where a standard-library measurement got its
// bytes.
//
// Stability: supporting type of the StdlibStore port; unstable pre-v1. Values
// may be added within a major version (§4).
type StdlibAcquisitionRoute = stdlibdomain.AcquisitionRoute

// StdlibCustodyFacts is the persisted chain-of-custody evidence for one Go
// standard-library version.
//
// Stability: supporting type of the StdlibStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type StdlibCustodyFacts = stdlibdomain.Facts

// StdlibFacts is the standard library's chain-of-custody evidence, carried on
// the synthetic stdlib graph node so downstream stages (SBOM, audit) read a
// real verification status, real artefact hashes, and a real licence instead
// of special-cased constants.
//
// Stability: supporting type of the WalkStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type StdlibFacts = walkdomain.StdlibFacts

// StdlibVerificationStatus records how far the standard-library source
// tarball was verified.
//
// Stability: supporting type of the StdlibStore port; unstable pre-v1. Values
// may be added within a major version (§4).
type StdlibVerificationStatus = stdlibdomain.VerificationStatus

// SubjectKind names what a signature attests over.
//
// Stability: supporting type of the AttestationStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type SubjectKind = fetchdomain.SubjectKind

// SumDBResult is the outcome of a checksum database lookup.
//
// Stability: supporting type of the SumDBClient port; unstable pre-v1. Fields
// may be added within a major version (§4).
type SumDBResult = fetchports.SumDBResult

// SumDBUnavailability discriminates why a checksum-database lookup produced
// no hashes.
//
// Stability: supporting type of the SumDBClient port; unstable pre-v1. Values
// may be added within a major version (§4).
type SumDBUnavailability = fetchports.SumDBUnavailability

// SymbolRef identifies a symbol in the index, returned by FindSymbol.
//
// Stability: supporting type of the InterfaceStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type SymbolRef = ifaceports.SymbolRef

// SynthesisedGoMod records that the tree an analysis read is NOT the tree
// that was published: the module zip shipped no go.mod, so kanonarion wrote
// one into the extraction directory before loading.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type SynthesisedGoMod = callgraphdomain.SynthesisedGoMod

// SynthesisedRequire is one require directive written into a synthesised
// go.mod: a module path at the exact version some walk resolved for it.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type SynthesisedRequire = callgraphdomain.SynthesisedRequire

// TestScope records whether a module's _test.go declarations were part of the
// analysis.
//
// Stability: supporting type of the CallGraphStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type TestScope = callgraphdomain.TestScope

// ToolchainVersion is a Go toolchain version in `go env GOVERSION` form
// ("go1.26.6").
//
// Stability: supporting type of the CallGraphStore, ConfigStore,
// InterfaceStore and VulnerabilityStore ports; unstable pre-v1. Values may be
// added within a major version (§4).
type ToolchainVersion = gotoolchain.Version

// UncoveredVendoredModule is one module of the vendored tree a document does
// not describe, with the reason it does not.
//
// Stability: supporting type of the VendorStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type UncoveredVendoredModule = vendordomain.UncoveredVendoredModule

// UnknownLicensePolicy governs how an *undetermined* license is treated for a
// scope.
//
// Stability: supporting type of the ConfigStore port; unstable pre-v1. Values
// may be added within a major version (§4).
type UnknownLicensePolicy = configdomain.UnknownLicensePolicy

// UnreadSource is the source files a binary's parser refused because they
// are newer than the Go it was compiled with.
//
// Stability: supporting type of the ExampleStore and InterfaceStore ports;
// unstable pre-v1. Fields may be added within a major version (§4).
type UnreadSource = gotoolchain.UnreadSource

// UnscanReason is a machine-readable cause code for why a module could not be
// fully scanned from source.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type UnscanReason = vulndomain.UnscanReason

// ValidationLeg names a check a measurement may perform, and LegProvenance
// says how a given record came by that check's result.
//
// Stability: supporting type of the FactStore and WalkStore ports; unstable
// pre-v1. Fields may be added within a major version (§4).
type ValidationLeg = fetchdomain.ValidationLeg

// ValidationLegKind enumerates the checks a fetch measurement can perform.
//
// Stability: supporting type of the FactStore and WalkStore ports; unstable
// pre-v1. Values may be added within a major version (§4).
type ValidationLegKind = fetchdomain.ValidationLegKind

// VendorFinding is one classified discrepancy with enough provenance for an
// agent to act: which module, which axis, and (for drift) both hashes.
//
// Stability: supporting type of the VendorStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type VendorFinding = vendordomain.Finding

// VendorFindingKind classifies a vendor reconciliation discrepancy.
//
// Stability: supporting type of the VendorStore port; unstable pre-v1. Values
// may be added within a major version (§4).
type VendorFindingKind = vendordomain.FindingKind

// VendorPolicy governs vendored-tree analysis: how vendor/ drift and
// vendor/modules.txt inconsistencies are treated, and whether the scan must
// run in airgapped vendor-only mode (no proxy contact).
//
// Stability: supporting type of the ConfigStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type VendorPolicy = configdomain.VendorPolicy

// VendorScope states what a document covers of the vendored tree it was made
// from: how many modules the tree holds, how many the document describes, and
// every module it does not, each with its reason.
//
// Stability: supporting type of the VendorStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type VendorScope = vendordomain.VendorScope

// VendoredModule is one module reconciled from the vendored tree.
//
// Stability: supporting type of the VendorStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type VendoredModule = vendordomain.VendoredModule

// VulnRooting names the analysis frame a vulnerability record was produced
// in.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type VulnRooting = vulndomain.Rooting

// VulnSeverity represents CVSS metrics as provided by the vulnerability
// database.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type VulnSeverity = vulndomain.Severity

// VulnerabilityFinding represents a single vulnerability affecting a module.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type VulnerabilityFinding = vulndomain.VulnerabilityFinding

// VulnerabilityRecordGeneration is one pipeline version the ledger holds
// records for a coordinate at, with what it holds there.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type VulnerabilityRecordGeneration = vulnports.VulnerabilityRecordGeneration

// VulnerabilityStatus describes the outcome of a module's vulnerability scan
// as a single word.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type VulnerabilityStatus = vulndomain.VulnerabilityStatus

// WalkBuildEnv is the Go build environment a project walk was resolved under.
//
// Stability: supporting type of the WalkStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type WalkBuildEnv = walkdomain.BuildEnv

// WalkDepth controls how much of the dependency graph a Walk resolves.
//
// Stability: supporting type of the WalkStore port; unstable pre-v1. Values
// may be added within a major version (§4).
type WalkDepth = walkdomain.WalkDepth

// WalkFilter constrains ListWalks results.
//
// Stability: supporting type of the WalkStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type WalkFilter = walkports.WalkFilter

// WalkGraph is the resolved transitive dependency closure for a target
// module.
//
// Stability: supporting type of the WalkStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type WalkGraph = walkdomain.Graph

// WalkScanCounts is the per-outcome module breakdown a walk scan produces.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Fields may be added within a major version (§4).
type WalkScanCounts = vulndomain.WalkScanCounts

// WalkScanStatus describes the outcome of a walk-wide vulnerability scan.
//
// Stability: supporting type of the VulnerabilityStore port; unstable pre-v1.
// Values may be added within a major version (§4).
type WalkScanStatus = vulndomain.WalkScanStatus

// WalkScope identifies which dependency set a walk records.
//
// Stability: supporting type of the WalkStore port; unstable pre-v1. Values
// may be added within a major version (§4).
type WalkScope = walkdomain.WalkScope

// WalkStatus summarises the overall outcome of a Walk operation.
//
// Stability: supporting type of the WalkStore port; unstable pre-v1. Values
// may be added within a major version (§4).
type WalkStatus = walkdomain.WalkStatus

// WalkStoredError is a serialisation-stable error representation.
//
// Stability: supporting type of the WalkStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type WalkStoredError = walkdomain.StoredError

// WalkSummary is a lightweight projection of a WalkRecord for list views.
//
// Stability: supporting type of the WalkStore port; unstable pre-v1. Fields
// may be added within a major version (§4).
type WalkSummary = walkports.WalkSummary
