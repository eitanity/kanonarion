package kanonarion

import (
	"fmt"

	cgapp "code.eitanity.com/kanonarion/internal/callgraph/application"
	callgraphdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	callgraphports "code.eitanity.com/kanonarion/internal/callgraph/ports"
	"code.eitanity.com/kanonarion/internal/composition"
	dirapp "code.eitanity.com/kanonarion/internal/directive/application"
	exapp "code.eitanity.com/kanonarion/internal/example/application"
	extractapp "code.eitanity.com/kanonarion/internal/extract/application"
	fetchapp "code.eitanity.com/kanonarion/internal/fetch/application"
	fipsapp "code.eitanity.com/kanonarion/internal/fips/application"
	gdapp "code.eitanity.com/kanonarion/internal/godebug/application"
	ifaceapp "code.eitanity.com/kanonarion/internal/iface/application"
	licapp "code.eitanity.com/kanonarion/internal/license/application"
	sbomapp "code.eitanity.com/kanonarion/internal/sbom/application"
	venapp "code.eitanity.com/kanonarion/internal/vendortree/application"
	vulnapp "code.eitanity.com/kanonarion/internal/vuln/application"
	walkapp "code.eitanity.com/kanonarion/internal/walk/application"
)

// Query use cases (called by consumers). Each is a TYPE ALIAS to the internal
// read-only use case (§2.2). They are the read-consumption surface;
// the write/extraction use cases (Fetch*, ExecuteWalk*, Extract*, Scan*,
// Generate*) are deliberately NOT exported, so the pipeline-orchestration shape
// stays free to change. Per §4 a use case may gain a method (or an
// optional argument-struct field) within a major version; removing or changing
// a signature is breaking.
//
// Construct them through Open, which builds the read surface via the neutral DI
// composition root — consumers never reach into internal/cli.

// QueryFetchUseCase is the read-only access to stored FactRecords.
//
// Stability: query use case (called by consumers); unstable pre-v1. May gain
// methods within a major version (§4).
type QueryFetchUseCase = fetchapp.QueryFetchUseCase

// QueryWalksUseCase is the read-only access to stored WalkRecords.
//
// Stability: query use case (called by consumers); unstable pre-v1. May gain
// methods within a major version (§4).
type QueryWalksUseCase = walkapp.QueryWalksUseCase

// QueryLicenseUseCase is the read-only access to stored LicenseRecords,
// including closure-aware resolution across a walk.
//
// Stability: query use case (called by consumers); unstable pre-v1. May gain
// methods within a major version (§4).
type QueryLicenseUseCase = licapp.QueryLicenseUseCase

// QueryInterfaceUseCase is the read-only access to stored InterfaceRecords.
//
// Stability: query use case (called by consumers); unstable pre-v1. May gain
// methods within a major version (§4).
type QueryInterfaceUseCase = ifaceapp.QueryInterfaceUseCase

// QueryCallGraphUseCase is the read-only access to stored CallGraphRecords,
// including caller/callee traversal and implementers. A method given an empty
// pipeline version reads CallGraphPipelineVersion.
//
// Stability: query use case (called by consumers); unstable pre-v1. May gain
// methods within a major version.
type QueryCallGraphUseCase = cgapp.QueryCallGraphUseCase

// CallGraphPipelineVersion is the call-graph pipeline this build writes and
// serves: the pipeline version QueryCallGraphUseCase's methods read at.
//
// Stability: supporting constant of QueryCallGraphUseCase; unstable pre-v1.
// It changes when the call-graph pipeline does.
const CallGraphPipelineVersion = cgapp.PipelineVersion

// The pipelines this build writes and serves for the other record types: the
// pipeline version each query use case's methods read at, and read when given
// an empty one.
//
// Stability: supporting constants of the query use cases; unstable pre-v1.
// Each changes when its pipeline does.
const (
	// FetchPipelineVersion is what QueryFetchUseCase.GetFetchRecord reads at.
	FetchPipelineVersion = fetchapp.PipelineVersion
	// LicensePipelineVersion is what QueryLicenseUseCase reads at.
	LicensePipelineVersion = licapp.PipelineVersion
	// InterfacePipelineVersion is what QueryInterfaceUseCase reads at.
	InterfacePipelineVersion = ifaceapp.PipelineVersion
	// ExamplePipelineVersion is what QueryExamplesUseCase reads at.
	ExamplePipelineVersion = exapp.PipelineVersion
	// VulnPipelineVersion is what QueryVulnUseCase reads at.
	VulnPipelineVersion = vulnapp.PipelineVersion
)

// TraversalRequest is the input to TraverseCallers and TraverseCallees: the
// symbol to start from, the depth to follow (0 follows to the closure), the
// module versions in scope, edge options and an optional progress reporter.
//
// Stability: request struct (passed by consumers); unstable pre-v1. Fields may
// be added within a major version.
type TraversalRequest = cgapp.TraversalRequest

// TraversalResult is a transitive traversal's edges and nodes, whether it
// stopped at its depth with symbols still to follow, and the coordinates it
// could not search.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major version.
type TraversalResult = cgapp.TraversalResult

// TraversalProgressReporter is told, on an interval, the depth a traversal has
// reached and how many symbols it has visited.
//
// Stability: substitution port (implemented by consumers); unstable pre-v1.
type TraversalProgressReporter = callgraphports.TraversalProgressReporter

// ImplementersRequest is the input to Implementers: the interface,
// "pkg/path.Name", or one of its methods, "pkg/path.(Name).Method", with the
// module versions in scope and edge options.
//
// Stability: request struct (passed by consumers); unstable pre-v1. Fields may
// be added within a major version.
type ImplementersRequest = cgapp.ImplementersRequest

// ImplementersResult is the output of Implementers: the concrete types of the
// interface's own module that satisfy it, the answer's verdict and the
// coordinates it could not search.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major version.
type ImplementersResult = cgapp.ImplementersResult

// Implementer is one concrete type in an ImplementersResult.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major version.
type Implementer = cgapp.Implementer

// CallGraphAnswer is the verdict on a call-graph answer: RESOLVED-PRESENT,
// RESOLVED-ABSENT (a measured absence), or UNRESOLVED with the soundness sinks
// that leave room for a missing result. Reason says why in one sentence.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major version.
type CallGraphAnswer = callgraphdomain.Answer

// AnswerOutcome is the outcome of a CallGraphAnswer.
//
// Stability: result enumeration (compared by consumers); unstable pre-v1.
// Values may be added within a major version.
type AnswerOutcome = callgraphdomain.AnswerOutcome

// SoundnessSink is one reason a CallGraphAnswer is UNRESOLVED: what kind, the
// symbol it applies to, and a detail sentence.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major version.
type SoundnessSink = callgraphdomain.SoundnessSink

// SinkKind is the kind of a SoundnessSink.
//
// Stability: result enumeration (compared by consumers); unstable pre-v1.
// Values may be added within a major version.
type SinkKind = callgraphdomain.SinkKind

// InterfaceNotDeclaredError is Implementers' refusal when no served call graph
// declares the interface.
//
// Stability: error type (returned to consumers); unstable pre-v1. Fields may
// be added within a major version.
type InterfaceNotDeclaredError = cgapp.InterfaceNotDeclaredError

// SupersededModuleError is Implementers' refusal when the interface's module
// has call graphs only at a superseded pipeline version.
//
// Stability: error type (returned to consumers); unstable pre-v1. Fields may
// be added within a major version.
type SupersededModuleError = cgapp.SupersededModuleError

// CallGraphComposeRequest restricts GetCallGraphRecordFrom to the generations
// of one analysis source, toolchain or worktree.
//
// Stability: request struct (passed by consumers); unstable pre-v1. Fields may
// be added within a major version.
type CallGraphComposeRequest = callgraphdomain.ComposeRequest

// CallGraphCoordinate is one analysed module version and pipeline version, as
// ListCallGraphCoordinates lists them.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major version.
type CallGraphCoordinate = callgraphports.CallGraphCoordinate

// CallGraphGeneration is one stored call-graph generation of a
// CallGraphCoordinate.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major version.
type CallGraphGeneration = callgraphports.CallGraphGeneration

// UnservedCoordinate is a module version holding call graphs only at
// superseded pipeline versions, so a query could not read it.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major version.
type UnservedCoordinate = callgraphports.UnservedCoordinate

// WorktreeRouting is which working tree answered for a local coordinate, and
// how many the store holds for it.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major version.
type WorktreeRouting = callgraphports.WorktreeRouting

// QueryExamplesUseCase is the read-only access to stored ExampleRecords.
//
// Stability: query use case (called by consumers); unstable pre-v1. May gain
// methods within a major version (§4).
type QueryExamplesUseCase = exapp.QueryExamplesUseCase

// QueryExtractionUseCase is the read-only access to stored ExtractionRuns.
//
// Stability: query use case (called by consumers); unstable pre-v1. May gain
// methods within a major version (§4).
type QueryExtractionUseCase = extractapp.QueryExtractionUseCase

// QueryVulnUseCase is the read-only access to stored VulnerabilityRecords.
//
// Stability: query use case (called by consumers); unstable pre-v1. May gain
// methods within a major version (§4).
type QueryVulnUseCase = vulnapp.QueryVulnUseCase

// QueryScanRunsUseCase is the read-only access to stored WalkScanRuns.
//
// Stability: query use case (called by consumers); unstable pre-v1. May gain
// methods within a major version (§4).
type QueryScanRunsUseCase = vulnapp.QueryScanRunsUseCase

// QuerySBOMUseCase is the read-only access to stored SBOMRecords.
//
// Stability: query use case (called by consumers); unstable pre-v1. May gain
// methods within a major version (§4).
type QuerySBOMUseCase = sbomapp.QuerySBOMUseCase

// QueryDirectivesUseCase is the read-only access to stored DirectiveRecords,
// including per-project scan history.
//
// Stability: query use case (called by consumers); unstable pre-v1. May gain
// methods within a major version (§4).
type QueryDirectivesUseCase = dirapp.QueryDirectivesUseCase

// QueryGoDebugUseCase is the read-only access to stored GoDebugRecords.
//
// Stability: query use case (called by consumers); unstable pre-v1. May gain
// methods within a major version (§4).
type QueryGoDebugUseCase = gdapp.QueryGoDebugUseCase

// QueryVendorUseCase is the read-only access to stored VendorRecords.
//
// Stability: query use case (called by consumers); unstable pre-v1. May gain
// methods within a major version (§4).
type QueryVendorUseCase = venapp.QueryVendorUseCase

// QueryFIPSUseCase is the read-only access to stored FIPSRecords.
//
// Stability: query use case (called by consumers); unstable pre-v1. May gain
// methods within a major version (§4).
type QueryFIPSUseCase = fipsapp.QueryFIPSUseCase

// Queries is the read-only consumption surface: a pointer to every Query* use
// case, constructed together against one store handle. Its fields carry the
// alias types above, so a consumer holds *kanonarion.QueryFetchUseCase and the
// rest.
//
// Stability: result of the public composition entrypoint; unstable pre-v1.
// Fields may be added within a major version (§4).
type Queries = composition.Queries

// Open builds the read-consumption surface against the kanonarion store rooted
// at storeRoot (the standard default is ~/.kanonarion). The storage.backend
// value of <storeRoot>/config.yaml selects the backend among those registered
// with RegisterBackend. With nothing registered, or no config.yaml, the SQLite
// backend (mirror.db and blobs under storeRoot) is the implicit default. It
// opens the store, wires the read-side adapters through the DI composition root, and returns the
// constructed Queries together with a cleanup function that closes the store.
// Callers MUST invoke cleanup when finished.
//
// This is the only supported way for an external consumer to obtain the Query
// use cases; it constructs them without exposing internal/cli (§2.2).
//
// Stability: public composition entrypoint; unstable pre-v1. It may gain
// optional configuration via a variadic option within a major version
// (§4).
func Open(storeRoot string, opts ...Option) (*Queries, func() error, error) {
	queries, cleanup, err := composition.NewQueries(storeRoot, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("opening kanonarion store: %w", err)
	}
	return queries, cleanup, nil
}
