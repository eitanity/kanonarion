package kanonarion

import (
	"fmt"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	"github.com/eitanity/kanonarion/internal/composition"
	dirapp "github.com/eitanity/kanonarion/internal/directive/application"
	exapp "github.com/eitanity/kanonarion/internal/example/application"
	extractapp "github.com/eitanity/kanonarion/internal/extract/application"
	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
	fipsapp "github.com/eitanity/kanonarion/internal/fips/application"
	gdapp "github.com/eitanity/kanonarion/internal/godebug/application"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	sbomapp "github.com/eitanity/kanonarion/internal/sbom/application"
	venapp "github.com/eitanity/kanonarion/internal/vendortree/application"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
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
// including caller/callee traversal.
//
// Stability: query use case (called by consumers); unstable pre-v1. May gain
// methods within a major version (§4).
type QueryCallGraphUseCase = cgapp.QueryCallGraphUseCase

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
// at storeRoot (the directory holding mirror.db and blobs; the standard default
// is ~/.kanonarion). It opens the store with the binary's full migration set,
// wires the read-side adapters through the DI composition root, and returns the
// constructed Queries together with a cleanup function that closes the store.
// Callers MUST invoke cleanup when finished.
//
// This is the only supported way for an external consumer to obtain the Query
// use cases; it constructs them without exposing internal/cli (§2.2).
//
// Stability: public composition entrypoint; unstable pre-v1. It may gain
// optional configuration via a variadic option within a major version
// (§4).
func Open(storeRoot string) (*Queries, func() error, error) {
	queries, cleanup, err := composition.NewQueries(storeRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("opening kanonarion store: %w", err)
	}
	return queries, cleanup, nil
}
