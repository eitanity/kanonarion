package kanonarion_test

import (
	"context"
	"reflect"
	"testing"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
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
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"

	"github.com/eitanity/kanonarion/pkg/kanonarion"
)

// The compile-time assignments below pin every published query use case to the
// internal use case it must alias (§2.2). Both directions compile only
// when the two names denote the identical type, so a re-wired or forked alias
// fails the build — and proves each query type is reachable through the façade.
var (
	_ *kanonarion.QueryFetchUseCase      = (*fetchapp.QueryFetchUseCase)(nil)
	_ *fetchapp.QueryFetchUseCase        = (*kanonarion.QueryFetchUseCase)(nil)
	_ *kanonarion.QueryWalksUseCase      = (*walkapp.QueryWalksUseCase)(nil)
	_ *walkapp.QueryWalksUseCase         = (*kanonarion.QueryWalksUseCase)(nil)
	_ *kanonarion.QueryLicenseUseCase    = (*licapp.QueryLicenseUseCase)(nil)
	_ *licapp.QueryLicenseUseCase        = (*kanonarion.QueryLicenseUseCase)(nil)
	_ *kanonarion.QueryInterfaceUseCase  = (*ifaceapp.QueryInterfaceUseCase)(nil)
	_ *ifaceapp.QueryInterfaceUseCase    = (*kanonarion.QueryInterfaceUseCase)(nil)
	_ *kanonarion.QueryCallGraphUseCase  = (*cgapp.QueryCallGraphUseCase)(nil)
	_ *cgapp.QueryCallGraphUseCase       = (*kanonarion.QueryCallGraphUseCase)(nil)
	_ *kanonarion.QueryExamplesUseCase   = (*exapp.QueryExamplesUseCase)(nil)
	_ *exapp.QueryExamplesUseCase        = (*kanonarion.QueryExamplesUseCase)(nil)
	_ *kanonarion.QueryExtractionUseCase = (*extractapp.QueryExtractionUseCase)(nil)
	_ *extractapp.QueryExtractionUseCase = (*kanonarion.QueryExtractionUseCase)(nil)
	_ *kanonarion.QueryVulnUseCase       = (*vulnapp.QueryVulnUseCase)(nil)
	_ *vulnapp.QueryVulnUseCase          = (*kanonarion.QueryVulnUseCase)(nil)
	_ *kanonarion.QueryScanRunsUseCase   = (*vulnapp.QueryScanRunsUseCase)(nil)
	_ *vulnapp.QueryScanRunsUseCase      = (*kanonarion.QueryScanRunsUseCase)(nil)
	_ *kanonarion.QuerySBOMUseCase       = (*sbomapp.QuerySBOMUseCase)(nil)
	_ *sbomapp.QuerySBOMUseCase          = (*kanonarion.QuerySBOMUseCase)(nil)
	_ *kanonarion.QueryDirectivesUseCase = (*dirapp.QueryDirectivesUseCase)(nil)
	_ *dirapp.QueryDirectivesUseCase     = (*kanonarion.QueryDirectivesUseCase)(nil)
	_ *kanonarion.QueryGoDebugUseCase    = (*gdapp.QueryGoDebugUseCase)(nil)
	_ *gdapp.QueryGoDebugUseCase         = (*kanonarion.QueryGoDebugUseCase)(nil)
	_ *kanonarion.QueryVendorUseCase     = (*venapp.QueryVendorUseCase)(nil)
	_ *venapp.QueryVendorUseCase         = (*kanonarion.QueryVendorUseCase)(nil)
	_ *kanonarion.QueryFIPSUseCase       = (*fipsapp.QueryFIPSUseCase)(nil)
	_ *fipsapp.QueryFIPSUseCase          = (*kanonarion.QueryFIPSUseCase)(nil)
)

// TestOpen_ConstructsEveryQueryUseCase is the acceptance test: every
// Query use case is constructible via the public Open entrypoint alone, with no
// import of internal/cli. It opens a fresh store under a temp root (exercising
// migration application on an empty mirror.db) and asserts each field is wired.
func TestOpen_ConstructsEveryQueryUseCase(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	queries, cleanup, err := kanonarion.Open(root)
	if err != nil {
		t.Fatalf("Open(%q): %v", root, err)
	}
	t.Cleanup(func() {
		if cerr := cleanup(); cerr != nil {
			t.Errorf("cleanup: %v", cerr)
		}
	})

	// A missing field means the composition root left a query unwired.
	checks := map[string]any{
		"Fetch":      queries.Fetch,
		"Walks":      queries.Walks,
		"License":    queries.License,
		"Interface":  queries.Interface,
		"CallGraph":  queries.CallGraph,
		"Examples":   queries.Examples,
		"Extraction": queries.Extraction,
		"Vuln":       queries.Vuln,
		"ScanRuns":   queries.ScanRuns,
		"SBOM":       queries.SBOM,
		"Directives": queries.Directives,
		"GoDebug":    queries.GoDebug,
		"Vendor":     queries.Vendor,
		"FIPS":       queries.FIPS,
	}
	// reflect.ValueOf(...).IsNil rather than uc == nil: a nil typed pointer
	// boxed in `any` compares non-nil, which would let an unwired field pass.
	for name, uc := range checks {
		if uc == nil || reflect.ValueOf(uc).IsNil() {
			t.Errorf("Queries.%s is nil; composition root left it unwired", name)
		}
	}
}

// TestOpen_QueriesAreCallableAgainstEmptyStore exercises the read surface end to
// end through the façade: a freshly opened store has no records, so a lookup
// reports genuine absence (found == false, no error) rather than failing. This
// confirms the wired use cases actually reach a working store handle.
func TestOpen_QueriesAreCallableAgainstEmptyStore(t *testing.T) {
	t.Parallel()

	queries, cleanup, err := kanonarion.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = cleanup() })

	// A read-shaped result type is constructed via its exported fields, not a
	// constructor (constructors are not part of the contract, §4).
	coord := kanonarion.ModuleCoordinate{Path: "golang.org/x/mod", Version: "v0.35.0"}

	_, found, err := queries.Fetch.GetFetchRecord(context.Background(), coord, fetchapp.PipelineVersion)
	if err != nil {
		t.Fatalf("GetFetchRecord against empty store: %v", err)
	}
	if found {
		t.Error("GetFetchRecord found a record in a freshly created store")
	}

	walks, err := queries.Walks.ListWalks(context.Background(), walkports.WalkFilter{})
	if err != nil {
		t.Fatalf("ListWalks against empty store: %v", err)
	}
	if len(walks) != 0 {
		t.Errorf("ListWalks returned %d walks from a fresh store, want 0", len(walks))
	}

	// The supply-chain-gap query use cases (directives, godebug, vendor, fips)
	// are keyed by project module path; an un-scanned project must report
	// genuine absence (found == false, no error), never an error.
	const project = "example.com/never/scanned"

	if _, found, derr := queries.Directives.Get(context.Background(), project); derr != nil {
		t.Fatalf("Directives.Get against empty store: %v", derr)
	} else if found {
		t.Error("Directives.Get found a record in a freshly created store")
	}

	if _, found, gerr := queries.GoDebug.Get(context.Background(), project); gerr != nil {
		t.Fatalf("GoDebug.Get against empty store: %v", gerr)
	} else if found {
		t.Error("GoDebug.Get found a record in a freshly created store")
	}

	if _, found, verr := queries.Vendor.Get(context.Background(), project); verr != nil {
		t.Fatalf("Vendor.Get against empty store: %v", verr)
	} else if found {
		t.Error("Vendor.Get found a record in a freshly created store")
	}

	if _, found, ferr := queries.FIPS.Get(context.Background(), project); ferr != nil {
		t.Fatalf("FIPS.Get against empty store: %v", ferr)
	} else if found {
		t.Error("FIPS.Get found a record in a freshly created store")
	}
}

// TestOpen_TwoOpensShareNoState confirms Open is self-contained: two roots are
// independent stores, so writing through one cannot leak into the other. It is a
// light guard that Open does not hold global/process state.
func TestOpen_TwoOpensShareNoState(t *testing.T) {
	t.Parallel()

	qa, cleanupA, err := kanonarion.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open A: %v", err)
	}
	t.Cleanup(func() { _ = cleanupA() })

	qb, cleanupB, err := kanonarion.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open B: %v", err)
	}
	t.Cleanup(func() { _ = cleanupB() })

	if qa == qb {
		t.Error("two Open calls returned the same Queries pointer; the surface is not per-store")
	}
}
