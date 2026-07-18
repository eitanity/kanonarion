// Package composition is the neutral composition root shared by the CLI and the
// public façade (pkg/kanonarion). It owns the migration set that defines the
// store schema and constructs the read-only query use cases from a store root,
// so the public API can build the read-consumption surface
// without importing internal/cli — the CLI layer must stay private.
package composition

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
	"github.com/eitanity/kanonarion/internal/adapters/clock"
	fetchsqlite "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	fetchproxy "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	noopsigner "github.com/eitanity/kanonarion/internal/adapters/signer/noop"
	fetchsumdb "github.com/eitanity/kanonarion/internal/adapters/sumdb/gosum"
	fetchvcs "github.com/eitanity/kanonarion/internal/adapters/vcs/gitexec"
	cgsqlite "github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	dirsqlite "github.com/eitanity/kanonarion/internal/directive/adapters/store/sqlite"
	dirapp "github.com/eitanity/kanonarion/internal/directive/application"
	"github.com/eitanity/kanonarion/internal/driver"
	exgoast "github.com/eitanity/kanonarion/internal/example/adapters/parser/goast"
	exsqlite "github.com/eitanity/kanonarion/internal/example/adapters/store/sqlite"
	exapp "github.com/eitanity/kanonarion/internal/example/application"
	extextractor "github.com/eitanity/kanonarion/internal/extract/adapters/extractor/local"
	extstages "github.com/eitanity/kanonarion/internal/extract/adapters/stages/local"
	extstore "github.com/eitanity/kanonarion/internal/extract/adapters/store/sqlite"
	extractapp "github.com/eitanity/kanonarion/internal/extract/application"
	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	fipssqlite "github.com/eitanity/kanonarion/internal/fips/adapters/store/sqlite"
	fipsapp "github.com/eitanity/kanonarion/internal/fips/application"
	gdsqlite "github.com/eitanity/kanonarion/internal/godebug/adapters/store/sqlite"
	gdapp "github.com/eitanity/kanonarion/internal/godebug/application"
	ifaceext "github.com/eitanity/kanonarion/internal/iface/adapters/extractor/godoc"
	ifacesqlite "github.com/eitanity/kanonarion/internal/iface/adapters/store/sqlite"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	licdet "github.com/eitanity/kanonarion/internal/license/adapters/detector/licensecheck"
	licsqlite "github.com/eitanity/kanonarion/internal/license/adapters/store/sqlite"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	sbomstore "github.com/eitanity/kanonarion/internal/sbom/adapters/store/sqlite"
	sbomapp "github.com/eitanity/kanonarion/internal/sbom/application"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
	stdlibgodev "github.com/eitanity/kanonarion/internal/stdlib/adapters/godev"
	stdlibgit "github.com/eitanity/kanonarion/internal/stdlib/adapters/gitlsremote"
	stdliblic "github.com/eitanity/kanonarion/internal/stdlib/adapters/licenseident"
	stdliblocalsrc "github.com/eitanity/kanonarion/internal/stdlib/adapters/localsource"
	stdlibsqlite "github.com/eitanity/kanonarion/internal/stdlib/adapters/store/sqlite"
	stdlibtoolchain "github.com/eitanity/kanonarion/internal/stdlib/adapters/toolchainenv"
	stdlibbridge "github.com/eitanity/kanonarion/internal/stdlib/adapters/walkbridge"
	stdlibapp "github.com/eitanity/kanonarion/internal/stdlib/application"
	vensqlite "github.com/eitanity/kanonarion/internal/vendortree/adapters/store/sqlite"
	venapp "github.com/eitanity/kanonarion/internal/vendortree/application"
	vulnsqlite "github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	walkbuildlist "github.com/eitanity/kanonarion/internal/walk/adapters/buildlist/gotoolchain"
	walkfetcher "github.com/eitanity/kanonarion/internal/walk/adapters/fetcher/local"
	walkgomod "github.com/eitanity/kanonarion/internal/walk/adapters/gomod/xmod"
	walklocalfs "github.com/eitanity/kanonarion/internal/walk/adapters/localfs"
	walksqlite "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
)

// Migrations returns every migration the binary knows about, in apply order.
// Its length is the binary's expected schema version, so the CLI and the public
// façade open mirror.db against an identical schema.
func Migrations() []sqlitestore.Migration {
	var m []sqlitestore.Migration
	m = append(m, fetchsqlite.Migrations()...)
	m = append(m, walksqlite.Migrations()...)
	m = append(m, extstore.Migrations()...)
	m = append(m, licsqlite.Migrations()...)
	m = append(m, ifacesqlite.Migrations()...)
	m = append(m, cgsqlite.Migrations()...)
	m = append(m, exsqlite.Migrations()...)
	m = append(m, sbomstore.Migrations()...)
	m = append(m, vulnsqlite.Migrations()...)
	m = append(m, dirsqlite.Migrations()...)
	m = append(m, gdsqlite.Migrations()...)
	m = append(m, vensqlite.Migrations()...)
	m = append(m, fipssqlite.Migrations()...)
	m = append(m, stdlibsqlite.Migrations()...)
	return m
}

// NewStdlibAcquirer wires the standard-library chain-of-custody acquirer over
// the shared DB and blob store: the go.dev/dl manifest+tarball client, the
// googlesource commit resolver, the licence detector, and the version-keyed
// fact cache. It is returned as a walk StdlibAcquirer via the bridge so the
// resolver depends only on the narrow port. Both composition roots (the driver
// here and the CLI container) share it so stdlib custody behaves identically.
func NewStdlibAcquirer(db sqlitestore.DB, blobs fetchports.BlobStore, clk fetchports.Clock, logger *slog.Logger) *stdlibbridge.Bridge {
	godev := stdlibgodev.New()
	acquirer := stdlibapp.NewAcquirer(
		godev, godev,
		stdlibgit.New(),
		stdliblic.New(licdet.New()),
		stdlibsqlite.New(db),
		blobs, clk, logger,
	)
	return stdlibbridge.New(acquirer)
}

// NewOfflineStdlibAcquirer wires the offline standard-library chain-of-custody
// acquirer used in --from-modcache runs. It anchors to the local toolchain
// instead of go.dev/dl: the `go env GOROOT GOVERSION` inspector locates the
// toolchain, the local source reader exposes $GOROOT/src and $GOROOT/LICENSE, and
// the same licence detector and version-keyed fact cache the online path uses
// classify and persist the result. No network client is wired — the offline path
// performs no I/O beyond the local filesystem. goBinary may be empty (PATH "go").
func NewOfflineStdlibAcquirer(db sqlitestore.DB, goBinary string, clk fetchports.Clock, logger *slog.Logger) *stdlibbridge.Bridge {
	acquirer := stdlibapp.NewLocalAcquirer(
		stdlibtoolchain.New(goBinary, logger),
		stdliblocalsrc.New(),
		stdliblic.New(licdet.New()),
		stdlibsqlite.New(db),
		clk, logger,
	)
	return stdlibbridge.New(acquirer)
}

// Queries is the read-only consumption surface: every Query* use case the public
// façade exposes. Write/extraction use cases are deliberately
// absent — the pipeline orchestration shape stays free to change and is driven
// through the CLI composition root, not this read surface.
type Queries struct {
	Fetch      *fetchapp.QueryFetchUseCase
	Walks      *walkapp.QueryWalksUseCase
	License    *licapp.QueryLicenseUseCase
	Interface  *ifaceapp.QueryInterfaceUseCase
	CallGraph  *cgapp.QueryCallGraphUseCase
	Examples   *exapp.QueryExamplesUseCase
	Extraction *extractapp.QueryExtractionUseCase
	Vuln       *vulnapp.QueryVulnUseCase
	ScanRuns   *vulnapp.QueryScanRunsUseCase
	SBOM       *sbomapp.QuerySBOMUseCase
	Directives *dirapp.QueryDirectivesUseCase
	GoDebug    *gdapp.QueryGoDebugUseCase
	Vendor     *venapp.QueryVendorUseCase
	FIPS       *fipsapp.QueryFIPSUseCase
}

// NewQueries opens mirror.db under storeRoot with all migrations applied, wires
// the read-side store adapters, and constructs every Query* use case. It returns
// the populated Queries together with a cleanup function that closes the DB.
//
// The store root is created if absent. Only read stores are wired — no proxy,
// VCS, extractor, or signer — so the read surface stays independent of the
// pipeline-construction machinery.
func NewQueries(storeRoot string) (*Queries, func() error, error) {
	if err := os.MkdirAll(storeRoot, 0o750); err != nil {
		return nil, nil, fmt.Errorf("creating store root %s: %w", storeRoot, err)
	}

	dbPath := filepath.Join(storeRoot, "mirror.db")
	db, err := sqlitestore.Open(dbPath, Migrations())
	if err != nil {
		return nil, nil, fmt.Errorf("opening database: %w", err)
	}
	cleanup := func() error {
		if cerr := db.Close(); cerr != nil {
			return fmt.Errorf("closing database: %w", cerr)
		}
		return nil
	}

	walkStore := walksqlite.New(db)
	licStore := licsqlite.New(db)

	q := &Queries{
		Fetch:      fetchapp.NewQueryFetchUseCase(fetchsqlite.New(db)),
		Walks:      walkapp.NewQueryWalksUseCase(walkStore),
		License:    licapp.NewQueryLicenseUseCaseWithWalks(licStore, walkStore),
		Interface:  ifaceapp.NewQueryInterfaceUseCase(ifacesqlite.New(db)),
		CallGraph:  cgapp.NewQueryCallGraphUseCase(cgsqlite.New(db)),
		Examples:   exapp.NewQueryExamplesUseCase(exsqlite.New(db)),
		Extraction: extractapp.NewQueryExtractionUseCase(extstore.New(db)),
		Vuln:       vulnapp.NewQueryVulnUseCase(vulnsqlite.New(db)),
		ScanRuns:   vulnapp.NewQueryScanRunsUseCase(vulnsqlite.New(db)),
		SBOM:       sbomapp.NewQuerySBOMUseCase(sbomstore.New(db)),
		Directives: dirapp.NewQueryDirectivesUseCase(dirsqlite.New(db)),
		GoDebug:    gdapp.NewQueryGoDebugUseCase(gdsqlite.New(db)),
		Vendor:     venapp.NewQueryVendorUseCase(vensqlite.New(db)),
		FIPS:       fipsapp.NewQueryFIPSUseCase(fipssqlite.New(db)),
	}
	return q, cleanup, nil
}

// Driver is the write/serving surface. It holds the individually
// exported write use cases — the verified single-coordinate fetch/serve driver
// that powers a gating module proxy, the local walk→extract driver, and the
// validate-and-ingest boundary. The bulk extraction pipeline is deliberately
// absent: it stays behind the CLI composition root so its orchestration shape is
// free to change. Further drivers join this struct as additional fields.
type Driver struct {
	// FetchServe resolves a single ModuleCoordinate, fetching and verifying on a
	// miss, and returns a BlobHandle for serving.
	FetchServe *fetchapp.ServeModuleUseCase
	// LocalWalkExtract runs a project-rooted walk over a local working tree and
	// its extraction stages, returning the records. Powers the local-walking
	// gRPC client (source never leaves the machine).
	LocalWalkExtract *driver.LocalWalkExtractUseCase
	// ValidateIngest is the verified-fact boundary: it validates imported records
	// against the same invariants extracted ones satisfy before persisting them
	// (Ingest), and re-verifies records fail-closed on read (ReadVerified). Powers
	// the consume side of the airgap bundle.
	ValidateIngest *fetchapp.ValidateAndIngestUseCase
}

// NewDriver opens mirror.db under storeRoot with all migrations applied, wires
// the fetch pipeline (proxy, VCS, sumdb, blob store, fact store) with the OSS
// no-op signer, and constructs the verified fetch/serve driver. It returns the
// populated Driver together with a cleanup function that closes the DB. The
// caller MUST invoke cleanup when finished.
//
// The store root is created if absent. The proxy resolves $GOPROXY (or
// proxy.golang.org); the verification path is identical to the CLI fetch — this
// surface only re-shapes the result, never the integrity checks. Diagnostics
// are discarded: a serving consumer drives its own logging around the call.
func NewDriver(storeRoot string) (*Driver, func() error, error) {
	if err := os.MkdirAll(storeRoot, 0o750); err != nil {
		return nil, nil, fmt.Errorf("creating store root %s: %w", storeRoot, err)
	}

	dbPath := filepath.Join(storeRoot, "mirror.db")
	db, err := sqlitestore.Open(dbPath, Migrations())
	if err != nil {
		return nil, nil, fmt.Errorf("opening database: %w", err)
	}
	cleanup := func() error {
		if cerr := db.Close(); cerr != nil {
			return fmt.Errorf("closing database: %w", cerr)
		}
		return nil
	}

	factStore, err := fetchsqlite.NewAuditingStore(fetchsqlite.New(db), filepath.Join(storeRoot, "audit.jsonl"))
	if err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("creating auditing fetch store: %w", err)
	}

	proxy, err := fetchproxy.New("", false)
	if err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("creating proxy adapter: %w", err)
	}

	blobs := localfs.New(storeRoot)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	clk := clock.System{}
	stopwatch := clock.Monotonic{}
	fetchUC := fetchapp.NewFetchModuleUseCase(
		proxy, fetchvcs.New(), blobs, factStore,
		fetchsumdb.New(filepath.Join(storeRoot, "sumdb")),
		clk, stopwatch, "", logger,
	).WithSigner(noopsigner.New(), factStore)

	kanonarionBinary, err := os.Executable()
	if err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("resolving executable path for callgraph subprocess: %w", err)
	}

	d := &Driver{
		FetchServe:       fetchapp.NewServeModuleUseCase(fetchUC, blobs).WithAudit(factStore),
		LocalWalkExtract: newLocalWalkExtract(db, blobs, factStore, fetchUC, clk, stopwatch, logger, kanonarionBinary),
		ValidateIngest:   fetchapp.NewValidateAndIngestUseCase(factStore).WithAudit(factStore),
	}
	return d, cleanup, nil
}

// stagePipelineVersion is the per-stage extraction pipeline version the driver
// wires, matching the CLI composition root. It is a constant rather than a
// config knob: the driver runs the same built-in stages the CLI does.
const stagePipelineVersion = "0.1.0"

// newLocalWalkExtract wires the project-walk and extraction pipelines over the
// shared DB and fetch infrastructure, then constructs the local walk→extract
// driver. Full git/sumdb verification is on (the fetcher does not skip VCS); the
// driver runs the full built-in stage set by default.
func newLocalWalkExtract(
	db sqlitestore.DB,
	blobs *localfs.Store,
	factStore *fetchsqlite.AuditingStore,
	fetchUC *fetchapp.FetchModuleUseCase,
	clk clock.System,
	stopwatch clock.Monotonic,
	logger *slog.Logger,
	kanonarionBinary string,
) *driver.LocalWalkExtractUseCase {
	walkStore := walksqlite.New(db)
	extStore := extstore.New(db)
	licStore := licsqlite.New(db)
	ifaceStore := ifacesqlite.New(db)
	cgStore := cgsqlite.New(db)
	exStore := exsqlite.New(db)

	// ---- project-walk pipeline ----
	fetcher := walkfetcher.New(fetchUC, false)
	localFetcher := walklocalfs.New(blobs, factStore, clk)
	resolver := walkapp.NewGraphResolver(walkgomod.New(), fetcher, blobs, clk, "", logger).
		WithBuildListResolver(walkbuildlist.New("", logger)).
		WithStdlibAcquirer(NewStdlibAcquirer(db, blobs, clk, logger), false)
	walker := walkapp.NewWalker(resolver, fetcher, localFetcher, clk, stopwatch, 0, logger)
	executeWalkUC := walkapp.NewExecuteWalkUseCase(walker, walkStore, "", "", logger)

	// ---- extraction pipeline (full built-in stage set) ----
	licExtractUC := licapp.NewExtractLicenseUseCase(licapp.Config{
		Facts: factStore, Blobs: blobs, Licenses: licStore,
		Detector: licdet.New(), Clock: clk, Stopwatch: stopwatch, Logger: logger,
		FetchPipelineVersion:      fetchapp.PipelineVersion,
		LocalFetchPipelineVersion: walklocalfs.PipelineVersion,
	})
	ifaceExtractUC := ifaceapp.NewExtractInterfaceUseCase(ifaceapp.Config{
		Facts: factStore, Blobs: blobs, Store: ifaceStore,
		Extractor: ifaceext.New(stagePipelineVersion, clk), Clock: clk, Stopwatch: stopwatch, Logger: logger,
		FetchPipelineVersion:      fetchapp.PipelineVersion,
		LocalFetchPipelineVersion: walklocalfs.PipelineVersion,
	})
	cgSubprocessExec := extextractor.NewOsSubprocessExecutor(kanonarionBinary)
	exExtractUC := exapp.NewExtractExampleUseCase(exapp.Config{
		Facts: factStore, Blobs: blobs, Examples: exStore,
		Parser: exgoast.New(),
		Clock:  clk, Stopwatch: stopwatch, Logger: logger,
		FetchPipelineVersion:      fetchapp.PipelineVersion,
		LocalFetchPipelineVersion: walklocalfs.PipelineVersion,
	})
	stages := extstages.New()
	extractUC := extractapp.NewExtractUseCase(extractapp.Config{
		Runs:      extStore,
		Walks:     walkStore,
		Extractor: extextractor.NewAdapterExtractor(licExtractUC, ifaceExtractUC, cgSubprocessExec, cgStore, cgapp.PipelineVersion, exExtractUC),
		Stages:    stages,
		Clock:     clk,
		Stopwatch: stopwatch,
		PipelineVersions: map[string]string{
			"license":   stagePipelineVersion,
			"interface": stagePipelineVersion,
			"callgraph": stagePipelineVersion,
			"example":   stagePipelineVersion,
		},
		Logger: logger,
	})

	return driver.NewLocalWalkExtractUseCase(executeWalkUC, extractUC, stages.Stages())
}
