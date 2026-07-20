package cli

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/eitanity/kanonarion/internal/config/domain"

	blobstore "github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
	mcblobstore "github.com/eitanity/kanonarion/internal/adapters/blobstore/modcache"
	"github.com/eitanity/kanonarion/internal/adapters/clock"
	fetchsqlite "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	fetchproxy "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	mcproxy "github.com/eitanity/kanonarion/internal/adapters/proxy/modcache"
	noopsigner "github.com/eitanity/kanonarion/internal/adapters/signer/noop"
	fetchsumdb "github.com/eitanity/kanonarion/internal/adapters/sumdb/gosum"
	gosumfile "github.com/eitanity/kanonarion/internal/adapters/sumdb/gosumfile"
	fetchvcs "github.com/eitanity/kanonarion/internal/adapters/vcs/gitexec"

	cganalyser "github.com/eitanity/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	cgsqlite "github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"

	"github.com/eitanity/kanonarion/internal/composition"

	dirxmod "github.com/eitanity/kanonarion/internal/directive/adapters/parser/xmod"
	dirsqlite "github.com/eitanity/kanonarion/internal/directive/adapters/store/sqlite"
	dirapp "github.com/eitanity/kanonarion/internal/directive/application"

	gdgosrc "github.com/eitanity/kanonarion/internal/godebug/adapters/scanner/gosrc"
	gdsqlite "github.com/eitanity/kanonarion/internal/godebug/adapters/store/sqlite"
	gdapp "github.com/eitanity/kanonarion/internal/godebug/application"

	fipsgosrc "github.com/eitanity/kanonarion/internal/fips/adapters/scanner/gosrc"
	fipssqlite "github.com/eitanity/kanonarion/internal/fips/adapters/store/sqlite"
	fipsapp "github.com/eitanity/kanonarion/internal/fips/application"

	venlocalfs "github.com/eitanity/kanonarion/internal/vendortree/adapters/scanner/localfs"
	vensqlite "github.com/eitanity/kanonarion/internal/vendortree/adapters/store/sqlite"
	venapp "github.com/eitanity/kanonarion/internal/vendortree/application"

	exgoast "github.com/eitanity/kanonarion/internal/example/adapters/parser/goast"
	exsqlite "github.com/eitanity/kanonarion/internal/example/adapters/store/sqlite"
	exapp "github.com/eitanity/kanonarion/internal/example/application"

	extextractor "github.com/eitanity/kanonarion/internal/extract/adapters/extractor/local"
	extstages "github.com/eitanity/kanonarion/internal/extract/adapters/stages/local"
	extsqlite "github.com/eitanity/kanonarion/internal/extract/adapters/store/sqlite"
	extractapp "github.com/eitanity/kanonarion/internal/extract/application"

	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"

	walklocalfs "github.com/eitanity/kanonarion/internal/walk/adapters/localfs"

	ifaceext "github.com/eitanity/kanonarion/internal/iface/adapters/extractor/godoc"
	ifacesqlite "github.com/eitanity/kanonarion/internal/iface/adapters/store/sqlite"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"

	licdet "github.com/eitanity/kanonarion/internal/license/adapters/detector/licensecheck"
	licoverrides "github.com/eitanity/kanonarion/internal/license/adapters/overrides/yaml"
	licsqlite "github.com/eitanity/kanonarion/internal/license/adapters/store/sqlite"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licports "github.com/eitanity/kanonarion/internal/license/ports"

	sbomcdx "github.com/eitanity/kanonarion/internal/sbom/adapters/generator/cyclonedx"
	sbomstore "github.com/eitanity/kanonarion/internal/sbom/adapters/store/sqlite"
	sbomapp "github.com/eitanity/kanonarion/internal/sbom/application"

	"github.com/eitanity/kanonarion/internal/sqlitestore"

	vulncallgraph "github.com/eitanity/kanonarion/internal/vuln/adapters/callgraph"
	vulnfetch "github.com/eitanity/kanonarion/internal/vuln/adapters/fetch"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/reachability"
	vulnsqlite "github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	govulncheck "github.com/eitanity/kanonarion/internal/vuln/adapters/vuln/govulncheck"
	osvdb "github.com/eitanity/kanonarion/internal/vuln/adapters/vulndb/osv"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"

	walkbuildlist "github.com/eitanity/kanonarion/internal/walk/adapters/buildlist/gotoolchain"
	walkfetcher "github.com/eitanity/kanonarion/internal/walk/adapters/fetcher/local"
	walkgomod "github.com/eitanity/kanonarion/internal/walk/adapters/gomod/xmod"
	walksqlite "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
)

// Container is the composition root for the CLI. It opens a single mirror.db
// handle, wires all adapters, and exposes all use cases as interface fields.
type Container struct {
	// Config is the resolved store configuration for this invocation.
	// Preferences have already been applied to logLevel/jsonOut by root's
	// PersistentPreRunE; this field is provided for use-case layers that need
	// access to license_policy, license_overrides, or callgraph settings.
	Config domain.Config

	// fetch
	FetchModule QueryFetchUseCase // query-only; full fetch is done by runFetch directly
	QueryFetch  QueryFetchUseCase

	// identity. Signer is the published substitution port for
	// keyed attestation; the default is the OSS no-op (no attestation).
	// Pipeline call sites are wired in a later subtask.
	Signer fetchports.Signer

	// walk
	ExecuteWalk ExecuteWalkUseCase
	QueryWalks  QueryWalksUseCase
	DiffWalks   DiffWalksUseCase

	// extract
	Extract      ExtractUseCase
	QueryExtract QueryExtractionUseCase

	// license
	ExtractLicense     ExtractLicenseUseCase
	QueryLicense       QueryLicenseUseCase
	DiffLicense        DiffLicenseUseCase
	GenerateNotice     GenerateNoticeUseCase
	CheckCompatibility CheckCompatibilityUseCase
	LicenseOverrides   licports.LicenseOverrideStore

	// iface
	ExtractInterface ExtractInterfaceUseCase
	QueryInterface   QueryInterfaceUseCase

	// callgraph
	ExtractCallGraph      ExtractCallGraphUseCase
	ExtractLocalCallGraph ExtractLocalCallGraphUseCase
	QueryCallGraph        QueryCallGraphUseCase

	// examples
	ExtractExample ExtractExampleUseCase
	QueryExamples  QueryExamplesUseCase

	// vuln
	ScanModule          ScanModuleUseCase
	ScanWalk            ScanWalkUseCase
	RescanWalk          RescanWalkUseCase
	QueryVuln           QueryVulnUseCase
	QueryScanRuns       QueryScanRunsUseCase
	DiffScanRuns        DiffScanRunsUseCase
	VulnStore           vulnports.VulnerabilityStore
	VulnPipelineVersion string

	// sbom
	GenerateSBOM GenerateSBOMUseCase
	QuerySBOM    QuerySBOMUseCase

	// directive
	ExtractDirectives *dirapp.ExtractDirectivesUseCase
	QueryDirectives   QueryDirectivesUseCase
	DiffDirectives    DiffDirectivesUseCase

	// godebug
	ExtractGoDebug *gdapp.ExtractGoDebugUseCase
	QueryGoDebug   *gdapp.QueryGoDebugUseCase

	// vendor
	ExtractVendor *venapp.ExtractVendorUseCase
	QueryVendor   *venapp.QueryVendorUseCase

	// fips
	ExtractFIPS ExtractFIPSUseCase
	QueryFIPS   QueryFIPSUseCase
}

// NewContainer opens a single mirror.db with all migrations applied, wires all
// adapters from that handle, and returns the populated Container together with
// a cleanup function that closes the DB.
//
// cfg is the resolved store configuration; callers should pass activeConfig
// from the CLI layer. goBinary may be empty (falls back to PATH).
// skipVCSVerify is forwarded to the fetch use case for the walk pipeline.
func NewContainer(storeRoot, goproxy, goBinary string, skipVCSVerify bool, cfg domain.Config, logger *slog.Logger) (*Container, func() error, error) {
	if err := os.MkdirAll(storeRoot, 0o750); err != nil {
		return nil, nil, fmt.Errorf("creating store root %s: %w", storeRoot, err)
	}

	dbPath := filepath.Join(storeRoot, "mirror.db")
	dbHandle, err := sqlitestore.Open(dbPath, allMigrations())
	if err != nil {
		return nil, nil, fmt.Errorf("opening database: %w", err)
	}

	cleanup := func() error {
		if cerr := dbHandle.Close(); cerr != nil {
			return fmt.Errorf("closing database: %w", cerr)
		}
		return nil
	}

	// ---- shared infrastructure ----
	clk := clock.System{}
	stopwatch := clock.Monotonic{}
	signer := noopsigner.New()
	localBlobs := blobstore.New(storeRoot)
	if n, err := localBlobs.CleanOrphanedTemps(); err != nil {
		logger.Warn("failed to clean orphaned blob temp files", "error", err)
	} else if n > 0 {
		logger.Debug("cleaned orphaned blob temp files", "count", n)
	}
	vcs := fetchvcs.New()

	// Adapter selection. In the default path the network proxy, the network
	// checksum-database client, and the content-addressed blob store are wired.
	// In --from-modcache mode three adapters are swapped for module-cache-backed
	// equivalents: bytes are read from $GOMODCACHE, verification is against the
	// local go.sum, and the fetch pipeline records coordinate-derived handles
	// instead of writing blobs.
	var (
		blobs           fetchports.BlobStore = localBlobs
		sumdb           fetchports.SumDBClient
		proxyAdapter    fetchports.ModuleProxy
		modcacheDeriver fetchapp.ModcacheHandleDeriver
	)
	if modcacheMode {
		mcBlobs := mcblobstore.New(modcacheDir, localBlobs)
		blobs = mcBlobs
		modcacheDeriver = mcBlobs
		proxyAdapter = mcproxy.New(modcacheDir, goBinary, filepath.Dir(goSumPath), logger)
		gsClient, gerr := gosumfile.New(goSumPath)
		if gerr != nil {
			_ = dbHandle.Close()
			return nil, nil, fmt.Errorf("loading go.sum for modcache mode: %w", gerr)
		}
		sumdb = gsClient
	} else {
		sumdb = fetchsumdb.New(filepath.Join(storeRoot, "sumdb"))
		dp, perr := fetchproxy.New(goproxy, false)
		if perr != nil {
			_ = dbHandle.Close()
			return nil, nil, fmt.Errorf("creating proxy adapter: %w", perr)
		}
		proxyAdapter = dp
	}

	// ---- factstore (auditing) ----
	rawStore := fetchsqlite.New(dbHandle)
	factStore, err := fetchsqlite.NewAuditingStore(rawStore, filepath.Join(storeRoot, "audit.jsonl"))
	if err != nil {
		_ = dbHandle.Close()
		return nil, nil, fmt.Errorf("creating auditing fetch store: %w", err)
	}

	// ---- store adapters (all share dbHandle) ----
	walkStore := walksqlite.New(dbHandle)
	extStore := extsqlite.New(dbHandle)
	licStore := licsqlite.New(dbHandle)
	ifaceStore := ifacesqlite.New(dbHandle)
	cgStore := cgsqlite.New(dbHandle)
	exStore := exsqlite.New(dbHandle)
	vulnStore := vulnsqlite.New(dbHandle)
	sbomStore := sbomstore.New(dbHandle)

	// ---- fetch use cases ----
	fetchUC := fetchapp.NewFetchModuleUseCase(
		proxyAdapter, vcs, blobs, factStore,
		sumdb, clk, stopwatch, "", logger,
	).WithSigner(signer, factStore)
	if modcacheDeriver != nil {
		fetchUC = fetchUC.WithModcache(modcacheDeriver)
	}
	// On the normal network path, layer the walk root's local go.sum on
	// as an additional, always-on integrity anchor when one is present. It is a
	// cheap offline complement to the network checksum database — not a
	// replacement — so a module whose fetched h1 disagrees with go.sum fails
	// hard, while an absent entry falls through to network sumdb verification.
	// In --from-modcache mode go.sum is already the sole anchor (via sumdb), so
	// this is skipped.
	if !modcacheMode && projectGoSumPath != "" {
		gsClient, gerr := gosumfile.New(projectGoSumPath)
		if gerr != nil {
			_ = dbHandle.Close()
			return nil, nil, fmt.Errorf("loading project go.sum for verification: %w", gerr)
		}
		fetchUC = fetchUC.WithProjectGoSum(gsClient)
	}
	queryFetchUC := fetchapp.NewQueryFetchUseCase(factStore)

	// ---- walk pipeline ----
	parser := walkgomod.New()
	fetcher := walkfetcher.New(fetchUC, skipVCSVerify)
	localFetcher := walklocalfs.New(blobs, factStore, clk)
	resolver := walkapp.NewGraphResolver(parser, fetcher, blobs, clk, "", logger).
		WithBuildListResolver(walkbuildlist.New(goBinary, logger))
	// The stdlib chain of custody has two anchors. On the network path it uses
	// go.dev/dl's published checksum plus a googlesource commit. In --from-modcache
	// mode the run is fully offline, so it anchors instead to the local toolchain
	// ($GOROOT/src + $GOROOT/LICENSE), recorded as VerifiedLocalToolchain — no
	// network I/O either way leaves the stdlib node populated.
	if modcacheMode {
		resolver = resolver.WithStdlibAcquirer(
			composition.NewOfflineStdlibAcquirer(dbHandle, goBinary, clk, logger), skipVCSVerify)
	} else {
		resolver = resolver.WithStdlibAcquirer(
			composition.NewStdlibAcquirer(dbHandle, blobs, clk, logger), skipVCSVerify)
	}
	walker := walkapp.NewWalker(resolver, fetcher, localFetcher, clk, stopwatch, 0, logger)

	executeWalkUC := walkapp.NewExecuteWalkUseCase(walker, walkStore, "", "", logger).WithAudit(factStore)
	queryWalksUC := walkapp.NewQueryWalksUseCase(walkStore)
	diffWalksUC := walkapp.NewDiffWalksUseCase(walkStore)

	// ---- extract use cases ----
	licExtractUC := licapp.NewExtractLicenseUseCase(licapp.Config{
		Facts: factStore, Blobs: blobs, Licenses: licStore,
		Detector: licdet.New(), Clock: clk, Stopwatch: stopwatch, Logger: logger,
		FetchPipelineVersion:      fetchapp.PipelineVersion,
		LocalFetchPipelineVersion: walklocalfs.PipelineVersion,
	}).WithAudit(factStore)
	ifaceExtractUC := ifaceapp.NewExtractInterfaceUseCase(ifaceapp.Config{
		Facts: factStore, Blobs: blobs, Store: ifaceStore,
		Extractor: ifaceext.New("0.1.0", clk), Clock: clk, Stopwatch: stopwatch, Logger: logger,
		FetchPipelineVersion:      fetchapp.PipelineVersion,
		LocalFetchPipelineVersion: walklocalfs.PipelineVersion,
	})
	cgAnalyser := cganalyser.New("0.1.0", goBinary, logger)
	cgExtractUC := cgapp.NewExtractCallGraphUseCase(cgapp.Config{
		Facts: factStore, Blobs: blobs, Store: cgStore,
		Analyser: cgAnalyser, Clock: clk, Logger: logger,
		Stopwatch:                 stopwatch,
		FetchPipelineVersion:      fetchapp.PipelineVersion,
		LocalFetchPipelineVersion: walklocalfs.PipelineVersion,
		Exclusions:                cfg.Callgraph.Exclude,
	})
	cgLocalExtractUC := cgapp.NewExtractLocalCallGraphUseCase(cgapp.LocalConfig{
		Store: cgStore, Analyser: cgAnalyser, Clock: clk, Stopwatch: stopwatch, Logger: logger,
	})
	exExtractUC := exapp.NewExtractExampleUseCase(exapp.Config{
		Facts: factStore, Blobs: blobs, Examples: exStore,
		Parser: exgoast.New(),
		Clock:  clk, Stopwatch: stopwatch, Logger: logger,
		FetchPipelineVersion:      fetchapp.PipelineVersion,
		LocalFetchPipelineVersion: walklocalfs.PipelineVersion,
	})

	kanonarionBinary, err := os.Executable()
	if err != nil {
		_ = dbHandle.Close()
		return nil, nil, fmt.Errorf("resolving executable path for callgraph subprocess: %w", err)
	}
	cgSubprocessExec := extextractor.NewOsSubprocessExecutor(kanonarionBinary)
	// The callgraph stage runs as a fresh subprocess (see NewAdapterExtractor),
	// which does not inherit this process's --store-root/--from-modcache
	// state. Without these the child falls back to the default store root and
	// the plain content-addressed blob store, and a modcache-sourced module
	// (a "modcache:zip:" blob handle) fails to resolve.
	cgExtraArgs := []string{"--store-root=" + storeRoot}
	if modcacheMode {
		cgExtraArgs = append(cgExtraArgs, "--from-modcache="+modcacheDir)
	}
	adapterExtractor := extextractor.NewAdapterExtractor(licExtractUC, ifaceExtractUC, cgSubprocessExec, cgStore, cgapp.PipelineVersion, cgExtraArgs, exExtractUC)
	pipelineVersions := map[string]string{
		"license":   "0.1.0",
		"interface": "0.1.0",
		"callgraph": "0.1.0",
		"example":   "0.1.0",
	}
	extractUC := extractapp.NewExtractUseCase(extractapp.Config{
		Runs:             extStore,
		Walks:            walkStore,
		Extractor:        adapterExtractor,
		Stages:           extstages.New(),
		Clock:            clk,
		Stopwatch:        stopwatch,
		PipelineVersions: pipelineVersions,
		Logger:           logger,
	})
	queryExtractUC := extractapp.NewQueryExtractionUseCase(extStore)

	// ---- license query / notice / compatibility / diff use cases ----
	queryLicenseUC := licapp.NewQueryLicenseUseCaseWithWalks(licStore, walkStore)
	diffLicenseUC := licapp.NewDiffLicenseUseCase(licStore)
	checkCompatUC := licapp.NewCheckCompatibilityUseCase(licStore, walkStore)
	generateNoticeUC := licapp.NewGenerateNoticeUseCase(
		licStore, factStore, blobs,
		licapp.PipelineVersion,
		fetchapp.PipelineVersion,
	).WithLocalFetchPipelineVersion(walklocalfs.PipelineVersion)

	// ---- iface query use case ----
	queryIfaceUC := ifaceapp.NewQueryInterfaceUseCase(ifaceStore)

	// ---- callgraph query use case ----
	queryCGUC := cgapp.NewQueryCallGraphUseCase(cgStore)

	// ---- example query use case ----
	queryExamplesUC := exapp.NewQueryExamplesUseCase(exStore)

	// ---- vuln use cases ----
	scanner := govulncheck.New("v1", vulnStore).WithLogger(logger)
	database := osvdb.New(nil, vulnStore).WithLogger(logger)
	reach := reachability.New()
	cgLoader := reachability.NewCallGraphStoreLoader(cgStore, cgapp.PipelineVersion)

	cgSpawner := vulncallgraph.NewOsCallGraphSpawner(kanonarionBinary)
	moduleScannerUC := vulnapp.NewScanModuleUseCase(
		factStore, blobs, vulnStore, walkStore,
		scanner, database, reach,
		clk, vulnapp.PipelineVersion, fetchapp.PipelineVersion, logger,
	).WithCallGraphLoader(cgLoader).
		WithCallGraphSpawner(cgSpawner).
		WithLocalFetchPipelineVersion(walklocalfs.PipelineVersion)
	walkScannerUC := vulnapp.NewScanWalkUseCase(
		walkStore, vulnStore, moduleScannerUC,
		vulnfetch.NewFetchModuleAdapter(fetchUC),
		clk, vulnapp.PipelineVersion, logger,
	).WithAudit(factStore)
	rescanWalkUC := vulnapp.NewRescanWalkUseCase(
		walkStore, vulnStore, moduleScannerUC,
		vulnfetch.NewFetchModuleAdapter(fetchUC),
		clk, vulnapp.PipelineVersion, logger,
	).WithAudit(factStore)
	if modcacheMode {
		// --from-modcache: govulncheck reads the caller's existing module cache
		// directly instead of a blob-store-populated temp cache.
		walkScannerUC = walkScannerUC.WithRealModcache(modcacheDir)
		rescanWalkUC = rescanWalkUC.WithRealModcache(modcacheDir)
	}
	queryVulnUC := vulnapp.NewQueryVulnUseCase(vulnStore)
	queryScanRunsUC := vulnapp.NewQueryScanRunsUseCase(vulnStore)
	diffScanRunsUC := vulnapp.NewDiffScanRunsUseCase(vulnStore)

	// ---- sbom use cases ----
	const sbomPipelineVersion = "0.5.0"
	generateSBOMUC := sbomapp.NewGenerateSBOMUseCase(
		walkStore, licStore, vulnStore, sbomStore,
		sbomcdx.New(sbomPipelineVersion),
		clk, sbomPipelineVersion, licapp.PipelineVersion, logger,
	)
	querySBOMUC := sbomapp.NewQuerySBOMUseCase(sbomStore)

	// ---- directive use cases ----
	dirStore := dirsqlite.New(dbHandle)
	extractDirectivesUC := dirapp.NewExtractDirectivesUseCase(dirapp.Config{
		Parser: dirxmod.New(), Store: dirStore, Audit: factStore,
		Clock: clk, Stopwatch: stopwatch, Logger: logger,
	})
	queryDirectivesUC := dirapp.NewQueryDirectivesUseCase(dirStore)
	diffDirectivesUC := dirapp.NewDiffScansUseCase(dirStore)

	// ---- godebug use cases ----
	gdStore := gdsqlite.New(dbHandle)
	extractGoDebugUC := gdapp.NewExtractGoDebugUseCase(gdapp.Config{
		Scanner: gdgosrc.New(), Store: gdStore, Audit: factStore,
		Clock: clk, Stopwatch: stopwatch, Logger: logger,
	})
	queryGoDebugUC := gdapp.NewQueryGoDebugUseCase(gdStore)

	// ---- vendor use cases ----
	venStore := vensqlite.New(dbHandle)
	extractVendorUC := venapp.NewExtractVendorUseCase(venapp.Config{
		Scanner: venlocalfs.New(), Store: venStore, Audit: factStore,
		Clock: clk, Stopwatch: stopwatch, Logger: logger,
	})
	queryVendorUC := venapp.NewQueryVendorUseCase(venStore)

	// ---- fips use cases ----
	fipsStore := fipssqlite.New(dbHandle)
	extractFIPSUC := fipsapp.NewExtractFIPSUseCase(fipsapp.Config{
		Scanner: fipsgosrc.New(), Store: fipsStore, Audit: factStore,
		Clock: clk, Stopwatch: stopwatch, Logger: logger,
	})
	queryFIPSUC := fipsapp.NewQueryFIPSUseCase(fipsStore)

	ctr := &Container{
		Config:      cfg,
		FetchModule: queryFetchUC,
		QueryFetch:  queryFetchUC,
		Signer:      signer,

		ExecuteWalk: executeWalkUC,
		QueryWalks:  queryWalksUC,
		DiffWalks:   diffWalksUC,

		Extract:      extractUC,
		QueryExtract: queryExtractUC,

		ExtractLicense:     licExtractUC,
		QueryLicense:       queryLicenseUC,
		DiffLicense:        diffLicenseUC,
		GenerateNotice:     generateNoticeUC,
		CheckCompatibility: checkCompatUC,
		LicenseOverrides:   licoverrides.New(cfg.LicenseOverrides),

		ExtractInterface: ifaceExtractUC,
		QueryInterface:   queryIfaceUC,

		ExtractCallGraph:      cgExtractUC,
		ExtractLocalCallGraph: cgLocalExtractUC,
		QueryCallGraph:        queryCGUC,

		ExtractExample: exExtractUC,
		QueryExamples:  queryExamplesUC,

		ScanModule:          moduleScannerUC,
		ScanWalk:            walkScannerUC,
		RescanWalk:          rescanWalkUC,
		QueryVuln:           queryVulnUC,
		QueryScanRuns:       queryScanRunsUC,
		DiffScanRuns:        diffScanRunsUC,
		VulnStore:           vulnStore,
		VulnPipelineVersion: vulnapp.PipelineVersion,

		GenerateSBOM: generateSBOMUC,
		QuerySBOM:    querySBOMUC,

		ExtractDirectives: extractDirectivesUC,
		QueryDirectives:   queryDirectivesUC,
		DiffDirectives:    diffDirectivesUC,

		ExtractGoDebug: extractGoDebugUC,
		QueryGoDebug:   queryGoDebugUC,

		ExtractVendor: extractVendorUC,
		QueryVendor:   queryVendorUC,

		ExtractFIPS: extractFIPSUC,
		QueryFIPS:   queryFIPSUC,
	}

	return ctr, cleanup, nil
}
