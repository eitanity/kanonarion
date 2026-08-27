package cli

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/eitanity/kanonarion/internal/config/domain"

	blobstore "github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
	mcblobstore "github.com/eitanity/kanonarion/internal/adapters/blobstore/modcache"
	"github.com/eitanity/kanonarion/internal/adapters/clock"
	fetchsqlite "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	"github.com/eitanity/kanonarion/internal/adapters/meminfo"
	fetchproxy "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	mcproxy "github.com/eitanity/kanonarion/internal/adapters/proxy/modcache"
	noopsigner "github.com/eitanity/kanonarion/internal/adapters/signer/noop"
	fetchsumdb "github.com/eitanity/kanonarion/internal/adapters/sumdb/gosum"
	gosumfile "github.com/eitanity/kanonarion/internal/adapters/sumdb/gosumfile"
	sumdbretry "github.com/eitanity/kanonarion/internal/adapters/sumdb/retrying"
	fetchvcs "github.com/eitanity/kanonarion/internal/adapters/vcs/gitexec"
	"github.com/eitanity/kanonarion/internal/goenv"

	cganalyser "github.com/eitanity/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	cgsqlite "github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"

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
	venzipsource "github.com/eitanity/kanonarion/internal/vendortree/adapters/zipsource/blobstore"
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
	goastspelling "github.com/eitanity/kanonarion/internal/iface/adapters/spelling/goast"
	ifacesqlite "github.com/eitanity/kanonarion/internal/iface/adapters/store/sqlite"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"

	licdet "github.com/eitanity/kanonarion/internal/license/adapters/detector/licensecheck"
	licoverrides "github.com/eitanity/kanonarion/internal/license/adapters/overrides/yaml"
	licsqlite "github.com/eitanity/kanonarion/internal/license/adapters/store/sqlite"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licports "github.com/eitanity/kanonarion/internal/license/ports"

	sbomcdx "github.com/eitanity/kanonarion/internal/sbom/adapters/generator/cyclonedx"
	sbomorigin "github.com/eitanity/kanonarion/internal/sbom/adapters/origin/fetchfacts"
	sbomstore "github.com/eitanity/kanonarion/internal/sbom/adapters/store/sqlite"
	sbomvendortree "github.com/eitanity/kanonarion/internal/sbom/adapters/vendortree"
	sbomapp "github.com/eitanity/kanonarion/internal/sbom/application"

	"github.com/eitanity/kanonarion/internal/sqlitestore"

	stalesqlite "github.com/eitanity/kanonarion/internal/staleness/adapters/store/sqlite"
	staleports "github.com/eitanity/kanonarion/internal/staleness/ports"

	stdlibsqlite "github.com/eitanity/kanonarion/internal/stdlib/adapters/store/sqlite"

	vulncallgraph "github.com/eitanity/kanonarion/internal/vuln/adapters/callgraph"
	vulnfetch "github.com/eitanity/kanonarion/internal/vuln/adapters/fetch"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/reachability"
	vulnsqlite "github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	vulnvendorclosure "github.com/eitanity/kanonarion/internal/vuln/adapters/vendorclosure/vendortree"
	govulncheck "github.com/eitanity/kanonarion/internal/vuln/adapters/vuln/govulncheck"
	osvdb "github.com/eitanity/kanonarion/internal/vuln/adapters/vulndb/osv"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"

	walkbuildlist "github.com/eitanity/kanonarion/internal/walk/adapters/buildlist/gotoolchain"
	walkfetcher "github.com/eitanity/kanonarion/internal/walk/adapters/fetcher/local"
	walkretry "github.com/eitanity/kanonarion/internal/walk/adapters/fetcher/retrying"
	walkgomod "github.com/eitanity/kanonarion/internal/walk/adapters/gomod/xmod"
	walksqlite "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
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

	// StdlibCustody is the recorded chain of custody for the standard library,
	// which carries its licence on the acquisition rather than in a licence
	// record. Every command asked about the stdlib coordinate reads it here, so
	// the answer is the one audit and the SBOM already give.
	StdlibCustody StdlibCustodyReader

	// iface
	ExtractInterface ExtractInterfaceUseCase
	QueryInterface   QueryInterfaceUseCase
	DiffInterface    DiffInterfaceUseCase

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
	// NegativeSearch is the read-time call-graph search over stored negatives.
	// QueryVuln already applies it; this is for the read paths that go to the
	// vuln store directly rather than through the query use case.
	NegativeSearch *reachability.NegativeSearcher

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

	// staleness. The ledger of latest-version lookups, read and written by
	// every command that reports how far behind a dependency is.
	StalenessLedger staleports.Ledger
}

// NewContainer opens a single mirror.db with all migrations applied, wires all
// adapters from that handle, and returns the populated Container together with
// a cleanup function that closes the DB.
//
// cfg is the resolved store configuration; callers should pass activeConfig
// from the CLI layer. goBinary may be empty (falls back to PATH).
// skipVCSVerify is forwarded to the fetch use case for the walk pipeline.
// openMigratedStore opens mirror.db and applies every migration this build
// knows, refusing a store that already carries migrations it does not.
//
// Opened without migrations, then judged, then migrated. This is the operating
// path's only door into the store, so it is where an older binary meeting a
// newer store has to be stopped: schema_migrations is keyed on (module,
// version), so this binary's own migrations all appear applied and nothing
// errors — the store just holds tables and constraints shaped by a later build.
// The failure that follows is not an open failure but a write one, per
// statement, and every one of them was logged and stepped over: a full scan
// that persisted nothing and still printed a summary.
//
// `store info` deliberately does not come through here — it opens with nil
// migrations and never applies any — so the command that names the remedy stays
// available after this refuses.
func openMigratedStore(dbPath string) (sqlitestore.DB, error) {
	dbHandle, err := sqlitestore.Open(dbPath, nil)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	state, err := readStoreSchemaState(dbHandle)
	if err != nil {
		return nil, errors.Join(err, dbHandle.Close())
	}
	if state.isNewer() {
		return nil, errors.Join(newerStoreError(dbPath, state), dbHandle.Close())
	}
	if err := sqlitestore.Apply(dbHandle, allMigrations()); err != nil {
		return nil, errors.Join(fmt.Errorf("opening database: %w", err), dbHandle.Close())
	}
	return dbHandle, nil
}

// offlineStdlibAnchor reports whether this run anchors the standard library to
// the local toolchain rather than to go.dev/dl.
//
// Two independent circumstances select it, and naming the decision keeps them
// from being confused for one: --from-modcache says where module bytes come
// from, and a declared air gap says whether this process may leave the
// building. Either one alone is enough, which is the correction — the choice
// used to be made on the acquisition mode alone, so an air-gapped run without
// --from-modcache still reached go.dev/dl.
func offlineStdlibAnchor(modcacheMode bool) bool {
	return modcacheMode || goenv.NetworkForbidden()
}

func NewContainer(storeRoot, goproxy, goBinary string, skipVCSVerify bool, cfg domain.Config, logger *slog.Logger) (*Container, func() error, error) {
	if err := os.MkdirAll(storeRoot, 0o750); err != nil {
		return nil, nil, fmt.Errorf("creating store root %s: %w", storeRoot, err)
	}

	dbPath := filepath.Join(storeRoot, "mirror.db")
	dbHandle, err := openMigratedStore(dbPath)
	if err != nil {
		return nil, nil, err
	}

	cleanup := func() error {
		if cerr := dbHandle.Close(); cerr != nil {
			return fmt.Errorf("closing database: %w", cerr)
		}
		return nil
	}

	// ---- shared infrastructure ----
	// The container reads the clock the CLI reads rather than constructing its
	// own. The two were separate, so pinning the CLI's clock fixed what a
	// command PRINTED about now while the records a command WROTE — a walk's
	// completion time, a scan run's completion time, and the seconds half of a
	// scan run's identifier — still carried the wall clock. A golden naming a
	// served answer then had to generalise away which run answered and when,
	// which are the two facts such a golden exists to check.
	//
	// The production default is unchanged: cliClock is the system clock unless
	// SetClockForTest pins it, and nothing in the operating path calls that.
	//
	// The stopwatch below is deliberately NOT sourced from here. It measures
	// elapsed durations from a monotonic reading, so it stays correct under a
	// pinned wall clock — every duration this process reports comes from it, and
	// none is computed as a difference between two clock readings.
	clk := cliClock
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
		blobs        fetchports.BlobStore = localBlobs
		sumdb        fetchports.SumDBClient
		proxyAdapter fetchports.ModuleProxy
	)
	if modcacheMode {
		blobs = mcblobstore.New(modcacheDir, localBlobs)
		proxyAdapter = mcproxy.New(modcacheDir, goBinary, filepath.Dir(goSumPath), logger)
		gsClient, gerr := gosumfile.New(goSumPath)
		if gerr != nil {
			_ = dbHandle.Close()
			return nil, nil, fmt.Errorf("loading go.sum for modcache mode: %w", gerr)
		}
		sumdb = gsClient
	} else {
		// A transient checksum-database failure (429/5xx, connection reset,
		// truncated transfer) is retried with bounded backoff before it can
		// downgrade a module's verification status. Only a failed lookup is retried;
		// a policy answer (GOSUMDB=off, GOPRIVATE, no hash line) returns on the first
		// attempt. In --from-modcache mode the go.sum adapter above reads a local
		// file with no network to flake, so it is left undecorated.
		sumdb = sumdbretry.New(fetchsumdb.New(filepath.Join(storeRoot, "sumdb")), logger)
		dp, perr := fetchproxy.New(goproxy, false)
		switch {
		case fetchproxy.IsRefusal(perr):
			// The environment declares no module fetching (GOPROXY=off), or a
			// fetch route this adapter has not got (direct). The container is
			// still built: every command that only reads the store must keep
			// working inside an air gap, and most of them wire this adapter
			// without ever fetching through it. What is withdrawn is the
			// fetching, and the refusal arrives at the attempt — before any
			// network I/O — rather than being quietly re-pointed at the
			// default proxy, which is what breached the gap.
			logger.Warn("module fetching refused by the environment; reads continue, fetches will fail", "reason", perr)
			proxyAdapter = fetchproxy.Refusing(perr)
		case perr != nil:
			_ = dbHandle.Close()
			return nil, nil, fmt.Errorf("creating proxy adapter: %w", perr)
		default:
			proxyAdapter = dp
		}
	}

	// ---- factstore (auditing) ----
	rawStore := fetchsqlite.New(dbHandle)
	factStore, err := fetchsqlite.NewAuditingStore(rawStore, filepath.Join(storeRoot, "audit.jsonl"))
	if err != nil {
		_ = dbHandle.Close()
		return nil, nil, fmt.Errorf("creating auditing fetch store: %w", err)
	}

	// Re-address artefacts written under the old store-chosen blob handles so an
	// existing store survives the change to identity addressing. Runs once,
	// guarded by a marker file.
	if err := adoptLegacyBlobs(dbHandle, localBlobs, storeRoot, logger); err != nil {
		logger.Warn("could not re-address existing blobs by artefact identity", "error", err)
	}

	// ---- store adapters (all share dbHandle) ----
	walkStore := walksqlite.New(dbHandle)
	extStore := extsqlite.New(dbHandle)
	licStore := licsqlite.New(dbHandle)
	ifaceStore := ifacesqlite.New(dbHandle)
	cgStore := cgsqlite.New(dbHandle)
	// Which working tree the reader is standing in. A query about a local
	// coordinate is then answered from THAT tree's newest generation rather than
	// from whichever tree was analysed last — and from outside any module, or in a
	// module the ledger has never been run in, the read is exactly what it was.
	cgStore.PreferWorktree(callerWorktree(logger))
	exStore := exsqlite.New(dbHandle)
	vulnStore := vulnsqlite.New(dbHandle)
	sbomStore := sbomstore.New(dbHandle)

	// ---- fetch use cases ----
	fetchUC := fetchapp.NewFetchModuleUseCase(
		proxyAdapter, vcs, blobs, factStore,
		sumdb, clk, stopwatch, "", logger,
	).WithSigner(signer, factStore).
		// The write side keeps the stronger of an existing and an incoming record
		// unless the operator asked for the weaker one, and emits the refusal (or
		// the permitted downgrade) into the same append-only log the writes go to.
		WithAudit(factStore).
		WithAllowVerificationDowngrade(allowVerificationDowngrade)
	if modcacheMode {
		fetchUC = fetchUC.WithModcacheMode()
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
	// On the network path a transient proxy failure (HTTP/2 stream reset, connection
	// reset, 429/5xx) is retried with bounded backoff before it can degrade a module
	// to a fetch-failure node. In --from-modcache mode there is no network to flake,
	// so the fetcher is left undecorated.
	var fetcher walkports.ModuleFetcher = walkfetcher.New(fetchUC, skipVCSVerify)
	if !modcacheMode {
		fetcher = walkretry.New(fetcher, logger)
	}
	localFetcher := walklocalfs.New(blobs, factStore, clk)
	resolver := walkapp.NewGraphResolver(parser, fetcher, blobs, clk, "", logger).
		WithBuildListResolver(walkbuildlist.New(goBinary, logger))
	// The stdlib chain of custody has two anchors. On the network path it uses
	// go.dev/dl's published checksum plus a googlesource commit. In --from-modcache
	// mode the run is fully offline, so it anchors instead to the local toolchain
	// ($GOROOT/src + $GOROOT/LICENSE), recorded as VerifiedLocalToolchain — no
	// network I/O either way leaves the stdlib node populated.
	//
	// An environment that declares no network selects the offline anchor for the
	// same reason --from-modcache does, and this is the whole of the fix: the
	// offline acquirer already existed and already anchors without I/O, but the
	// choice was made on the acquisition MODE alone, so an air-gapped run that
	// had not also passed --from-modcache reached go.dev/dl. The two are
	// different questions — where the module bytes come from, and whether this
	// environment may leave the building — and only the second one governs here.
	if offlineStdlibAnchor(modcacheMode) {
		resolver = resolver.WithStdlibAcquirer(
			composition.NewOfflineStdlibAcquirer(dbHandle, goBinary, clk, factStore, logger), skipVCSVerify)
	} else {
		resolver = resolver.WithStdlibAcquirer(
			composition.NewStdlibAcquirer(dbHandle, blobs, clk, factStore, logger), skipVCSVerify)
	}
	walker := walkapp.NewWalker(resolver, fetcher, localFetcher, clk, stopwatch, 0, logger)

	executeWalkUC := walkapp.NewExecuteWalkUseCase(walker, walkStore, "", "", logger).WithAudit(factStore)
	queryWalksUC := walkapp.NewQueryWalksUseCase(walkStore)
	diffWalksUC := walkapp.NewDiffWalksUseCase(walkStore)

	// ---- extract use cases ----
	licExtractUC := licapp.NewExtractLicenseUseCase(licapp.Config{
		Facts: factStore, Blobs: blobs, Licenses: licStore,
		Detector: licdet.New(), Clock: clk, Stopwatch: stopwatch, Logger: logger,
	}).WithAudit(factStore)
	ifaceExtractUC := ifaceapp.NewExtractInterfaceUseCase(ifaceapp.Config{
		Facts: factStore, Blobs: blobs, Store: ifaceStore,
		Extractor: ifaceext.New("0.1.0", clk), Clock: clk, Stopwatch: stopwatch, Logger: logger,
	}).WithAudit(factStore)
	cganalyser.SetToolchainProbe(goToolchainVersionProbe)
	cgAnalyser := cganalyser.New("0.1.0", goBinary, logger)
	cgExtractUC := cgapp.NewExtractCallGraphUseCase(cgapp.Config{
		Facts: factStore, Blobs: blobs, Store: cgStore,
		Analyser: cgAnalyser, Clock: clk, Logger: logger,
		Stopwatch:  stopwatch,
		Exclusions: cfg.Callgraph.Exclude,
		Toolchain:  runToolchainNamer,
	}).WithAudit(factStore)
	cgLocalExtractUC := cgapp.NewExtractLocalCallGraphUseCase(cgapp.LocalConfig{
		Store: cgStore, Analyser: cgAnalyser, Clock: clk, Stopwatch: stopwatch, Logger: logger,
	}).WithAudit(factStore)
	exExtractUC := exapp.NewExtractExampleUseCase(exapp.Config{
		Facts: factStore, Blobs: blobs, Examples: exStore,
		Parser: exgoast.New(),
		Clock:  clk, Stopwatch: stopwatch, Logger: logger,
	}).WithAudit(factStore)

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
	cgModcacheDir := ""
	if modcacheMode {
		cgModcacheDir = modcacheDir
	}
	cgExtraArgs := extextractor.CallGraphSubprocessArgs(storeRoot, cgModcacheDir)
	adapterExtractor := extextractor.NewAdapterExtractor(licExtractUC, ifaceExtractUC, cgSubprocessExec, cgStore, cgapp.PipelineVersion, cgExtraArgs, exExtractUC).
		WithLogger(logger)
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
	}).WithAudit(factStore)
	queryExtractUC := extractapp.NewQueryExtractionUseCase(extStore)

	// ---- license query / notice / compatibility / diff use cases ----
	stdlibCustody := stdlibsqlite.New(dbHandle)
	queryLicenseUC := licapp.NewQueryLicenseUseCaseWithWalks(licStore, walkStore)
	diffLicenseUC := licapp.NewDiffLicenseUseCase(licStore)
	checkCompatUC := licapp.NewCheckCompatibilityUseCase(licStore, walkStore)
	generateNoticeUC := licapp.NewGenerateNoticeUseCase(
		licStore, factStore, blobs,
		licapp.PipelineVersion,
	)

	// ---- iface query / diff use cases ----
	queryIfaceUC := ifaceapp.NewQueryInterfaceUseCase(ifaceStore)
	diffIfaceUC := ifaceapp.NewDiffInterfaceUseCase(ifaceStore, goastspelling.Reader{})

	// ---- callgraph query use case ----
	queryCGUC := cgapp.NewQueryCallGraphUseCase(cgStore)

	// ---- example query use case ----
	queryExamplesUC := exapp.NewQueryExamplesUseCase(exStore)

	// ---- vuln use cases ----
	scanner := govulncheck.New("v1", vulnStore).WithLogger(logger)
	database := osvdb.New(nil, vulnStore, clk).WithLogger(logger)
	reach := reachability.New()
	cgLoader := reachability.NewCallGraphStoreLoader(cgStore, cgapp.PipelineVersion)

	cgSpawner := vulncallgraph.NewOsCallGraphSpawner(kanonarionBinary)
	moduleScannerUC := vulnapp.NewScanModuleUseCase(
		factStore, blobs, vulnStore, walkStore,
		scanner, database, reach,
		clk, vulnapp.PipelineVersion, logger,
	).WithCallGraphLoader(cgLoader).
		WithCallGraphSpawner(cgSpawner).
		// A module scan resolves its own snapshot when no walk scan handed it one,
		// and that download is a persist like any other. The walk and re-scan use
		// cases carry the same sink, so an advisory set arriving by any route is
		// witnessed once, by the route that fetched it.
		WithAudit(factStore)
	walkScannerUC := vulnapp.NewScanWalkUseCase(
		walkStore, vulnStore, moduleScannerUC,
		vulnfetch.NewFetchModuleAdapter(fetchUC),
		clk, vulnapp.PipelineVersion, logger,
	).WithAudit(factStore).WithHostMemory(meminfo.New()).
		// A vendored project's analysis surface is its vendor/ tree. The reader is
		// built over the vendor context's own modules.txt parser rather than a
		// second one, so the closure the scan analyses and the closure the vendor
		// command verifies are the same reading. It needs no zip source: this asks
		// only which modules the tree holds, not whether their bytes match.
		WithVendoredClosure(vulnvendorclosure.New(venlocalfs.New(nil)))
	rescanWalkUC := vulnapp.NewRescanWalkUseCase(
		walkStore, vulnStore, moduleScannerUC,
		vulnfetch.NewFetchModuleAdapter(fetchUC),
		clk, vulnapp.PipelineVersion, logger,
	).WithAudit(factStore).WithHostMemory(meminfo.New()).
		// The same reader the scan gets, for the same reason and one more: a
		// re-scan reaches for the walk's project directory to reproduce the frame
		// the run it re-scans was rooted in, and without this it could only
		// re-derive every module in isolation — which is a different question, and
		// one whose answer then outranks the consumer's on the compose ladder.
		WithVendoredClosure(vulnvendorclosure.New(venlocalfs.New(nil)))
	if modcacheMode {
		// --from-modcache: govulncheck reads the caller's existing module cache
		// directly instead of a blob-store-populated temp cache.
		walkScannerUC = walkScannerUC.WithRealModcache(modcacheDir)
		rescanWalkUC = rescanWalkUC.WithRealModcache(modcacheDir)
	}
	// Every vuln read is put through kanonarion's own call-graph search before it
	// reaches a surface, so a negative another analyser only stayed silent about
	// is answered by a search wherever a graph exists for the coordinate. It
	// writes nothing: see searchedVulnQuery.
	negSearcher := reachability.NewNegativeSearcher(cgLoader)
	queryVulnUC := newSearchedVulnQuery(vulnapp.NewQueryVulnUseCase(vulnStore), negSearcher)
	queryScanRunsUC := vulnapp.NewQueryScanRunsUseCase(vulnStore, walkStore)
	diffScanRunsUC := newSearchedDiffScanRuns(vulnapp.NewDiffScanRunsUseCase(vulnStore), negSearcher)

	// ---- sbom use cases ----
	// The version bump is the whole migration every time. SBOM records are a
	// cache keyed on it, so every stored document of a previous shape simply
	// stops being reachable and is regenerated on demand.
	//
	// 0.9.0 changes two things about the document's assertions. A component's
	// external references are now built only from what the fetch ledger
	// recorded — the repository the module zip was cross-verified against —
	// instead of being assembled from the module path, so a 0.8.0 document
	// carries a VCS URL that may name no repository and a proxy download URL
	// for bytes the proxy may never have served. And the subject's --main-version
	// and --main-license stamp now reaches the subject's own entry in the
	// component list, so a stamped 0.8.0 document describes one module twice at
	// two versions with the licence on only one of them. Neither shape may be
	// served for a 0.9.0 request.
	//
	// The preceding bump, for the record: 0.8.0 derived the stdlib component's
	// anchor_limitation property from the verification status the measurement
	// reached, instead of stating one fixed sentence naming the go.dev/dl
	// checksum and the googlesource commit.
	const sbomPipelineVersion = "0.9.0"
	generateSBOMUC := sbomapp.NewGenerateSBOMUseCase(
		walkStore, licStore, sbomStore,
		sbomcdx.New(sbomPipelineVersion),
		clk, sbomPipelineVersion, licapp.PipelineVersion, logger,
	).WithVendorTree(sbomvendortree.New(venlocalfs.New(nil))).
		// What a component's external references may assert. Without it a
		// document states no origin for anything rather than guessing one.
		WithModuleOrigins(sbomorigin.New(factStore)).
		// The SBOM is the artefact that leaves the building, so both producing one
		// and handing a stored one back are appended to the assurance log.
		WithAudit(factStore)
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
		Scanner: venlocalfs.New(venzipsource.New(blobs)), Store: venStore, Audit: factStore,
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
		StdlibCustody:      stdlibCustody,
		DiffLicense:        diffLicenseUC,
		GenerateNotice:     generateNoticeUC,
		CheckCompatibility: checkCompatUC,
		LicenseOverrides:   licoverrides.New(cfg.LicenseOverrides),

		ExtractInterface: ifaceExtractUC,
		QueryInterface:   queryIfaceUC,
		DiffInterface:    diffIfaceUC,

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
		NegativeSearch:      negSearcher,

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

		StalenessLedger: stalesqlite.New(dbHandle),
	}

	return ctr, cleanup, nil
}

// callerWorktree resolves the working tree the process is standing in: the
// nearest enclosing directory holding a go.mod, and the module path that file
// declares.
//
// It returns the zero preference — no preference — for every case where the
// question has no answer: not inside a module, a go.mod that will not parse, a
// working directory that cannot be resolved. None of those is an error worth
// failing a command over. The read they leave in place is the one every command
// had before trees could be told apart, so the cost of not knowing is the
// behaviour that was previously the only behaviour.
func callerWorktree(logger *slog.Logger) cgports.WorktreePreference {
	cwd, err := os.Getwd()
	if err != nil {
		logger.Debug("worktree_preference_unresolved", slog.String("reason", err.Error()))
		return cgports.WorktreePreference{}
	}
	dir, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		logger.Debug("worktree_preference_unresolved", slog.String("reason", err.Error()))
		return cgports.WorktreePreference{}
	}
	for {
		gomod := filepath.Join(dir, "go.mod")
		if _, statErr := os.Stat(gomod); statErr == nil {
			modulePath, mErr := readGoModulePath(gomod)
			if mErr != nil {
				logger.Debug("worktree_preference_unresolved", slog.String("reason", mErr.Error()))
				return cgports.WorktreePreference{}
			}
			return cgports.WorktreePreference{ModulePath: modulePath, Root: dir}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return cgports.WorktreePreference{}
		}
		dir = parent
	}
}
