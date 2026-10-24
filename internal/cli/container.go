package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/eitanity/kanonarion/internal/config/domain"
	configports "github.com/eitanity/kanonarion/internal/config/ports"

	mcblobstore "github.com/eitanity/kanonarion/internal/adapters/blobstore/modcache"
	"github.com/eitanity/kanonarion/internal/adapters/clock"
	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/adapters/meminfo"
	fetchproxy "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	mcproxy "github.com/eitanity/kanonarion/internal/adapters/proxy/modcache"
	privateproxy "github.com/eitanity/kanonarion/internal/adapters/proxy/private"
	noopsigner "github.com/eitanity/kanonarion/internal/adapters/signer/noop"
	fetchsumdb "github.com/eitanity/kanonarion/internal/adapters/sumdb/gosum"
	gosumfile "github.com/eitanity/kanonarion/internal/adapters/sumdb/gosumfile"
	sumdbretry "github.com/eitanity/kanonarion/internal/adapters/sumdb/retrying"
	fetchvcs "github.com/eitanity/kanonarion/internal/adapters/vcs/gitexec"

	cganalyser "github.com/eitanity/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	cgmodulecache "github.com/eitanity/kanonarion/internal/callgraph/adapters/modulecache"
	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"

	"github.com/eitanity/kanonarion/internal/composition"
	"github.com/eitanity/kanonarion/internal/composition/storage"
	sqlitestorage "github.com/eitanity/kanonarion/internal/composition/storage/sqlite"

	dirxmod "github.com/eitanity/kanonarion/internal/directive/adapters/parser/xmod"
	dirapp "github.com/eitanity/kanonarion/internal/directive/application"
	dirports "github.com/eitanity/kanonarion/internal/directive/ports"

	gdgosrc "github.com/eitanity/kanonarion/internal/godebug/adapters/scanner/gosrc"
	gdvendortree "github.com/eitanity/kanonarion/internal/godebug/adapters/vendortree"
	gdapp "github.com/eitanity/kanonarion/internal/godebug/application"

	fipsgosrc "github.com/eitanity/kanonarion/internal/fips/adapters/scanner/gosrc"
	fipsvendortree "github.com/eitanity/kanonarion/internal/fips/adapters/vendortree"
	fipsapp "github.com/eitanity/kanonarion/internal/fips/application"
	nativegosource "github.com/eitanity/kanonarion/internal/native/adapters/gosource"
	nativeapp "github.com/eitanity/kanonarion/internal/native/application"

	venlocalfs "github.com/eitanity/kanonarion/internal/vendortree/adapters/scanner/localfs"
	venzipsource "github.com/eitanity/kanonarion/internal/vendortree/adapters/zipsource/blobstore"
	venapp "github.com/eitanity/kanonarion/internal/vendortree/application"

	exgoast "github.com/eitanity/kanonarion/internal/example/adapters/parser/goast"
	exapp "github.com/eitanity/kanonarion/internal/example/application"

	extextractor "github.com/eitanity/kanonarion/internal/extract/adapters/extractor/local"
	extstages "github.com/eitanity/kanonarion/internal/extract/adapters/stages/local"
	extractapp "github.com/eitanity/kanonarion/internal/extract/application"

	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"

	walklocalfs "github.com/eitanity/kanonarion/internal/walk/adapters/localfs"

	ifaceext "github.com/eitanity/kanonarion/internal/iface/adapters/extractor/godoc"
	goastspelling "github.com/eitanity/kanonarion/internal/iface/adapters/spelling/goast"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"

	licdet "github.com/eitanity/kanonarion/internal/license/adapters/detector/licensecheck"
	licoverrides "github.com/eitanity/kanonarion/internal/license/adapters/overrides/yaml"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	licports "github.com/eitanity/kanonarion/internal/license/ports"

	sbomcdx "github.com/eitanity/kanonarion/internal/sbom/adapters/generator/cyclonedx"
	sbomnative "github.com/eitanity/kanonarion/internal/sbom/adapters/nativefacts"
	sbomorigin "github.com/eitanity/kanonarion/internal/sbom/adapters/origin/fetchfacts"
	sbomvendortree "github.com/eitanity/kanonarion/internal/sbom/adapters/vendortree"
	sbomapp "github.com/eitanity/kanonarion/internal/sbom/application"

	staleports "github.com/eitanity/kanonarion/internal/staleness/ports"

	vulncallgraph "github.com/eitanity/kanonarion/internal/vuln/adapters/callgraph"
	vulnfetch "github.com/eitanity/kanonarion/internal/vuln/adapters/fetch"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/reachability"
	vulnvendorclosure "github.com/eitanity/kanonarion/internal/vuln/adapters/vendorclosure/vendortree"
	govulncheck "github.com/eitanity/kanonarion/internal/vuln/adapters/vuln/govulncheck"
	osvdb "github.com/eitanity/kanonarion/internal/vuln/adapters/vulndb/osv"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"

	walkbuildlist "github.com/eitanity/kanonarion/internal/walk/adapters/buildlist/gotoolchain"
	walkfetcher "github.com/eitanity/kanonarion/internal/walk/adapters/fetcher/local"
	walkretry "github.com/eitanity/kanonarion/internal/walk/adapters/fetcher/retrying"
	walkgomod "github.com/eitanity/kanonarion/internal/walk/adapters/gomod/xmod"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// Container is the composition root for the CLI. It wires every adapter over
// one storage value and exposes all use cases as interface fields.
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

	// CallgraphBound is the subprocess bound this invocation adopted and what
	// decided it. It is on the container because it is resolved when the
	// extractor is built and a command that reports it must report the value the
	// run is actually using — resolving it a second time reads the host again and
	// can produce a different number from the one in force.
	CallgraphBound extextractor.CallgraphBound

	// cgAnalyser and cgFrames are where the invocation's build frame is wired:
	// the frame analyses run under, and the frame reads select. See
	// adoptDeclaredFrame.
	cgAnalyser *cganalyser.Analyser
	cgFrames   cgports.CallGraphFrameSelector

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
	ExtractCallGraph       ExtractCallGraphUseCase
	ExtractLocalCallGraph  ExtractLocalCallGraphUseCase
	ExtractStdlibCallGraph ExtractStdlibCallGraphUseCase
	QueryCallGraph         QueryCallGraphUseCase

	// examples
	ExtractExample ExtractExampleUseCase
	QueryExamples  QueryExamplesUseCase

	// vuln
	ScanModule ScanModuleUseCase
	ScanWalk   ScanWalkUseCase
	// SetAside is where the scans state the stored generations their writes and
	// reuse reads set aside; a scanning command points it at its stderr.
	SetAside            *setAsideRelay
	RescanWalk          RescanWalkUseCase
	QueryVuln           QueryVulnUseCase
	QueryScanRuns       QueryScanRunsUseCase
	DiffScanRuns        DiffScanRunsUseCase
	VulnStore           vulnports.VulnerabilityStore
	VulnPipelineVersion string
	// NegativeSearch is the read-time call-graph search over stored negatives.
	// QueryVuln already applies it; this is for the read paths that go to the
	// vuln store directly rather than through the query use case, and for the
	// records a fresh scan prints without reading them back.
	NegativeSearch *reachability.NegativeSearcher

	// sbom
	GenerateSBOM GenerateSBOMUseCase
	QuerySBOM    QuerySBOMUseCase

	// directive
	ExtractDirectives *dirapp.ExtractDirectivesUseCase
	QueryDirectives   QueryDirectivesUseCase
	DiffDirectives    DiffDirectivesUseCase
	// DirectiveParser reads a project's replace/exclude directives without
	// recording a scan. A diagnostic needs the local-replace fact to name a
	// remedy that can work, and reading it here keeps that answer coming from
	// the directive context instead of a second go.mod parser. Nil means the
	// question cannot be asked, which is not the same as answering "no".
	DirectiveParser dirports.DirectiveParser

	// godebug
	ExtractGoDebug *gdapp.ExtractGoDebugUseCase
	QueryGoDebug   *gdapp.QueryGoDebugUseCase

	// vendor
	ExtractVendor *venapp.ExtractVendorUseCase
	QueryVendor   *venapp.QueryVendorUseCase

	// fips
	ExtractFIPS ExtractFIPSUseCase
	QueryFIPS   QueryFIPSUseCase

	// native — the third-party C/C++ library a cgo module compiles into the
	// binary from source it ships in its own zip.
	ExtractNative *nativeapp.ExtractNativeUseCase
	QueryNative   *nativeapp.QueryNativeUseCase

	// staleness. The ledger of latest-version lookups, read and written by
	// every command that reports how far behind a dependency is.
	StalenessLedger staleports.Ledger

	// Audit is the backend's assurance log; ConfigHashes is its memory of the
	// last config hash that log recorded, nil when it keeps none.
	Audit        fetchports.AuditSink
	ConfigHashes configports.ConfigHashLedger
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

// releaseStore closes a store handle once a command is done with it. Every
// record the command wrote was committed before this runs, so a close error
// loses nothing and cannot change what the command has already reported.
func releaseStore(closeStore func() error) {
	_ = closeStore() //nolint:errcheck // nothing committed is lost; see above
}

// openStorage opens the backend req.Config selects; a test swaps it to run
// the CLI over a supplied backend.
var openStorage = openConfiguredStorage

// openConfiguredStorage is the one resolver every command opens its store
// through. A configuration naming a backend this binary did not register is a
// precondition failure.
func openConfiguredStorage(req storage.Request) (*storage.Storage, error) {
	req.Command, req.OnBlobRefused = invokedCommand, blobRefusals.observe
	st, err := composition.OpenStorage(context.Background(), req)
	if errors.Is(err, storage.ErrBackendNotRegistered) {
		return nil, &exitError{code: ExitConfig, msg: err.Error()}
	}
	return st, err //nolint:wrapcheck // the backend's text is the refusal
}

// NewContainer opens the store under storeRoot and returns the populated
// Container together with a cleanup function that closes the store.
//
// cfg is the resolved store configuration; callers should pass activeConfig
// from the CLI layer. goBinary may be empty (falls back to PATH).
// skipVCSVerify is forwarded to the fetch use case for the walk pipeline.
func NewContainer(storeRoot, goproxy, goBinary string, skipVCSVerify bool, cfg domain.Config, logger *slog.Logger) (*Container, func() error, error) {
	// The store root is created only for a command that declared it writes
	// records. Every other command gets a container over a store that already
	// exists, which is why a mistyped --store-root now reaches the caller as a
	// refusal instead of as an empty store with a truthful-sounding answer.
	st, err := openStorage(storage.Request{
		StoreRoot: storeRoot,
		Intent:    storeOpenIntent(),
		SetAside:  storeSetAside.report,
		Logger:    logger,
		Config:    cfg,
	})
	if err != nil {
		return nil, nil, err
	}
	return NewContainerFrom(st, storeRoot, goproxy, goBinary, skipVCSVerify, cfg, logger)
}

// NewContainerFrom wires every adapter over st and returns the Container with
// a cleanup that closes st. It owns st: a refusal closes it before returning.
//
// storeRoot is where the checksum-database cache and the call-graph child's
// --store-root live, not where records are stored.
func NewContainerFrom(st *storage.Storage, storeRoot, goproxy, goBinary string, skipVCSVerify bool, cfg domain.Config, logger *slog.Logger) (*Container, func() error, error) {
	closeStore := storageCloser(st)
	if err := admitStorage(st, storeRoot); err != nil {
		return nil, nil, errors.Join(err, closeStore())
	}
	cleanup := closeStore

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
	signer := storageSigner(st)
	vcs := fetchvcs.New()

	blobs, sumdb, proxyAdapter, err := selectFetchAdapters(cfg.Storage.SumDBCacheDir(storeRoot), goproxy, goBinary, st.Blobs, closeStore, logger)
	if err != nil {
		return nil, nil, err
	}

	// ---- stores, all from the storage value ----
	factStore, auditSink := st.Facts, st.Audit
	walkStore, extStore, licStore, ifaceStore := st.Walks, st.Extractions, st.Licenses, st.Interfaces
	cgStore, exStore, vulnStore, sbomStore := st.CallGraphs, st.Examples, st.Vulnerabilities, st.SBOMs
	// Which working tree the reader is standing in. A query about a local
	// coordinate is then answered from THAT tree's newest generation rather than
	// from whichever tree was analysed last — and from outside any module, or in a
	// module the ledger has never been run in, the read is exactly what it was.
	// A backend without the preference is read as it was before trees could be
	// told apart.
	if wp, ok := cgStore.(interface {
		PreferWorktree(cgports.WorktreePreference)
	}); ok {
		wp.PreferWorktree(callerWorktree(logger))
	}

	// ---- fetch use cases ----
	fetchUC := fetchapp.NewFetchModuleUseCase(
		proxyAdapter, vcs, blobs, factStore,
		sumdb, clk, stopwatch, "", logger,
	).WithSigner(signer, st.Attestations).
		// The write side keeps the stronger of an existing and an incoming record
		// unless the operator asked for the weaker one, and emits the refusal (or
		// the permitted downgrade) into the same append-only log the writes go to.
		WithAudit(auditSink).
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
	fetchUC, err = withProjectGoSumAnchor(fetchUC, closeStore, logger)
	if err != nil {
		return nil, nil, err
	}
	fetchUC, err = withPrivateModules(fetchUC, closeStore, logger)
	if err != nil {
		return nil, nil, err
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
		WithBuildListResolver(walkbuildlist.New(goBinary, logger).WithTarget(declaredTarget).WithTinyGo(declaredTinyGo))
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
			composition.NewOfflineStdlibAcquirer(st.Stdlib, goBinary, clk, auditSink, logger), skipVCSVerify)
	} else {
		resolver = resolver.WithStdlibAcquirer(
			composition.NewStdlibAcquirer(st.Stdlib, blobs, clk, auditSink, logger), skipVCSVerify)
	}
	// TinyGo custody's release leg follows the stdlib's offline rule: serve a
	// held measurement and reach nothing when the run or environment is offline.
	resolver = resolver.WithTinyGoReleaseAcquirer(
		composition.NewTinyGoReleaseAcquirer(st.TinyGoReleases, clk, logger, offlineStdlibAnchor(modcacheMode)))
	walker := walkapp.NewWalker(resolver, fetcher, localFetcher, clk, stopwatch, 0, logger)

	executeWalkUC := walkapp.NewExecuteWalkUseCase(walker, walkStore, "", "", logger).WithAudit(auditSink)
	queryWalksUC := walkapp.NewQueryWalksUseCase(walkStore)
	diffWalksUC := walkapp.NewDiffWalksUseCase(walkStore)

	// ---- extract use cases ----
	licExtractUC := licapp.NewExtractLicenseUseCase(licapp.Config{
		Facts: factStore, Blobs: blobs, Licenses: licStore,
		Detector: licdet.New(), Clock: clk, Stopwatch: stopwatch, Logger: logger,
	}).WithAudit(auditSink)
	ifaceExtractUC := ifaceapp.NewExtractInterfaceUseCase(ifaceapp.Config{
		Facts: factStore, Blobs: blobs, Store: ifaceStore,
		Extractor: ifaceext.New("0.1.0", clk), Clock: clk, Stopwatch: stopwatch, Logger: logger,
	}).WithAudit(auditSink)
	cganalyser.SetToolchainProbe(goToolchainVersionProbe)
	// Where the analysis's own toolchain keeps the standard library, the module
	// cache and the files it generates. The analyser renders every recorded source
	// position against those roots, so that nothing about this host reaches the
	// seal and a build-cache entry — content-addressed, and a different path every
	// time it is rebuilt — is given no position at all.
	cganalyser.SetSourceDirsProbe(goSourceDirsProbe)
	// The analyser narrates its phases to the same place the spawners copy a
	// child's to. This process is one or the other, never both: as a child it
	// writes the lines its parent's stall detector reads, and as a parent it
	// forwards what its children wrote.
	cgAnalyser := cganalyser.New("0.1.0", goBinary, logger).WithProgress(callgraphNarration).
		WithIgnoredFiles(reportIgnoredPackages)
	// A module analysed in isolation is its own main module, and the load runs
	// with the network off, so every go.mod minimal version selection reads and
	// every dependency the type checker compiles has to be in a module cache
	// already. Reading the host's own made that a property of what unrelated go
	// commands had left on the machine; the cache is built here instead, from the
	// bytes the store holds, fetching what it is missing.
	cgAnalyser = withAnalysisModuleCache(cgAnalyser, factStore, blobs, fetchUC, logger)
	cgExtractUC := cgapp.NewExtractCallGraphUseCase(cgapp.Config{
		Facts: factStore, Blobs: blobs, Store: cgStore,
		Analyser: cgAnalyser, Clock: clk, Logger: logger,
		Stopwatch:  stopwatch,
		Exclusions: cfg.Callgraph.Exclude,
		Toolchain:  runToolchainNamer,
	}).WithAudit(auditSink)
	cgLocalExtractUC := cgapp.NewExtractLocalCallGraphUseCase(cgapp.LocalConfig{
		Store: cgStore, Analyser: cgAnalyser, Clock: clk, Stopwatch: stopwatch, Logger: logger,
	}).WithAudit(auditSink)
	// The recorded chain of custody, read by the stdlib call-graph stage to anchor
	// its record and by every command asked about the stdlib coordinate.
	stdlibCustody := st.Stdlib
	cgStdlibExtractUC := cgapp.NewExtractStdlibCallGraphUseCase(cgapp.StdlibConfig{
		Store: cgStore, Analyser: cgAnalyser,
		Toolchains: newToolchainLocator(goBinary),
		Custody:    stdlibCustodyProjection{reader: stdlibCustody},
		Clock:      clk, Stopwatch: stopwatch, Logger: logger,
	}).WithAudit(auditSink)
	exExtractUC := exapp.NewExtractExampleUseCase(exapp.Config{
		Facts: factStore, Blobs: blobs, Examples: exStore,
		Parser: exgoast.New(),
		Clock:  clk, Stopwatch: stopwatch, Logger: logger,
	}).WithAudit(auditSink)

	kanonarionBinary, err := os.Executable()
	if err != nil {
		_ = closeStore() //nolint:errcheck // the refusal is the error returned
		return nil, nil, fmt.Errorf("resolving executable path for callgraph subprocess: %w", err)
	}
	// One worker runs every stage for its module, so the pool cannot bound the
	// call-graph subprocesses without also slowing the cheap in-process stages.
	// The subprocesses carry their own bound, sized from this host, and each one
	// carries the ceiling that bound shares out.
	hostMemory := meminfo.New()
	callgraphBound := extextractor.ResolveCallgraphBound(callgraphWorkers, callgraphMemoryCeiling, hostMemory, logger)
	cgSubprocessExec := extextractor.NewOsSubprocessExecutor(kanonarionBinary, callgraphCeiling, callgraphNarration).
		WithMemoryCeiling(callgraphBound.CeilingBytes)
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
	// The child selects its backend from the same file, or it would write its
	// records into a different store from the one this process reads.
	if path, ok := explicitConfigPath(); ok {
		cgExtraArgs = append(cgExtraArgs, "--config="+absOrSelf(path))
	}
	adapterExtractor := extextractor.NewAdapterExtractor(licExtractUC, ifaceExtractUC, cgSubprocessExec, st.CallGraphOutcomes, cgapp.PipelineVersion, cgExtraArgs, exExtractUC).
		WithLogger(logger).
		WithCallgraphConcurrency(callgraphBound.Workers).
		// The bound is sized once; the host is re-read before each analysis
		// starts, because the module in front of a worker later in the run may be
		// the one that holds fifty gigabytes on its own.
		WithHostMemory(hostMemory)
	pipelineVersions := map[string]string{
		"license":   "0.1.0",
		"interface": "0.1.0",
		"callgraph": "0.1.0",
		"example":   "0.1.0",
	}
	extractUC, err := extractapp.NewExtractUseCase(extractapp.Config{
		Runs:             extStore,
		Walks:            walkStore,
		Extractor:        adapterExtractor,
		Stages:           extstages.New(),
		Clock:            clk,
		Stopwatch:        stopwatch,
		PipelineVersions: pipelineVersions,
		Logger:           logger,
	})
	if err != nil {
		_ = closeStore() //nolint:errcheck // the refusal is the error returned
		return nil, nil, fmt.Errorf("wiring extract use case: %w", err)
	}
	extractUC = extractUC.WithAudit(auditSink)
	queryExtractUC := extractapp.NewQueryExtractionUseCase(extStore)

	// ---- license query / notice / compatibility / diff use cases ----
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
	scanner := govulncheck.New("v1", vulnStore).WithLogger(logger).WithTarget(declaredTarget).WithTinyGo(declaredTinyGo)
	database := osvdb.New(nil, vulnStore, clk).WithLogger(logger).WithBase(cfg.VulnDB.Mirror())
	reach := reachability.New()
	cgLoader := reachability.NewCallGraphStoreLoader(cgStore, cgapp.PipelineVersion)
	// One annotator for the whole container, so the module scanner, the walk scan
	// and the re-scan share its memo of served graphs: serving a graph is a blob
	// decode and an edge reconstruction, and a walk's records share their routes.
	routeAnnotator := reachability.NewDispatchAnnotator(
		reachability.NewCallSiteStoreReader(cgStore, cgapp.PipelineVersion).WithReadFrame(declaredReadFrame), logger)

	// The same ceiling: a reachability scan spawns the same analysis of the same
	// module, and a ceiling that applied only on the extract path would leave the
	// heaviest module able to take the host by the other route.
	cgSpawner := vulncallgraph.NewOsCallGraphSpawner(kanonarionBinary, callgraphCeiling, callgraphNarration).
		WithMemoryCeiling(callgraphBound.CeilingBytes).
		// The same store and blob source the extract stage's child is given.
		WithExtraArgs(cgExtraArgs)
	setAside := newSetAsideRelay(logger)
	moduleScannerUC := vulnapp.NewScanModuleUseCase(
		factStore, blobs, vulnStore, walkStore,
		scanner, database, reach,
		clk, vulnapp.PipelineVersion, logger,
	).WithSetAsideReporter(setAside.report).
		WithCallGraphLoader(cgLoader).
		WithCallGraphSpawner(cgSpawner).
		WithRouteAnnotator(routeAnnotator).
		// A module scan resolves its own snapshot when no walk scan handed it one,
		// and that download is a persist like any other. The walk and re-scan use
		// cases carry the same sink, so an advisory set arriving by any route is
		// witnessed once, by the route that fetched it.
		WithAudit(auditSink)
	walkScannerUC := vulnapp.NewScanWalkUseCase(
		walkStore, vulnStore, moduleScannerUC,
		vulnfetch.NewFetchModuleAdapter(fetchUC),
		clk, vulnapp.PipelineVersion, logger,
	).WithAudit(auditSink).WithHostMemory(meminfo.New()).
		WithRouteAnnotator(routeAnnotator).
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
	).WithAudit(auditSink).WithHostMemory(meminfo.New()).
		WithRouteAnnotator(routeAnnotator).
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
	negSearcher := reachability.NewNegativeSearcher(cgLoader).
		WithProjectDirs(walkProjectDirs{walks: queryWalksUC}).
		WithWalkModules(walkProjectDirs{walks: queryWalksUC})
	queryVulnUC := newSearchedVulnQuery(vulnapp.NewQueryVulnUseCase(vulnStore), negSearcher)
	queryScanRunsUC := vulnapp.NewQueryScanRunsUseCase(vulnStore, st.WalkPresence)
	diffScanRunsUC := newSearchedDiffScanRuns(vulnapp.NewDiffScanRunsUseCase(vulnStore), negSearcher)

	// ---- sbom use cases ----
	// The version bump is the whole migration every time. SBOM records are a
	// cache keyed on it, so every stored document of a previous shape simply
	// stops being reachable and is regenerated on demand.
	//
	// 0.10.0 adds a kind of component the document could not previously contain.
	// A cgo module ships C source inside its own zip and compiles it into the
	// binary; where that library has been identified, it is now emitted as a
	// pkg:generic component carrying the declaration it was read from, with a
	// dependency edge from the Go module that ships it. A 0.9.0 document of the
	// same walk lists the Go module and not the library inside it, so it
	// understates what the binary contains and may not be served for a 0.10.0
	// request. A walk with no identified native component produces byte-identical
	// bytes either way.
	//
	// The preceding bump, for the record: 0.9.0 built a component's external
	// references only from what the fetch ledger recorded, instead of assembling
	// them from the module path, and carried the subject's --main-version and
	// --main-license stamp into the subject's own entry in the component list.
	const sbomPipelineVersion = "0.10.0"
	// Built here rather than with the other native wiring below, because the SBOM
	// use case reads it: a C library a cgo module ships inside its own zip is part
	// of what the binary contains, so it belongs in the document that lists what
	// ships. The native use cases further down share this handle.
	nativeStore := st.Native
	generateSBOMUC := sbomapp.NewGenerateSBOMUseCase(
		walkStore, licStore, sbomStore,
		sbomcdx.New(sbomPipelineVersion),
		sbomPipelineVersion, licapp.PipelineVersion, logger,
	).WithVendorTree(sbomvendortree.New(venlocalfs.New(nil))).
		// What a component's external references may assert. Without it a
		// document states no origin for anything rather than guessing one.
		WithModuleOrigins(sbomorigin.New(factStore)).
		// The C library a cgo module compiles into the binary from source its own
		// zip ships. Without it the document lists the Go module and not the
		// library inside it, which is a component that ships and is in no
		// inventory.
		WithNativeComponents(sbomnative.New(nativeStore)).
		// The SBOM is the artefact that leaves the building, so both producing one
		// and handing a stored one back are appended to the assurance log.
		WithAudit(auditSink)
	querySBOMUC := sbomapp.NewQuerySBOMUseCase(sbomStore)

	// ---- directive use cases ----
	dirStore := st.Directives
	directiveParser := dirxmod.New()
	extractDirectivesUC := dirapp.NewExtractDirectivesUseCase(dirapp.Config{
		Parser: directiveParser, Store: dirStore, Audit: auditSink,
		Clock: clk, Stopwatch: stopwatch, Logger: logger,
	})
	queryDirectivesUC := dirapp.NewQueryDirectivesUseCase(dirStore)
	diffDirectivesUC := dirapp.NewDiffScansUseCase(dirStore)

	// ---- godebug use cases ----
	gdStore := st.GoDebug
	extractGoDebugUC := gdapp.NewExtractGoDebugUseCase(gdapp.Config{
		// A vendored directive names the module vendor/modules.txt says owns
		// the file, read by the vendor context's scanner through the godebug
		// port — composed here, exactly as the fips scanner below is.
		Scanner: gdgosrc.New(gdvendortree.New(venlocalfs.New(nil))),
		Store:   gdStore, Audit: auditSink,
		Clock: clk, Stopwatch: stopwatch, Logger: logger,
	})
	queryGoDebugUC := gdapp.NewQueryGoDebugUseCase(gdStore)

	// ---- vendor use cases ----
	venStore := st.Vendor
	extractVendorUC := venapp.NewExtractVendorUseCase(venapp.Config{
		Scanner: venlocalfs.New(venzipsource.New(blobs)), Store: venStore, Audit: auditSink,
		Clock: clk, Stopwatch: stopwatch, Logger: logger,
	})
	queryVendorUC := venapp.NewQueryVendorUseCase(venStore)

	// ---- fips use cases ----
	fipsStore := st.FIPS
	extractFIPSUC := fipsapp.NewExtractFIPSUseCase(fipsapp.Config{
		// A vendored finding names the module vendor/modules.txt says owns the
		// file, read by the vendor context's scanner through the fips port —
		// the composition lives here so neither context reaches into the other.
		Scanner: fipsgosrc.New(fipsvendortree.New(venlocalfs.New(nil))),
		Store:   fipsStore, Audit: auditSink,
		Clock: clk, Stopwatch: stopwatch, Logger: logger,
	})
	queryFIPSUC := fipsapp.NewQueryFIPSUseCase(fipsStore)

	// ---- native use cases ----
	extractNativeUC := nativeapp.NewExtractNativeUseCase(nativeapp.Config{
		Facts: factStore, Blobs: blobs, Native: nativeStore,
		Source: nativegosource.New(), Audit: auditSink,
		Clock: clk, Stopwatch: stopwatch, Logger: logger,
	})
	queryNativeUC := nativeapp.NewQueryNativeUseCase(nativeStore)

	ctr := &Container{
		cgAnalyser:  cgAnalyser,
		Config:      cfg,
		FetchModule: queryFetchUC,
		QueryFetch:  queryFetchUC,
		Signer:      signer,

		ExecuteWalk: executeWalkUC,
		QueryWalks:  queryWalksUC,
		DiffWalks:   diffWalksUC,

		Extract:      extractUC,
		QueryExtract: queryExtractUC,

		CallgraphBound: callgraphBound,

		ExtractLicense:     licExtractUC,
		QueryLicense:       queryLicenseUC,
		StdlibCustody:      stdlibCustody,
		DiffLicense:        diffLicenseUC,
		GenerateNotice:     generateNoticeUC,
		CheckCompatibility: checkCompatUC,
		LicenseOverrides:   licoverrides.New(licenseOverrideEntries(cfg)),

		ExtractInterface: ifaceExtractUC,
		QueryInterface:   queryIfaceUC,
		DiffInterface:    diffIfaceUC,

		ExtractCallGraph:       cgExtractUC,
		ExtractLocalCallGraph:  cgLocalExtractUC,
		ExtractStdlibCallGraph: cgStdlibExtractUC,
		QueryCallGraph:         queryCGUC,

		ExtractExample: exExtractUC,
		QueryExamples:  queryExamplesUC,

		ScanModule:          moduleScannerUC,
		ScanWalk:            walkScannerUC,
		SetAside:            setAside,
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
		DirectiveParser:   directiveParser,

		ExtractGoDebug: extractGoDebugUC,
		QueryGoDebug:   queryGoDebugUC,

		ExtractVendor: extractVendorUC,
		QueryVendor:   queryVendorUC,

		ExtractFIPS: extractFIPSUC,
		QueryFIPS:   queryFIPSUC,

		ExtractNative: extractNativeUC,
		QueryNative:   queryNativeUC,

		StalenessLedger: st.Staleness,

		Audit:        auditSink,
		ConfigHashes: st.ConfigHashes,
	}

	if fs, ok := cgStore.(cgports.CallGraphFrameSelector); ok {
		ctr.cgFrames = fs
	}
	ctr.adoptDeclaredFrame()
	release := trackContainer(ctr)
	return ctr, func() error { release(); return cleanup() }, nil
}

// requireSQLiteBackend refuses a command that reads the SQLite backend's files
// under the store root directly when the store is configured for another
// backend; does says what the command does to those files.
func requireSQLiteBackend(command, does string) error {
	name, err := composition.ConfiguredBackend(activeConfig)
	if err != nil {
		return &exitError{code: ExitConfig, msg: err.Error()}
	}
	if name != sqlitestorage.Name {
		return &exitError{code: ExitConfig, msg: fmt.Sprintf(
			"%s %s; this store is configured for backend %q", command, does, name)}
	}
	return nil
}

// absOrSelf is path made absolute, or path itself when that fails.
func absOrSelf(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

// selectFetchAdapters wires the blob store, checksum client and module proxy
// for the network path, or their module-cache equivalents under
// --from-modcache. sumdbDir is the checksum-database cache.
func selectFetchAdapters(sumdbDir, goproxy, goBinary string, localBlobs fetchports.BlobStore, closeStore func() error, logger *slog.Logger) (fetchports.BlobStore, fetchports.SumDBClient, fetchports.ModuleProxy, error) {
	// Adapter selection. In the default path the network proxy, the network
	// checksum-database client, and the content-addressed blob store are wired.
	// In --from-modcache mode three adapters are swapped for module-cache-backed
	// equivalents: bytes are read from $GOMODCACHE, verification is against the
	// local go.sum, and the fetch pipeline records coordinate-derived handles
	// instead of writing blobs.
	var (
		blobs        = localBlobs
		sumdb        fetchports.SumDBClient
		proxyAdapter fetchports.ModuleProxy
	)
	if modcacheMode {
		// The module cache is linked into the backend's blobs, so they must be
		// files on this host.
		delegate, ok := localBlobs.(mcblobstore.Delegate)
		if !ok {
			_ = closeStore() //nolint:errcheck // the refusal is the error returned
			return nil, nil, nil, &exitError{code: ExitConfig, msg: fmt.Sprintf(
				"--from-modcache needs a blob store that holds files on this host; the storage backend's blob store (%T) does not", localBlobs)}
		}
		blobs = mcblobstore.New(modcacheDir, delegate)
		proxyAdapter = mcproxy.New(modcacheDir, goBinary, filepath.Dir(goSumPath), logger)
		gsClient, gerr := gosumfile.New(goSumPath, logger)
		if gerr != nil {
			_ = closeStore() //nolint:errcheck // the refusal is the error returned
			return nil, nil, nil, fmt.Errorf("loading go.sum for modcache mode: %w", gerr)
		}
		sumdb = gsClient
	} else {
		// A transient checksum-database failure (429/5xx, connection reset,
		// truncated transfer) is retried with bounded backoff before it can
		// downgrade a module's verification status. Only a failed lookup is retried;
		// a policy answer (GOSUMDB=off, GOPRIVATE, no hash line) returns on the first
		// attempt. In --from-modcache mode the go.sum adapter above reads a local
		// file with no network to flake, so it is left undecorated.
		sumdb = sumdbretry.New(fetchsumdb.New(sumdbDir), logger)
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
			//
			// The refusal carries this command's own offline remedy from here
			// on: it is what every later fetch attempt will print, and the
			// adapter that raised it cannot know which command is running.
			perr = withOfflineRemedy(perr)
			logger.Warn("module fetching refused by the environment; reads continue, fetches will fail", "reason", perr)
			proxyAdapter = fetchproxy.Refusing(perr)
		case perr != nil:
			_ = closeStore() //nolint:errcheck // the refusal is the error returned
			return nil, nil, nil, fmt.Errorf("creating proxy adapter: %w", perr)
		default:
			proxyAdapter = dp
		}
		proxyAdapter = withPrivateRoute(proxyAdapter, goBinary, projectGoSumPath, logger)
	}
	return blobs, sumdb, proxyAdapter, nil
}

// withPrivateRoute sends every module GOPRIVATE/GONOPROXY names to the module
// cache, where the go command fetches it as the user, so no proxy ever sees its
// path. goSum is the project's; without a pattern the proxy is unchanged.
func withPrivateRoute(proxyAdapter fetchports.ModuleProxy, goBinary, goSum string, logger *slog.Logger) fetchports.ModuleProxy {
	if !goenv.HasNoProxyPatterns() {
		return proxyAdapter
	}
	return privateproxy.New(proxyAdapter, goenv.NoProxy, func(ctx context.Context) (fetchports.ModuleProxy, error) {
		dir, err := goEnvGOMODCACHE(ctx)
		if err != nil {
			return nil, err
		}
		return mcproxy.New(dir, goBinary, filepath.Dir(goSum), logger), nil
	})
}

// withPrivateModules anchors the private modules withPrivateRoute sends to the
// module cache on the project go.sum; with none, the use case refuses them.
func withPrivateModules(fetchUC *fetchapp.FetchModuleUseCase, closeStore func() error, logger *slog.Logger) (*fetchapp.FetchModuleUseCase, error) {
	if modcacheMode {
		return fetchUC, nil
	}
	uc, err := privateFetchUseCase(fetchUC, projectGoSumPath, logger)
	if err != nil {
		_ = closeStore() //nolint:errcheck // the refusal is the error returned
		return nil, err
	}
	return uc, nil
}

// privateFetchUseCase anchors private modules on goSum, or refuses them when
// goSum is empty. Without a private pattern fetchUC is unchanged.
func privateFetchUseCase(fetchUC *fetchapp.FetchModuleUseCase, goSum string, logger *slog.Logger) (*fetchapp.FetchModuleUseCase, error) {
	if !goenv.HasNoProxyPatterns() {
		return fetchUC, nil
	}
	var anchor fetchports.SumDBClient
	if goSum != "" {
		gsClient, gerr := gosumfile.New(goSum, logger)
		if gerr != nil {
			return nil, fmt.Errorf("loading project go.sum for private modules: %w", gerr)
		}
		anchor = gsClient
	}
	return fetchUC.WithPrivateModules(goenv.NoProxy, anchor), nil
}

// withProjectGoSumAnchor layers the walk root's go.sum on the network path as
// an extra offline integrity anchor, when there is one.
func withProjectGoSumAnchor(fetchUC *fetchapp.FetchModuleUseCase, closeStore func() error, logger *slog.Logger) (*fetchapp.FetchModuleUseCase, error) {
	if !modcacheMode && projectGoSumPath != "" {
		gsClient, gerr := gosumfile.New(projectGoSumPath, logger)
		if gerr != nil {
			_ = closeStore() //nolint:errcheck // the refusal is the error returned
			return nil, fmt.Errorf("loading project go.sum for verification: %w", gerr)
		}
		fetchUC = fetchUC.WithProjectGoSum(gsClient)
	}
	return fetchUC, nil
}

// withAnalysisModuleCache gives the analyser the module cache its isolated
// loads read: the operator's own under --from-modcache, else one built from
// the store.
func withAnalysisModuleCache(cgAnalyser *cganalyser.Analyser, factStore fetchports.FactStore, blobs fetchports.BlobStore, fetchUC *fetchapp.FetchModuleUseCase, logger *slog.Logger) *cganalyser.Analyser {
	if modcacheMode {
		// --from-modcache: the operator's cache is already populated, and the walk
		// scan takes it as it stands for the same reason.
		cgAnalyser = cgAnalyser.WithRealModcache(modcacheDir)
	} else {
		cgAnalyser = cgAnalyser.WithModuleCache(
			cgmodulecache.New(factStore, blobs, logger).
				WithFetcher(vulnfetch.NewFetchModuleAdapter(fetchUC)))
	}
	return cgAnalyser
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

// licenseOverrideEntries maps the operator's recorded licence determinations
// from the config context's types to the licence domain's. The config context
// keeps its own value types, so the translation happens here, at the one place
// both are in scope — the same seam noticeDeclarations uses for the operator's
// recorded copyrights.
func licenseOverrideEntries(cfg domain.Config) map[string]licdomain.LicenseOverride {
	if len(cfg.LicenseOverrides) == 0 {
		return nil
	}
	entries := make(map[string]licdomain.LicenseOverride, len(cfg.LicenseOverrides))
	for key, o := range cfg.LicenseOverrides {
		entries[key] = licdomain.LicenseOverride{
			SPDX:       o.SPDX,
			DeclaredBy: o.DeclaredBy,
			DeclaredOn: o.DeclaredOn,
			Basis:      o.Basis,
		}
	}
	return entries
}

// storageCloser is st's Close, or a no-op for a value with nothing to close.
func storageCloser(st *storage.Storage) func() error {
	if st == nil || st.Close == nil {
		return func() error { return nil }
	}
	return st.Close
}

// storageSigner is st's signer; a backend that supplies none gets the no-op,
// which is the OSS default.
func storageSigner(st *storage.Storage) fetchports.Signer {
	if st.Signer == nil {
		return noopsigner.New()
	}
	return st.Signer
}

// admitStorage refuses an incomplete value and a store this build must not
// write. Every command refuses a newer store, reads included, because every
// command builds a container. NewContainer takes no context, so the checks,
// which read only the backend's own bookkeeping, run under their own.
//
//nolint:contextcheck // see above; NewContainer keeps its signature
func admitStorage(st *storage.Storage, storeRoot string) error {
	if err := st.Validate(); err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	if st.Writable == nil {
		return nil
	}
	ctx := context.Background()
	werr := st.Writable(ctx)
	if werr == nil || !errors.Is(werr, storage.ErrStoreSchemaNewer) {
		return werr
	}
	if st.Schema == nil {
		return &exitError{code: ExitConfig, msg: werr.Error()}
	}
	state, err := st.Schema.SchemaState(ctx)
	if err != nil {
		return errors.Join(werr, err)
	}
	// The refusal names the store as the backend does; one that names nothing
	// is named by its root.
	location := state.Location
	if location == "" {
		location = storeRoot
	}
	return newerStoreError(location, schemaStateOf(state))
}

// adoptDeclaredFrame wires the invocation's declared build frame into the
// call-graph analyser and the frame every call-graph read selects: the
// declaration, or this host when nothing was declared. It runs when the
// container is built and again from declare whenever a declaration is settled
// while the container is open.
func (c *Container) adoptDeclaredFrame() {
	if c.cgAnalyser != nil {
		c.cgAnalyser.WithTarget(declaredTarget).WithTinyGo(declaredTinyGo)
	}
	if c.cgFrames != nil {
		c.cgFrames.WithReadFrame(invocationFrame())
	}
}

// declaredReadFrame is invocationFrame and the flag a remedy carries to reach it.
func declaredReadFrame() (cgdomain.BuildFrame, string) {
	return invocationFrame(), targetFlagHint()
}

// invocationFrame is the build frame this invocation's call-graph reads select.
func invocationFrame() cgdomain.BuildFrame {
	return cganalyser.DeclaredFrame(declaredTarget, declaredTinyGo)
}
