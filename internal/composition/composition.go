// Package composition is the neutral composition root shared by the CLI and the
// public façade (pkg/kanonarion). It owns the migration set that defines the
// store schema and constructs the read-only query use cases from a store root,
// so the public API can build the read-consumption surface
// without importing internal/cli — the CLI layer must stay private.
package composition

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"code.eitanity.com/kanonarion/internal/adapters/clock"
	"code.eitanity.com/kanonarion/internal/adapters/goenv"
	"code.eitanity.com/kanonarion/internal/adapters/meminfo"
	fetchproxy "code.eitanity.com/kanonarion/internal/adapters/proxy/direct"
	"code.eitanity.com/kanonarion/internal/adapters/recordseal"
	noopsigner "code.eitanity.com/kanonarion/internal/adapters/signer/noop"
	"code.eitanity.com/kanonarion/internal/adapters/sqlitestore"
	fetchsumdb "code.eitanity.com/kanonarion/internal/adapters/sumdb/gosum"
	fetchvcs "code.eitanity.com/kanonarion/internal/adapters/vcs/gitexec"
	"code.eitanity.com/kanonarion/internal/adapters/yamlkeys"
	cganalyser "code.eitanity.com/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	cgapp "code.eitanity.com/kanonarion/internal/callgraph/application"
	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/composition/storage"
	sqlitestorage "code.eitanity.com/kanonarion/internal/composition/storage/sqlite"
	"code.eitanity.com/kanonarion/internal/config"
	configyaml "code.eitanity.com/kanonarion/internal/config/adapters/store/yaml"
	configdomain "code.eitanity.com/kanonarion/internal/config/domain"
	dirapp "code.eitanity.com/kanonarion/internal/directive/application"
	"code.eitanity.com/kanonarion/internal/driver"
	exgoast "code.eitanity.com/kanonarion/internal/example/adapters/parser/goast"
	exapp "code.eitanity.com/kanonarion/internal/example/application"
	extextractor "code.eitanity.com/kanonarion/internal/extract/adapters/extractor/local"
	extstages "code.eitanity.com/kanonarion/internal/extract/adapters/stages/local"
	extractapp "code.eitanity.com/kanonarion/internal/extract/application"
	fetchapp "code.eitanity.com/kanonarion/internal/fetch/application"
	fetchports "code.eitanity.com/kanonarion/internal/fetch/ports"
	fipsapp "code.eitanity.com/kanonarion/internal/fips/application"
	gdapp "code.eitanity.com/kanonarion/internal/godebug/application"
	ifaceext "code.eitanity.com/kanonarion/internal/iface/adapters/extractor/godoc"
	ifaceapp "code.eitanity.com/kanonarion/internal/iface/application"
	licdet "code.eitanity.com/kanonarion/internal/license/adapters/detector/licensecheck"
	licapp "code.eitanity.com/kanonarion/internal/license/application"
	sbomapp "code.eitanity.com/kanonarion/internal/sbom/application"
	staleports "code.eitanity.com/kanonarion/internal/staleness/ports"
	stdlibgit "code.eitanity.com/kanonarion/internal/stdlib/adapters/gitlsremote"
	stdlibgodev "code.eitanity.com/kanonarion/internal/stdlib/adapters/godev"
	stdliblic "code.eitanity.com/kanonarion/internal/stdlib/adapters/licenseident"
	stdliblocalsrc "code.eitanity.com/kanonarion/internal/stdlib/adapters/localsource"
	stdlibtoolchain "code.eitanity.com/kanonarion/internal/stdlib/adapters/toolchainenv"
	stdlibbridge "code.eitanity.com/kanonarion/internal/stdlib/adapters/walkbridge"
	stdlibapp "code.eitanity.com/kanonarion/internal/stdlib/application"
	stdlibports "code.eitanity.com/kanonarion/internal/stdlib/ports"
	tinygogithub "code.eitanity.com/kanonarion/internal/tinygo/adapters/github"
	tinygobridge "code.eitanity.com/kanonarion/internal/tinygo/adapters/walkbridge"
	tinygoapp "code.eitanity.com/kanonarion/internal/tinygo/application"
	tinygoports "code.eitanity.com/kanonarion/internal/tinygo/ports"
	venlocalfs "code.eitanity.com/kanonarion/internal/vendortree/adapters/scanner/localfs"
	venapp "code.eitanity.com/kanonarion/internal/vendortree/application"
	vulncallgraph "code.eitanity.com/kanonarion/internal/vuln/adapters/callgraph"
	vulnfetch "code.eitanity.com/kanonarion/internal/vuln/adapters/fetch"
	"code.eitanity.com/kanonarion/internal/vuln/adapters/reachability"
	vulnvendorclosure "code.eitanity.com/kanonarion/internal/vuln/adapters/vendorclosure/vendortree"
	govulncheck "code.eitanity.com/kanonarion/internal/vuln/adapters/vuln/govulncheck"
	osvdb "code.eitanity.com/kanonarion/internal/vuln/adapters/vulndb/osv"
	vulnapp "code.eitanity.com/kanonarion/internal/vuln/application"
	walkbuildlist "code.eitanity.com/kanonarion/internal/walk/adapters/buildlist/gotoolchain"
	walkfetcher "code.eitanity.com/kanonarion/internal/walk/adapters/fetcher/local"
	walkretry "code.eitanity.com/kanonarion/internal/walk/adapters/fetcher/retrying"
	walkgomod "code.eitanity.com/kanonarion/internal/walk/adapters/gomod/xmod"
	walklocalfs "code.eitanity.com/kanonarion/internal/walk/adapters/localfs"
	walkapp "code.eitanity.com/kanonarion/internal/walk/application"
)

// Migrations returns every migration the binary knows about, in apply order.
// The SQLite backend owns the list; it is re-exported here for the callers that
// read it beside a composition root.
func Migrations() []sqlitestore.Migration { return sqlitestorage.Migrations() }

// OpenStorage opens the backend req.Config selects. The SQLite backend is in
// force whether or not it was registered, so a consumer that registers
// nothing opens the store it always did.
func OpenStorage(ctx context.Context, req storage.Request) (*storage.Storage, error) {
	return storage.OpenConfigured(ctx, req, sqlitestorage.Backend()) //nolint:wrapcheck // the backend's text is what the roots have always returned
}

// ConfiguredBackend names the backend cfg selects among those in force,
// without opening it.
func ConfiguredBackend(cfg configdomain.Config) (string, error) {
	b, err := storage.Select(cfg, sqlitestorage.Backend())
	if err != nil {
		return "", err //nolint:wrapcheck // the resolver's text is the refusal
	}
	return b.Name, nil
}

// BackendConfigSpecs is the config.yaml section of every backend in force:
// the registered ones, then the SQLite backend when it was not registered.
func BackendConfigSpecs() []config.ConfigSpec {
	specs := storage.ConfigSpecs()
	if _, ok := storage.Lookup(sqlitestorage.Name); !ok {
		b := sqlitestorage.Backend()
		specs = append(specs, config.ConfigSpec{Section: b.Section, Defaults: b.Defaults})
	}
	return specs
}

// BackendSections names the config.yaml section of every backend in force,
// the only top-level keys outside the schema a config file may carry.
func BackendSections() []string {
	var names []string
	for _, spec := range BackendConfigSpecs() {
		if spec.Section != "" {
			names = append(names, spec.Section)
		}
	}
	return names
}

// loadStoreConfig reads <storeRoot>/config.yaml; an absent file is the
// built-in defaults.
func loadStoreConfig(storeRoot string) (configdomain.Config, error) {
	return LoadConfigFile(context.Background(), filepath.Join(storeRoot, "config.yaml"))
}

// LoadConfigFile reads the configuration file at path; an absent file is the
// built-in defaults.
func LoadConfigFile(ctx context.Context, path string) (configdomain.Config, error) {
	cfg, err := configyaml.New(path, BackendSections()...).LoadConfig(ctx)
	if err != nil {
		return configdomain.Config{}, fmt.Errorf("loading store configuration: %w", yamlkeys.InFile(err, path))
	}
	return cfg, nil
}

// ErrStoreSchemaNewer is storage.ErrStoreSchemaNewer, kept under this name so
// every errors.Is caller and the CLI's exit-code mapping read it unchanged.
var ErrStoreSchemaNewer = storage.ErrStoreSchemaNewer

// NewStdlibAcquirer wires the standard-library chain-of-custody acquirer over
// the given custody store and blob store: the go.dev/dl manifest+tarball
// client, the googlesource commit resolver, the licence detector, and the
// version-keyed fact cache. It is returned as a walk StdlibAcquirer via the
// bridge so the resolver depends only on the narrow port. Both composition
// roots (the driver here and the CLI container) share it so stdlib custody
// behaves identically — including the assurance log: audit is wired here
// rather than at each call site so neither root can be the quieter one.
func NewStdlibAcquirer(store stdlibports.Store, blobs fetchports.BlobStore, clk fetchports.Clock, audit stdlibports.AuditSink, logger *slog.Logger) *stdlibbridge.Bridge {
	godev := stdlibgodev.New()
	acquirer := stdlibapp.NewAcquirer(
		godev, godev,
		stdlibgit.New(),
		stdliblic.New(licdet.New()),
		store,
		blobs, clk, logger,
	).WithAudit(audit)
	return stdlibbridge.New(acquirer)
}

// NewTinyGoReleaseAcquirer wires the TinyGo release-archive measurement over the
// given store. Offline it serves held measurements and wires no network client.
func NewTinyGoReleaseAcquirer(store tinygoports.Store, clk fetchports.Clock, logger *slog.Logger, offline bool) *tinygobridge.Bridge {
	if offline {
		return tinygobridge.New(tinygoapp.NewOfflineAcquirer(store, clk, logger))
	}
	client := tinygogithub.New()
	return tinygobridge.New(tinygoapp.NewAcquirer(client, client, store, clk, logger))
}

// NewOfflineStdlibAcquirer wires the offline standard-library chain-of-custody
// acquirer used in --from-modcache runs. It anchors to the local toolchain
// instead of go.dev/dl: the `go env GOROOT GOVERSION` inspector locates the
// toolchain, the local source reader exposes $GOROOT/src and $GOROOT/LICENSE, and
// the same licence detector and version-keyed fact cache the online path uses
// classify and persist the result. No network client is wired — the offline path
// performs no I/O beyond the local filesystem. goBinary may be empty (PATH "go").
func NewOfflineStdlibAcquirer(store stdlibports.Store, goBinary string, clk fetchports.Clock, audit stdlibports.AuditSink, logger *slog.Logger) *stdlibbridge.Bridge {
	acquirer := stdlibapp.NewLocalAcquirer(
		stdlibtoolchain.New(goBinary, logger),
		stdliblocalsrc.New(),
		stdliblic.New(licdet.New()),
		store,
		clk, logger,
	).WithAudit(audit)
	return stdlibbridge.New(acquirer)
}

// Option configures a composition root.
type Option func(*options)

type options struct {
	setAside recordseal.Reporter
}

// WithSetAsideReporter states where the stores a root builds name each stored
// record they left out because this build cannot reproduce it. Without it each
// is logged at warn level.
func WithSetAsideReporter(r func([]recordseal.SetAsideRow)) Option {
	return func(o *options) { o.setAside = r }
}

func applyOptions(opts []Option) options {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	return o
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

// NewQueries opens the store under storeRoot through the backend its
// config.yaml selects (SQLite unless it names another) and builds every Query*
// use case over it. It returns the populated
// Queries together with a cleanup function that closes the DB.
//
// A store root that does not exist is refused, not created. Every use case
// here answers from records some other run wrote, so a root this call brought
// into existence could only ever answer "nothing recorded" — a true sentence
// about a store one millisecond old and a false one about the store the caller
// meant. Only read stores are wired — no proxy, VCS, extractor, or signer — so
// the read surface stays independent of the pipeline-construction machinery.
func NewQueries(storeRoot string, opts ...Option) (*Queries, func() error, error) {
	o := applyOptions(opts)
	cfg, err := loadStoreConfig(storeRoot)
	if err != nil {
		return nil, nil, err
	}
	st, err := OpenStorage(context.Background(), storage.Request{StoreRoot: storeRoot, Intent: storage.IntentRead, SetAside: o.setAside, Config: cfg})
	if err != nil {
		return nil, nil, err //nolint:wrapcheck // the backend's text is what this root has always returned
	}
	return NewQueriesFrom(st)
}

// NewQueriesFrom builds every Query* use case over a storage value. It takes
// ownership of st: the returned cleanup closes it, and a refusal closes it
// before returning. Writable is not consulted, so a store the driver refuses
// can still be read to find out why.
func NewQueriesFrom(st *storage.Storage) (*Queries, func() error, error) {
	if err := st.Validate(); err != nil {
		return nil, nil, errors.Join(err, closeStorage(st))
	}
	q := &Queries{
		Fetch:      fetchapp.NewQueryFetchUseCase(st.Facts),
		Walks:      walkapp.NewQueryWalksUseCase(st.Walks),
		License:    licapp.NewQueryLicenseUseCaseWithWalks(st.Licenses, st.Walks),
		Interface:  ifaceapp.NewQueryInterfaceUseCase(st.Interfaces),
		CallGraph:  cgapp.NewQueryCallGraphUseCase(st.CallGraphs),
		Examples:   exapp.NewQueryExamplesUseCase(st.Examples),
		Extraction: extractapp.NewQueryExtractionUseCase(st.Extractions),
		Vuln:       vulnapp.NewQueryVulnUseCase(st.Vulnerabilities),
		ScanRuns:   vulnapp.NewQueryScanRunsUseCase(st.Vulnerabilities, st.WalkPresence),
		SBOM:       sbomapp.NewQuerySBOMUseCase(st.SBOMs),
		Directives: dirapp.NewQueryDirectivesUseCase(st.Directives),
		GoDebug:    gdapp.NewQueryGoDebugUseCase(st.GoDebug),
		Vendor:     venapp.NewQueryVendorUseCase(st.Vendor),
		FIPS:       fipsapp.NewQueryFIPSUseCase(st.FIPS),
	}
	return q, func() error { return closeStorage(st) }, nil
}

// closeStorage releases a storage value; a nil Close has nothing to release.
func closeStorage(st *storage.Storage) error {
	if st == nil || st.Close == nil {
		return nil
	}
	return st.Close()
}

// Driver is the write/serving surface. It holds the individually
// exported write use cases — the verified single-coordinate fetch/serve driver
// that powers a gating module proxy, the local walk→extract driver, the
// coordinate analysis and rescan drivers, and the validate-and-ingest
// boundary. The stage use cases they compose stay behind this root, so their
// orchestration shape is free to change. Further drivers join this struct as
// additional fields.
type Driver struct {
	// FetchServe resolves a single ModuleCoordinate, fetching and verifying on a
	// miss, and returns a BlobHandle for serving.
	FetchServe *fetchapp.ServeModuleUseCase
	// LocalWalkExtract runs a project-rooted walk over a local working tree and
	// its extraction stages, returning the records. Powers the local-walking
	// gRPC client (source never leaves the machine).
	LocalWalkExtract *driver.LocalWalkExtractUseCase
	// CoordinateAnalysis runs, for a published module version, what
	// `inspect <module>@<version>` runs: walk, extraction and vulnerability scan.
	CoordinateAnalysis *driver.CoordinateAnalysisUseCase
	// Rescan re-scans a stored walk against a fresh or pinned advisory
	// snapshot, as `vuln-scan-rescan <walk-id>` does.
	Rescan *driver.RescanUseCase
	// CallGraphBuild builds and stores one module version's call graph in the
	// call-graph child, as `callgraph <module>@<version>` does.
	CallGraphBuild *driver.CallGraphBuildUseCase
	// ValidateIngest is the verified-fact boundary: it validates imported records
	// against the same invariants extracted ones satisfy before persisting them
	// (Ingest), and re-verifies records fail-closed on read (ReadVerified). Powers
	// the consume side of the airgap bundle.
	ValidateIngest *fetchapp.ValidateAndIngestUseCase

	// staleness and stalenessTTL are the ledger and staleness.ttl the
	// StalenessResolver method builds over.
	staleness    staleports.Ledger
	stalenessTTL time.Duration
}

// StalenessResolver builds the per-module staleness resolver over the
// driver's ledger, with the store's staleness.ttl unless cfg names one.
func (d *Driver) StalenessResolver(cfg StalenessResolverConfig) (*driver.StalenessResolver, error) {
	if cfg.TTL == 0 {
		cfg.TTL = d.stalenessTTL
	}
	return NewStalenessResolver(d.staleness, cfg)
}

// NewDriver opens the store under storeRoot through the backend its
// config.yaml selects (SQLite unless it names another),
// wires the fetch pipeline (proxy, VCS, sumdb, blob store, fact store) with the
// OSS no-op signer, and constructs the verified fetch/serve driver. It returns
// the populated Driver together with a cleanup function that closes the DB. The
// caller MUST invoke cleanup when finished.
//
// The store root is created if absent. The proxy resolves $GOPROXY (or
// proxy.golang.org); the verification path is identical to the CLI fetch — this
// surface only re-shapes the result, never the integrity checks. Diagnostics
// are discarded: a serving consumer drives its own logging around the call.
func NewDriver(storeRoot string, opts ...Option) (*Driver, func() error, error) {
	exec, err := osSubprocessExecutor()
	if err != nil {
		return nil, nil, err
	}
	return newDriver(storeRoot, exec, opts...)
}

// NewDriverFrom builds the driver over a storage value, which it owns from
// here on: the returned cleanup closes it, and a refusal closes it before
// returning. storeRoot is where the checksum-database cache and the call-graph
// child's configuration live, not where records are stored. No option applies
// yet: the set-aside reporter travels in the backend's Request.
func NewDriverFrom(st *storage.Storage, storeRoot string, opts ...Option) (*Driver, func() error, error) {
	_ = opts
	exec, err := osSubprocessExecutor()
	if err != nil {
		return nil, nil, errors.Join(err, closeStorage(st))
	}
	cfg, err := loadStoreConfig(storeRoot)
	if err != nil {
		return nil, nil, errors.Join(err, closeStorage(st))
	}
	return newDriverFrom(st, storeRoot, cfg, exec)
}

func osSubprocessExecutor() (extextractor.SubprocessExecutor, error) {
	kanonarionBinary, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolving executable path for callgraph subprocess: %w", err)
	}
	return extextractor.NewOsSubprocessExecutor(kanonarionBinary, 0, nil), nil
}

// newDriver is NewDriver with the callgraph child's executor injected. The
// executor is the only seam: it is what turns the child's argv into a process,
// so it is also the only place a test can observe the arguments the driver
// builds without spawning anything.
func newDriver(storeRoot string, cgSubprocessExec extextractor.SubprocessExecutor, opts ...Option) (*Driver, func() error, error) {
	o := applyOptions(opts)
	// This surface writes, so it creates the root it writes into: a first fetch
	// or walk on a clean machine must not need a preparatory step. NewQueries,
	// which only reads, deliberately does the opposite.
	cfg, err := loadStoreConfig(storeRoot)
	if err != nil {
		return nil, nil, err
	}
	st, err := OpenStorage(context.Background(), storage.Request{StoreRoot: storeRoot, Intent: storage.IntentCreate, SetAside: o.setAside, Config: cfg})
	if err != nil {
		return nil, nil, err
	}
	return newDriverFrom(st, storeRoot, cfg, cgSubprocessExec)
}

// newDriverFrom is NewDriverFrom with the callgraph child's executor injected;
// cfg is the configuration under storeRoot.
func newDriverFrom(st *storage.Storage, storeRoot string, cfg configdomain.Config, cgSubprocessExec extextractor.SubprocessExecutor) (*Driver, func() error, error) {
	if err := st.Validate(); err != nil {
		return nil, nil, errors.Join(err, closeStorage(st))
	}
	if storeRoot == "" {
		return nil, nil, errors.Join(errors.New("building driver: empty store root; the checksum-database cache and the call-graph child need one"), closeStorage(st))
	}
	// The driver writes — it fetches, walks, extracts and ingests — so it takes
	// the refusal the CLI's operating path takes. NewQueriesFrom is deliberately
	// not gated: an operator diagnosing the refusal must still be able to read.
	if st.Writable != nil {
		if err := st.Writable(context.Background()); err != nil {
			return nil, nil, errors.Join(err, closeStorage(st))
		}
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	clk := clock.System{}
	stopwatch := clock.Monotonic{}
	fetchUC, err := NewDriverFetch(st, storeRoot, cfg, clk, stopwatch, logger)
	if err != nil {
		return nil, nil, errors.Join(err, closeStorage(st))
	}

	pipeline, err := newWalkExtract(st, fetchUC, clk, stopwatch, logger, cgSubprocessExec, storeRoot)
	if err != nil {
		return nil, nil, errors.Join(err, closeStorage(st))
	}
	scanWalk, rescanWalk := newScanPipeline(st, fetchUC, clk, logger, storeRoot, cfg.VulnDB.Mirror())

	d := &Driver{
		FetchServe: fetchapp.NewServeModuleUseCase(fetchUC, st.Blobs).WithAudit(st.Audit),
		LocalWalkExtract: driver.NewLocalWalkExtractUseCase(pipeline.walk, pipeline.extract, pipeline.stages).
			WithWorkspaceProbe(walkbuildlist.New("", logger)),
		CoordinateAnalysis: driver.NewCoordinateAnalysisUseCase(pipeline.walk, pipeline.extract, scanWalk, pipeline.stages, privateModulePath),
		Rescan:             driver.NewRescanUseCase(rescanWalk),
		CallGraphBuild:     driver.NewCallGraphBuildUseCase(pipeline.stageRunner, st.CallGraphOutcomes, cgapp.PipelineVersion),
		ValidateIngest:     fetchapp.NewValidateAndIngestUseCase(st.Facts).WithAudit(st.Audit),
		staleness:          st.Staleness,
		stalenessTTL:       cfg.Staleness.TTL,
	}
	return d, func() error { return closeStorage(st) }, nil
}

// NewDriverFetch is the driver's fetch pipeline over st: the module proxy
// $GOPROXY names, the checksum database cached under the configured directory,
// git cross-verification, the storage's signer and audit sink. The call-graph
// child an importing application serves fetches through it too.
func NewDriverFetch(st *storage.Storage, storeRoot string, cfg configdomain.Config, clk clock.System, stopwatch clock.Monotonic, logger *slog.Logger) (*fetchapp.FetchModuleUseCase, error) {
	// The driver serves the offline half of the product too — extract and the
	// air-gap bundle's ingest side — so an environment that declares no module
	// fetching does not stop it being built. It gets an adapter that refuses
	// every fetch, before any network I/O, instead of one silently re-pointed at
	// the default proxy.
	var proxy fetchports.ModuleProxy
	dp, err := fetchproxy.New("", false)
	switch {
	case fetchproxy.IsRefusal(err):
		proxy = fetchproxy.Refusing(err)
	case err != nil:
		return nil, fmt.Errorf("creating proxy adapter: %w", err)
	default:
		proxy = dp
	}

	signer := st.Signer
	if signer == nil {
		signer = noopsigner.New()
	}
	fetchUC := fetchapp.NewFetchModuleUseCase(
		proxy, fetchvcs.New(), st.Blobs, st.Facts,
		fetchsumdb.New(cfg.Storage.SumDBCacheDir(storeRoot)),
		clk, stopwatch, "", logger,
	).WithSigner(signer, st.Attestations).
		// The write side emits a refused demotion (or a permitted downgrade) into
		// the same append-only log the writes go to. Wired here as well as in the
		// CLI so the two paths append identically: a library consumer's assurance
		// log is not a quieter one.
		WithAudit(st.Audit)
	// The driver holds no project go.sum, so a private module is refused rather
	// than named to the proxy.
	if goenv.HasNoProxyPatterns() {
		fetchUC = fetchUC.WithPrivateModules(goenv.NoProxy, nil)
	}
	return fetchUC, nil
}

// privateModulePath reports a module path GONOPROXY (else GOPRIVATE) names:
// no proxy is ever asked about it.
func privateModulePath(path string) bool {
	_, ok := goenv.NoProxy(path)
	return ok
}

// stagePipelineVersion is the per-stage extraction pipeline version the driver
// wires, matching the CLI composition root. It is a constant rather than a
// config knob: the driver runs the same built-in stages the CLI does.
const stagePipelineVersion = "0.1.0"

// walkExtract is the walk and extraction pipeline the driver's walking entries
// share, with the stage set they run by default.
type walkExtract struct {
	walk    *walkapp.ExecuteWalkUseCase
	extract *extractapp.ExtractUseCase
	stages  []string
	// stageRunner runs one stage for one coordinate, as the extraction does.
	stageRunner *extextractor.AdapterExtractor
}

// newWalkExtract wires the walk and extraction pipelines over the storage
// value and fetch infrastructure. Full git/sumdb verification is on (the
// fetcher does not skip VCS); the full built-in stage set is the default.
func newWalkExtract(
	st *storage.Storage,
	fetchUC *fetchapp.FetchModuleUseCase,
	clk clock.System,
	stopwatch clock.Monotonic,
	logger *slog.Logger,
	cgSubprocessExec extextractor.SubprocessExecutor,
	storeRoot string,
) (walkExtract, error) {
	blobs, factStore, audit := st.Blobs, st.Facts, st.Audit
	walkStore, extStore, licStore, exStore := st.Walks, st.Extractions, st.Licenses, st.Examples
	ifaceStore := st.Interfaces
	cgStore := st.CallGraphOutcomes

	// ---- project-walk pipeline ----
	// The driver always fetches over the network, so transient proxy failures are
	// retried with bounded backoff before a module degrades to a fetch-failure node.
	fetcher := walkretry.New(walkfetcher.New(fetchUC, false), logger)
	localFetcher := walklocalfs.New(blobs, factStore, clk)
	// The driver's stdlib anchor follows the same rule the CLI's does: an
	// environment that declares no network gets the local-toolchain acquirer,
	// which reaches nothing, instead of the go.dev/dl one. Wired here as well as
	// in the container so a library consumer inside an air gap is not the one
	// that dials.
	var stdlibAcquirer *stdlibbridge.Bridge
	if goenv.NetworkForbidden() {
		stdlibAcquirer = NewOfflineStdlibAcquirer(st.Stdlib, "", clk, audit, logger)
	} else {
		stdlibAcquirer = NewStdlibAcquirer(st.Stdlib, blobs, clk, audit, logger)
	}
	resolver := walkapp.NewGraphResolver(walkgomod.New(), fetcher, blobs, clk, "", logger).
		WithBuildListResolver(walkbuildlist.New("", logger)).
		WithStdlibAcquirer(stdlibAcquirer, false)
	walker := walkapp.NewWalker(resolver, fetcher, localFetcher, clk, stopwatch, 0, logger)
	executeWalkUC := walkapp.NewExecuteWalkUseCase(walker, walkStore, "", "", logger).WithAudit(audit)

	// ---- extraction pipeline (full built-in stage set) ----
	licExtractUC := licapp.NewExtractLicenseUseCase(licapp.Config{
		Facts: factStore, Blobs: blobs, Licenses: licStore,
		Detector: licdet.New(), Clock: clk, Stopwatch: stopwatch, Logger: logger,
	}).WithAudit(audit)
	ifaceExtractUC := ifaceapp.NewExtractInterfaceUseCase(ifaceapp.Config{
		Facts: factStore, Blobs: blobs, Store: ifaceStore,
		Extractor: ifaceext.New(stagePipelineVersion, clk), Clock: clk, Stopwatch: stopwatch, Logger: logger,
	}).WithAudit(audit)
	exExtractUC := exapp.NewExtractExampleUseCase(exapp.Config{
		Facts: factStore, Blobs: blobs, Examples: exStore,
		Parser: exgoast.New(),
		Clock:  clk, Stopwatch: stopwatch, Logger: logger,
	}).WithAudit(audit)
	stages := extstages.New()
	// One reporter for both uses: the bound is sized from it once, and the
	// headroom gate re-reads it before each analysis starts.
	driverHostMemory := meminfo.New()
	stageRunner := extextractor.NewAdapterExtractor(licExtractUC, ifaceExtractUC, cgSubprocessExec, cgStore, cgapp.PipelineVersion,
		extextractor.CallGraphSubprocessArgs(storeRoot, ""), exExtractUC).WithLogger(logger).
		WithCallgraphConcurrency(extextractor.ResolveCallgraphConcurrency(0, driverHostMemory, logger)).
		WithHostMemory(driverHostMemory)
	extractUC, err := extractapp.NewExtractUseCase(extractapp.Config{
		Runs:  extStore,
		Walks: walkStore,
		// The callgraph stage is a fresh kanonarion process; it inherits none of
		// this one's state. Without its store root on the command line the child
		// resolves the DEFAULT store, so a driver constructed on a scratch or
		// tenant root would read, write and migrate ~/.kanonarion instead. The
		// arg list is built by the same constructor the CLI uses, so the two
		// composition roots cannot drift. The driver passes no modcache
		// directory: it has no --from-modcache concept and always reads bytes
		// through the content-addressed blob store.
		//
		// The subprocesses are bounded separately from the module pool, and sized
		// from this host: the driver takes no operator value, so it asks for the
		// host-derived default rather than leaving the memory term unread.
		Extractor: stageRunner,
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
	if err != nil {
		return walkExtract{}, fmt.Errorf("wiring extract use case: %w", err)
	}
	return walkExtract{walk: executeWalkUC, extract: extractUC.WithAudit(audit), stages: stages.Stages(), stageRunner: stageRunner}, nil
}

// newScanPipeline wires the walk scan and the re-scan over one module
// scanner, as the CLI container does, at this host's frame. The call-graph
// child is told the store root, as the extraction's is.
func newScanPipeline(
	st *storage.Storage,
	fetchUC *fetchapp.FetchModuleUseCase,
	clk clock.System,
	logger *slog.Logger,
	storeRoot string,
	vulndbURL string,
) (*vulnapp.ScanWalkUseCase, *vulnapp.RescanWalkUseCase) {
	vulnStore, cgStore := st.Vulnerabilities, st.CallGraphs
	callSites := reachability.NewCallSiteStoreReader(cgStore, cgapp.PipelineVersion).
		WithReadFrame(func() (cgdomain.BuildFrame, string) {
			return cganalyser.DeclaredFrame(goenv.Target{}, goenv.TinyGo{}), ""
		})
	routeAnnotator := reachability.NewDispatchAnnotator(callSites, logger)
	cgSpawner := vulncallgraph.NewOsCallGraphSpawner(cgChildBinary(), 0, io.Discard).
		WithExtraArgs(extextractor.CallGraphSubprocessArgs(storeRoot, ""))
	moduleScanner := vulnapp.NewScanModuleUseCase(
		st.Facts, st.Blobs, vulnStore, st.Walks,
		govulncheck.New("v1", vulnStore).WithLogger(logger),
		osvdb.New(nil, vulnStore, clk).WithLogger(logger).WithBase(vulndbURL),
		reachability.New(),
		clk, vulnapp.PipelineVersion, logger,
	).WithCallGraphLoader(reachability.NewCallGraphStoreLoader(cgStore, cgapp.PipelineVersion)).
		WithCallGraphSpawner(cgSpawner).
		WithRouteAnnotator(routeAnnotator).
		WithAudit(st.Audit)
	fetcher := vulnfetch.NewFetchModuleAdapter(fetchUC)
	scanWalk := vulnapp.NewScanWalkUseCase(st.Walks, vulnStore, moduleScanner, fetcher, clk, vulnapp.PipelineVersion, logger).
		WithAudit(st.Audit).WithHostMemory(meminfo.New()).WithRouteAnnotator(routeAnnotator).
		WithVendoredClosure(vulnvendorclosure.New(venlocalfs.New(nil)))
	rescanWalk := vulnapp.NewRescanWalkUseCase(st.Walks, vulnStore, moduleScanner, fetcher, clk, vulnapp.PipelineVersion, logger).
		WithAudit(st.Audit).WithHostMemory(meminfo.New()).WithRouteAnnotator(routeAnnotator).
		WithVendoredClosure(vulnvendorclosure.New(venlocalfs.New(nil)))
	return scanWalk, rescanWalk
}

// cgChildBinary is the binary a reachability scan spawns for a call graph:
// this one, as for the extraction stage. Empty when it cannot be resolved,
// which fails that one analysis rather than the driver.
func cgChildBinary() string {
	bin, err := os.Executable()
	if err != nil {
		return ""
	}
	return bin
}
