package application

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/mod/modfile"

	"github.com/eitanity/kanonarion/internal/adapters/modcache"
	"github.com/eitanity/kanonarion/internal/adapters/vulndbdir"
	"github.com/eitanity/kanonarion/internal/adapters/ziparchive"
	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// populateFailureLogLimit bounds how many individual coordinate failures a
// cache-population warning names before collapsing the rest into a count. The
// failures are named rather than counted alone because the operator needs to
// know which version is missing, not merely that something is.
const populateFailureLogLimit = 10

// perWorkerBudgetBytes is the memory one module-scan worker is budgeted. It is
// the observed working set of a single govulncheck source-mode scan of a
// cloud-SDK-heavy module — the shape that OOM-killed an entire 321-module pool
// and reported every one of them unanalysed.
//
// It is a budget, not a limit: nothing enforces it on the child. Its only job
// is to stop the pool from admitting more concurrent scans than the host can
// hold, so a slow scan replaces a killed one.
// It is typed rather than left untyped because 4 GiB does not fit an int on a
// 32-bit platform, and an untyped constant handed to a variadic any — the
// logger — defaults to int and fails to compile there.
const perWorkerBudgetBytes uint64 = 4 << 30 // 4 GiB

// cpuWorkerCap is the pool's ceiling from the CPU side. The workers spend most
// of their wall clock inside a govulncheck subprocess, so more than four buys
// little even on a large host — and each one costs perWorkerBudgetBytes.
const cpuWorkerCap = 4

// moduleResult holds the outcome of a single module scan dispatched by a worker pool.
type moduleResult struct {
	coord  coordinate.ModuleCoordinate
	record domain.VulnerabilityRecord
	err    error
}

// ScanWalkUseCase orchestrates a walk-wide vulnerability scan.
type ScanWalkUseCase struct {
	walkStore       walkports.WalkStore
	vulnStore       ports.VulnerabilityStore
	moduleScanner   *ScanModuleUseCase
	vcsHosts        fetchdomain.VCSHostAllowlist
	fetcher         ports.ModuleFetcher // pre-fetches modules missing from the fact store
	clock           fetchports.Clock
	pipelineVersion string
	logger          *slog.Logger
	audit           ports.AuditSink // optional; nil disables audit emission

	// realModcacheDir, when set (--from-modcache mode), is an existing Go module
	// cache that already holds every dependency verified against go.sum at build
	// time. The scan points GOMODCACHE straight at it and skips the temp-cache
	// prefetch/populate, so govulncheck runs fully offline with no blob reads.
	realModcacheDir string

	// vendoredClosure reads a project's vendor/ tree so the scan can root the
	// analysis at the source the project compiles. Optional: a nil reader (the
	// default) leaves every scan on the fetched surface, which is what every
	// caller had before the vendored surface existed. Set via
	// WithVendoredClosure.
	vendoredClosure ports.VendoredClosureReader

	// hostMemory sizes the module-scan pool against the host's available memory
	// as well as its CPU count. Optional: a nil reporter (the default) keeps the
	// CPU-only cap, which is what every caller had before the memory budget
	// existed. Set via WithHostMemory.
	hostMemory ports.HostMemory
}

// NewScanWalkUseCase returns a new ScanWalkUseCase.
// vcsHostCapable is a ModuleFetcher that accepts a per-run VCS forge allowlist.
// The scan type-asserts against it only when a policy actually enforces one; a
// fetcher that cannot accept the override fails the scan rather than quietly
// cross-verifying against forges the operator excluded. The walk stage declares
// the same capability for the same reason.
type vcsHostCapable interface {
	WithVCSHosts(fetchdomain.VCSHostAllowlist) ports.ModuleFetcher
}

// WithVCSHosts sets the effective VCS forge allowlist for the pre-fetch this
// scan may perform.
//
// It exists because a vuln-scan that finds a module missing from the fact store
// fetches it, and that fetch cross-verifies against a forge. Without this the
// allowlist a run applies depended on which command happened to populate the
// store first: walk and audit bound by the operator's policy, vuln-scan not
// bound at all.
func (uc *ScanWalkUseCase) WithVCSHosts(hosts fetchdomain.VCSHostAllowlist) *ScanWalkUseCase {
	uc.vcsHosts = hosts
	return uc
}

// applyVCSHosts binds the resolved allowlist to the fetcher, or fails.
//
// Only an ENFORCING list is applied — a policy-configured one. The built-in set
// is advisory and already the fetcher's zero-value behaviour, so binding it
// would be a no-op that only risks masking a fetcher that cannot accept the
// real thing. Gating on "differs from the built-in set" would be wrong: a
// policy naming exactly the built-in hosts is still a decision to refuse
// everything else.
func (uc *ScanWalkUseCase) applyVCSHosts() error {
	if !uc.vcsHosts.IsEnforcing() {
		return nil
	}
	vc, ok := uc.fetcher.(vcsHostCapable)
	if !ok {
		return fmt.Errorf(
			"policy sets allowed_vcs_hosts but the module fetcher cannot apply it: %T does not implement WithVCSHosts",
			uc.fetcher)
	}
	uc.fetcher = vc.WithVCSHosts(uc.vcsHosts)
	return nil
}

func NewScanWalkUseCase(
	walkStore walkports.WalkStore,
	vulnStore ports.VulnerabilityStore,
	moduleScanner *ScanModuleUseCase,
	fetcher ports.ModuleFetcher,
	clock fetchports.Clock,
	pipelineVersion string,
	logger *slog.Logger,
) *ScanWalkUseCase {
	return &ScanWalkUseCase{
		walkStore:       walkStore,
		vulnStore:       vulnStore,
		moduleScanner:   moduleScanner,
		fetcher:         fetcher,
		clock:           clock,
		pipelineVersion: pipelineVersion,
		logger:          logger,
	}
}

// WithAudit wires an audit sink so the scan appends assurance-log events: one
// vuln_scan_completed per run and one vuln_finding_observed per finding. It is
// optional — a nil sink (the default) disables emission — and returns the
// receiver for chaining, mirroring the other optional-dependency builders.
func (uc *ScanWalkUseCase) WithAudit(sink ports.AuditSink) *ScanWalkUseCase {
	uc.audit = sink
	return uc
}

// WithHostMemory wires the host-memory reporter the module-scan pool sizes
// itself against. It is optional — a nil reporter (the default) leaves the pool
// on its CPU-only cap — and returns the receiver for chaining, mirroring the
// other optional-dependency builders.
func (uc *ScanWalkUseCase) WithHostMemory(mem ports.HostMemory) *ScanWalkUseCase {
	uc.hostMemory = mem
	return uc
}

// WithVendoredClosure wires the reader that tells the scan which modules a
// vendored project's tree holds. It is optional — a nil reader (the default)
// keeps every scan on the fetched surface — and returns the receiver for
// chaining, mirroring the other optional-dependency builders.
func (uc *ScanWalkUseCase) WithVendoredClosure(r ports.VendoredClosureReader) *ScanWalkUseCase {
	uc.vendoredClosure = r
	return uc
}

// WithRealModcache switches the scan into --from-modcache mode: govulncheck runs
// with GOMODCACHE pointed at dir, an already-populated module cache, instead of
// materialising a temp cache from the blob store. A nil/empty dir (the default)
// keeps the blob-store-populated path. Returns the receiver for chaining.
func (uc *ScanWalkUseCase) WithRealModcache(dir string) *ScanWalkUseCase {
	uc.realModcacheDir = dir
	return uc
}

// ScanWalkParams defines the input for a walk scan.
type ScanWalkParams struct {
	WalkID             string
	Snapshot           *domain.DatabaseSnapshot // nil = use latest
	Force              bool
	Fresh              bool
	EnableReachability bool
	Operator           string
	// Workers controls the module scan pool size. Zero means the derived cap:
	// min(NumCPU, 4) further reduced by the host's available-memory budget (see
	// resolveWorkerCount). A non-zero value is an explicit operator override and
	// is taken as given — the memory budget does not second-guess it.
	Workers int
	// CallGraphWorkers limits concurrent on-demand callgraph subprocess spawns.
	// Zero defaults to 1. Kept separate from Workers because SSA builds are
	// memory-heavy while scan workers are I/O-bound; mixing them would allow
	// N concurrent SSA loads.
	CallGraphWorkers int
	// BinaryModePrePass runs a fast binary-mode scan first; only modules flagged as
	// Affected then receive the full (slow) source-mode scan for call-graph precision.
	BinaryModePrePass bool
	// ProjectDir is the project's working-tree directory (the one holding go.mod).
	// When set and the walk is rooted at the local main module, the scan is
	// project-rooted: one govulncheck over the live tree derives a per-module
	// verdict for the whole build, instead of scanning each dependency in
	// isolation. Empty on a coordinate-keyed walk, which roots the same kind of
	// single analysis at the walk target's own zip instead.
	ProjectDir string
	// NoVendor forces the fetched surface for a project that carries a
	// vendor/ tree, which would otherwise be analysed from the vendored source
	// it compiles. It exists for comparison — running both surfaces over one
	// project is how a divergence between the vendored tree and the fetched
	// artefacts becomes visible — and never as a default.
	NoVendor bool
	// Progress is called after each module is scanned. It may be nil.
	Progress func(coord coordinate.ModuleCoordinate, record domain.VulnerabilityRecord, current, total int)
}

// Scan performs the walk-wide scan.
func (uc *ScanWalkUseCase) Scan(ctx context.Context, params ScanWalkParams) (domain.WalkScanRun, error) {
	// 0. Pre-flight: fail fast with an actionable error if the scanner's
	// external tooling is missing, before any expensive snapshot fetch,
	// DB extraction, GOMODCACHE population or module scanning.
	if err := uc.moduleScanner.Preflight(ctx); err != nil {
		return domain.WalkScanRun{}, fmt.Errorf("vuln-scan pre-flight failed: %w", err)
	}

	// Bind the operator's VCS forge allowlist to the pre-fetch before anything
	// is fetched. Pre-flight is the right place: a policy that cannot be applied
	// must stop the run here, not after a snapshot fetch and a partial scan.
	if err := uc.applyVCSHosts(); err != nil {
		return domain.WalkScanRun{}, err
	}

	// 1. Walk Retrieval
	walk, err := uc.walkStore.GetWalk(ctx, params.WalkID)
	if err != nil {
		return domain.WalkScanRun{}, fmt.Errorf("retrieving walk %q: %w", params.WalkID, err)
	}

	// A scan by walk id gets no project directory from its caller, but the walk
	// remembers the one it was taken from. Adopting it is what stops the same
	// walk answering differently depending on which spelling of the command
	// asked for the scan.
	params.ProjectDir = uc.effectiveProjectDir(params, walk)

	run := domain.WalkScanRun{
		ID:               fmt.Sprintf("vscan-%s-%d", params.WalkID, uc.clock.Now().Unix()),
		WalkID:           params.WalkID,
		StartedAt:        uc.clock.Now(),
		PerModuleResults: make(map[coordinate.ModuleCoordinate]string),
		PipelineVersion:  uc.pipelineVersion,
		Operator:         params.Operator,
	}

	// 2. Snapshot resolution.
	snapshot, err := uc.resolveSnapshot(ctx, params.Snapshot, params.Fresh)
	if err != nil {
		return domain.WalkScanRun{}, err
	}
	// 3a. Extract the vulnerability database snapshot once, shared across all
	// module scans. The extraction is also where the snapshot is measured: it
	// refuses a database holding no advisories, and records how many a populated
	// one holds onto the snapshot value every record in this run will name.
	// run.Snapshot is therefore assigned after it, not before — a run that
	// reported a snapshot its own records carry a fuller reading of would put the
	// two out of step for no reason.
	vulnDBDir, cleanupDB, err := uc.preExtractVulnDB(ctx, snapshot)
	if err != nil {
		return domain.WalkScanRun{}, err
	}
	defer cleanupDB()
	run.Snapshot = *snapshot

	// 3b. Pre-populate a shared GOMODCACHE from the blob store so govulncheck workers
	// don't need to download dependencies from the network.
	goModCache, releaseModCache := uc.prepareModCache(ctx, walk)
	defer releaseModCache()

	// 4. Scan modules with a bounded worker pool. Unanalysed local-replace
	// nodes are extracted upfront so the scan pool only processes
	// modules govulncheck can actually open. Local-analysed nodes
	// have a real FactRecord zip and are treated as normal scannable modules.
	allCoords := make([]coordinate.ModuleCoordinate, 0, len(walk.Graph.Nodes))
	localReplaceNodes := make([]walkdomain.GraphNode, 0)
	for _, node := range walk.Graph.Nodes {
		if node.ResolutionSource == walkdomain.ResolutionLocalReplace {
			localReplaceNodes = append(localReplaceNodes, node)
			continue
		}
		allCoords = append(allCoords, node.Coordinate)
	}
	total := len(allCoords)
	uc.logger.Info("scanning walk modules", "walk_id", params.WalkID, "module_count", total)

	workers := min(uc.resolveWorkerCount(params.Workers), total)

	// Semaphore bounding concurrent on-demand callgraph subprocesses. SSA builds
	// are memory-heavy; they must not scale with the number of scan workers.
	cgWorkers := params.CallGraphWorkers
	if cgWorkers <= 0 {
		cgWorkers = 1
	}
	cgSem := make(chan struct{}, cgWorkers)

	// Built once and shared read-only across workers: the versions this walk
	// records, used to tell an offline resolution failure kanonarion caused from
	// one inherent to scanning a module in isolation.
	knownVersions := walk.Graph.KnownVersions()
	// The versions actually fetched, which is what a synthesised go.mod may
	// require. Narrower than knownVersions: a replaced-from coordinate is a name
	// the walk recognises, not source it holds.
	selectedVersions := walk.Graph.SelectedVersions()

	scanPool := func(coordSlice []coordinate.ModuleCoordinate, scanMode domain.ScanMode) []moduleResult {
		return uc.runScanPool(ctx, coordSlice, workers, cgSem, params, snapshot, goModCache, vulnDBDir, scanMode, knownVersions, selectedVersions)
	}

	// finalResults maps each coordinate to its definitive scan result.
	finalResults := make(map[coordinate.ModuleCoordinate]moduleResult, total)

	// Which copy of the source this run resolves from. It is a property of the
	// run, not of one code path, so it is settled once here and stamped on every
	// record the run writes — including the ones no analysis reached, which
	// otherwise could not be read alongside the rest.
	closure := uc.resolveVendoredClosure(ctx, params)
	runSurface := domain.AnalysisSurfaceFetched
	if closure.Vendored {
		runSurface = domain.AnalysisSurfaceVendored
	}

	// A coordinate-keyed walk has no project working tree, but it does have a
	// root: the target module itself. Rooting the analysis there makes every
	// dependency's package set import-driven — the packages the target's build
	// reaches — instead of `./...` over each dependency in isolation, which loads
	// commands and library packages no consumer can reach and records a coverage
	// gap when their imports demand versions the build never selected. It falls
	// back to the isolated pool rather than failing the walk when the target
	// cannot be analysed as a whole.
	targetRooted := false
	if !walk.Target.IsLocal() {
		uc.logger.Info("target-rooted vuln scan", "walk_id", params.WalkID, "root", walk.Target)
		var terr error
		targetRooted, terr = uc.scanTargetRooted(ctx, walk, allCoords, params, snapshot, vulnDBDir, goModCache, selectedVersions, finalResults)
		if terr != nil {
			return domain.WalkScanRun{}, terr
		}
	}

	switch {
	case walk.Target.IsLocal() && params.ProjectDir != "":
		// A project walk is rooted at the local main module. Its verdict is the
		// project's resolved, pruned build — derive it from a single
		// project-rooted scan of the live working tree, not from re-scanning each
		// dependency in isolation (which re-selects versions the project never
		// builds and reports a self-inflicted version-not-in-toolchain gap).
		//
		// A vendored project is analysed from vendor/ rather than from the
		// artefacts kanonarion fetched: the vendored tree is what the project
		// compiles, and a verdict about anything else is a verdict about a build
		// that does not exist.
		uc.logger.Info("project-rooted vuln scan",
			"walk_id", params.WalkID, "root", walk.Target, "project_dir", params.ProjectDir,
			"vendored", closure.Vendored)
		if perr := uc.scanProjectRooted(ctx, walk, allCoords, params, snapshot, vulnDBDir, closure, finalResults); perr != nil {
			return domain.WalkScanRun{}, perr
		}
	case targetRooted:
		// Verdicts already derived from the target-rooted analysis.
	case params.BinaryModePrePass:
		// Pass 1: fast binary-mode scan across all modules.
		uc.logger.Info("binary pre-pass: scanning all modules in binary mode", "count", total)
		pass1 := scanPool(allCoords, domain.ScanModeBinary)

		// Modules flagged Affected by binary mode need source-mode re-scan for call-graph precision.
		var needSourceScan []coordinate.ModuleCoordinate
		for _, r := range pass1 {
			// Which modules earn a source-mode re-scan is a findings question — the
			// re-scan exists to add call-graph precision to a match — so it is asked
			// of the findings axis. A binary-mode record that matched by coordinate
			// under a coverage gap reports its finding there, and reading the
			// collapsed word skipped the re-scan for exactly the module whose
			// reachability was never computed.
			_, findings := domain.RecordAxes(r.record)
			if r.err == nil && findings == domain.FindingsRecordAffected {
				needSourceScan = append(needSourceScan, r.coord)
			} else {
				finalResults[r.coord] = r
			}
		}

		if len(needSourceScan) > 0 {
			uc.logger.Info("binary pre-pass: re-scanning affected modules in source mode", "count", len(needSourceScan))
			pass2 := scanPool(needSourceScan, domain.ScanModeSource)
			for _, r := range pass2 {
				finalResults[r.coord] = r
			}
		}
	default:
		for _, r := range scanPool(allCoords, domain.ScanModeSource) {
			finalResults[r.coord] = r
		}
	}

	// A module scan that reached the snapshot itself and found it corrupt is not
	// one module's failure. The pool would otherwise fold it into a per-module
	// StatusScanFailed record and let the run complete, which is the same
	// swallow this abort exists to remove — one layer further down.
	if err := firstSnapshotIntegrityFailure(allCoords, finalResults); err != nil {
		return domain.WalkScanRun{}, err
	}

	progressCount := 0
	counts, err := uc.tallyModuleResults(ctx, allCoords, finalResults, &run, params, snapshot, &progressCount, total)
	if err != nil {
		return domain.WalkScanRun{}, err
	}

	// emit a deterministic StatusUnscannable record for each
	// local-replace node so absence isn't silently dropped.
	localReplaceCount, err := uc.recordLocalReplaceUnscannable(ctx, localReplaceNodes, &run, params, snapshot, runSurface, &progressCount, len(walk.Graph.Nodes))
	if err != nil {
		return domain.WalkScanRun{}, err
	}
	counts.unscannable += localReplaceCount

	// 4b. Every coordinate the run reported a verdict for must have that verdict
	// in the store. A module that produced a progress line and no record is a
	// verdict the run claims to have made and did not keep.
	if err := uc.verifyRecordsPersisted(ctx, walk, run, snapshot); err != nil {
		return domain.WalkScanRun{}, err
	}

	// 5. Status determination. The two axes are stored separately so a run that
	// both found something and left part of the build list unanalysed keeps both
	// facts; OverallStatus is the derived compatibility summary that collapses
	// them into one word.
	run.CompletedAt = uc.clock.Now()
	nodeCount := len(walk.Graph.Nodes)
	run.OverallStatus = domain.DetermineWalkScanStatus(
		counts.failed, counts.affected, counts.unscannable, nodeCount,
	)
	run.CoverageStatus = domain.DetermineCoverageStatus(counts.failed, counts.unscannable, nodeCount)
	run.FindingsStatus = domain.DetermineFindingsStatus(counts.affected)
	run.Counts = domain.WalkScanCounts{
		Total: nodeCount,
		// The coverage axis's own count, not clean+affected. A coordinate-matched
		// module reports a finding without having been analysed, so adding the
		// affected tally here counted it as read.
		Analysed:    counts.analysed,
		Affected:    counts.affected,
		Unscannable: counts.unscannable,
		Failed:      counts.failed,
	}

	// 6. Hash & Persist
	run, err = domain.WalkScanRunHasher{}.SetContentHash(run)
	if err != nil {
		return domain.WalkScanRun{}, fmt.Errorf("hashing walk scan run: %w", err)
	}
	if err := uc.vulnStore.PutWalkScanRun(ctx, run); err != nil {
		return domain.WalkScanRun{}, fmt.Errorf("persisting walk scan run: %w", err)
	}

	// 7. Assurance log: one vuln_finding_observed per finding plus one
	// vuln_scan_completed for the run, so the tamper-resistant append-only log
	// records what was scanned and what was found, not only the mutable vuln DB.
	if err := uc.emitAuditEvents(run, allCoords, finalResults, counts); err != nil {
		return domain.WalkScanRun{}, err
	}

	return run, nil
}

// missingRecordLogLimit bounds how many coordinates a persistence-gap error
// names before collapsing the rest into a count, so the message stays readable
// while still identifying which modules were lost.
const missingRecordLogLimit = 10

// verifyRecordsPersisted reads back every scanned coordinate and fails the run
// when any of them has no stored record for this walk.
//
// The scan reports one progress line per module in the graph, so the run asserts
// a verdict for each. Every write leg now raises its own failure rather than
// logging it, so a refused write can no longer reach here — but that is a
// property of the call sites, and this check does not depend on it. It is a
// read-back: it asks the store what it holds rather than trusting what the stage
// intended to write, which is the only form of the question that also catches a
// write that reported success and stored nothing, or a future leg that
// reintroduces the swallow.
//
// A gap fails the run rather than being logged: an incomplete record set silently
// under-reports the build, which is the same class of defect as a false clean.
//
// The check is by CONTENT HASH — the exact generation this run recorded in
// run.PerModuleResults — rather than by reading the coordinate back and
// comparing walk IDs. Two things make that necessary against a ledger. A read by
// coordinate now serves the composed record, which may legitimately be an
// earlier generation that outranks the one this run wrote, so a hash comparison
// against it would report a stored record as missing. And a reused record keeps
// the walk it was measured in, so a walk-ID comparison would report every reuse
// as a gap. The run's claim is a set of specific records; this asks whether each
// of them is in the store.
func (uc *ScanWalkUseCase) verifyRecordsPersisted(
	ctx context.Context,
	walk walkdomain.WalkRecord,
	run domain.WalkScanRun,
	snapshot *domain.DatabaseSnapshot,
) error {
	var missing []coordinate.ModuleCoordinate
	for _, node := range walk.Graph.Nodes {
		contentHash, claimed := run.PerModuleResults[node.Coordinate]
		if !claimed {
			// The run reported a result for every node and kept no record for this
			// one. That is exactly the gap this check exists to turn into a failure.
			missing = append(missing, node.Coordinate)
			continue
		}
		// Read back by the store's own record identity rather than through the
		// per-run module index: that index is written by PutWalkScanRun, which has
		// not run yet, so querying it here would answer for previous runs of this
		// walk instead of this one.
		ok, err := uc.vulnStore.HasVulnerabilityRecord(ctx, node.Coordinate, uc.pipelineVersion, *snapshot, contentHash)
		if err != nil {
			return fmt.Errorf("verifying persisted vulnerability record for %s: %w", node.Coordinate, err)
		}
		if !ok {
			missing = append(missing, node.Coordinate)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	named := missing
	if len(named) > missingRecordLogLimit {
		named = named[:missingRecordLogLimit]
	}
	return fmt.Errorf(
		"vuln scan of walk %s reported a verdict for %d modules but stored only %d: no record persisted for %v (and %d more)",
		run.WalkID, len(walk.Graph.Nodes), len(walk.Graph.Nodes)-len(missing), named, len(missing)-len(named),
	)
}

// scanCounts is the overall module-count breakdown recorded on a
// vuln_scan_completed audit event.
//
// The three coverage buckets partition the modules — analysed + unscannable +
// failed == total — and affected counts across all three, because a module can
// report an advisory whether or not its source was ever read. They are two
// independent tallies, not four slices of one, which is why affected is not part
// of the sum: counting a coordinate-matched module as analysed on the strength of
// its summary word is how a run came to report full coverage of a module nothing
// was analysed in.
// clean is the intersection — analysed and reporting nothing, the only real
// all-clear — kept beside them because it is what the audit event has always
// meant by "clean" and the one number that must not quietly start including
// modules that were never read.
type scanCounts struct {
	affected, analysed, clean, unscannable, failed int
	// withdrawn counts analysed modules whose every matched advisory was retracted
	// upstream. It is its own tally rather than a share of clean, so a run cannot
	// report "N clean" for modules that were reported affected until the retraction
	// was read. Such a module is not affected, so it does not degrade the run's
	// findings word; it is reported so the transition is visible rather than silent.
	withdrawn int
}

// tallyModuleResults walks the per-module results in deterministic allCoords
// order, persisting a StatusScanFailed record for any worker error, recording
// each module's content hash in run.PerModuleResults, driving Progress, and
// accumulating the status breakdown. It advances *progressCount in place.
//
// It returns an error when a StatusScanFailed record could not be stored: the
// counts it has accumulated so far describe modules whose verdicts are in the
// store, and returning them beside an unstored one would let the run summarise a
// module it did not keep.
func (uc *ScanWalkUseCase) tallyModuleResults(
	ctx context.Context,
	allCoords []coordinate.ModuleCoordinate,
	finalResults map[coordinate.ModuleCoordinate]moduleResult,
	run *domain.WalkScanRun,
	params ScanWalkParams,
	snapshot *domain.DatabaseSnapshot,
	progressCount *int,
	total int,
) (scanCounts, error) {
	var counts scanCounts
	for _, coord := range allCoords {
		r := finalResults[coord]
		*progressCount++
		if r.err != nil {
			uc.logger.Error("failed to scan module in walk", "walk_id", params.WalkID, "module", r.coord, "error", r.err)
			counts.failed++
			// No ArtefactIdentity: the worker failed before reaching a verdict, so
			// this record reports an outcome of the run rather than a reading of any
			// artefact. Naming one would claim bytes were analysed that were not.
			failedRecord := domain.VulnerabilityRecord{
				Ecosystem:        fetchdomain.EcosystemGo,
				Coordinate:       r.coord,
				WalkID:           params.WalkID,
				OverallStatus:    domain.StatusScanFailed,
				ErrorDetail:      r.err.Error(),
				DatabaseSnapshot: *snapshot,
				ScannedAt:        uc.clock.Now(),
				PipelineVersion:  uc.pipelineVersion,
				// A worker error only ever comes from the isolated scan pool — the
				// target-rooted paths return their own records and never an error here —
				// so this failure is a failure of the isolated analysis, and states that
				// frame rather than leaving it unrecorded.
				Rooting: domain.RootingIsolated,
				// The isolated pool resolves from the artefacts kanonarion fetched;
				// nothing routes it at a vendored tree, so the surface is not the
				// run's but this path's own, and it is fetched by construction.
				AnalysisSurface: domain.AnalysisSurfaceFetched,
			}
			var perr error
			failedRecord, perr = uc.persistSealed(ctx, failedRecord, "ScanFailed")
			if perr != nil {
				return counts, perr
			}
			run.PerModuleResults[r.coord] = failedRecord.ContentHash
			if params.Progress != nil {
				params.Progress(r.coord, failedRecord, *progressCount, total)
			}
			continue
		}

		run.PerModuleResults[r.coord] = r.record.ContentHash
		// Tallied per axis. Reading the collapsed word counted a coordinate-matched
		// module as analysed — the word says Affected, and Affected was an analysed
		// bucket — so a run whose modules were never read reported full coverage of
		// them. The findings tally is independent and counts the same module again
		// when it reports both.
		coverage, findings := domain.RecordAxes(r.record)
		if findings == domain.FindingsRecordAffected {
			counts.affected++
		}
		switch coverage {
		case domain.CoverageAnalysed:
			counts.analysed++
			// Clean is the narrow word here, not "everything that is not Affected". A
			// module whose only advisories were retracted reports Withdrawn, and
			// counting it clean would fold the retraction back into the all-clear tally
			// and lose the reason it is being kept out of.
			if findings == domain.FindingsRecordClean {
				counts.clean++
			}
			if findings == domain.FindingsRecordWithdrawn {
				counts.withdrawn++
			}
		case domain.CoverageFailedScan:
			counts.failed++
		case domain.CoverageUnscannable:
			counts.unscannable++
		default:
			// A coverage value outside the known set must not vanish from the counts.
			// The coverage axis and the "N of T unanalysed" summary derive from
			// analysed+unscannable+failed == total, so a dropped module would silently
			// understate the unanalysed count and let the run over-claim completeness.
			// Surface it and count it as failed: the run cannot vouch for a verdict it
			// does not understand, and an unaccounted module must degrade coverage
			// rather than disappear.
			uc.logger.Error("module scan produced an unrecognised coverage status",
				"walk_id", params.WalkID, "module", r.coord, "coverage", coverage, "status", r.record.OverallStatus)
			counts.failed++
		}
		if params.Progress != nil {
			params.Progress(r.coord, r.record, *progressCount, total)
		}
	}
	return counts, nil
}

// emitAuditEvents appends one vuln_finding_observed event per finding (in
// deterministic coordinate then finding-id order) followed by one
// vuln_scan_completed summary event. A nil audit sink disables emission.
// Findings are read from finalResults in allCoords order; local-replace nodes
// are Unscannable and carry no findings, so they contribute only to the count.
func (uc *ScanWalkUseCase) emitAuditEvents(
	run domain.WalkScanRun,
	allCoords []coordinate.ModuleCoordinate,
	finalResults map[coordinate.ModuleCoordinate]moduleResult,
	counts scanCounts,
) error {
	if uc.audit == nil {
		return nil
	}
	for _, coord := range allCoords {
		r := finalResults[coord]
		if r.err != nil {
			continue
		}
		for _, f := range r.record.Findings {
			ev := findingObservedEvent(coord, f.ID, r.record.OverallStatus)
			if err := uc.audit.RecordEvent(ev); err != nil {
				return fmt.Errorf("recording vuln finding audit event: %w", err)
			}
		}
	}
	if err := uc.audit.RecordEvent(scanCompletedEvent(run, counts)); err != nil {
		return fmt.Errorf("recording vuln scan audit event: %w", err)
	}
	return nil
}

// scanCompletedEvent builds the summary envelope for a completed scan run.
func scanCompletedEvent(run domain.WalkScanRun, counts scanCounts) audit.Event {
	return audit.Event{
		Type: audit.EventVulnScanCompleted,
		Payload: map[string]any{
			"walk_id":          run.WalkID,
			"scan_id":          run.ID,
			"snapshot_source":  run.Snapshot.Source(),
			"snapshot_version": run.Snapshot.Version(),
			"overall_status":   string(run.OverallStatus),
			"affected":         counts.affected,
			"clean":            counts.clean,
			"withdrawn":        counts.withdrawn,
			"unscannable":      counts.unscannable,
			"failed":           counts.failed,
		},
	}
}

// findingObservedEvent builds the envelope for a single observed finding.
func findingObservedEvent(coord coordinate.ModuleCoordinate, vulnID string, status domain.VulnerabilityStatus) audit.Event {
	return audit.Event{
		Type: audit.EventVulnFindingObserved,
		Payload: map[string]any{
			"module":         coord.Path(),
			"version":        coord.Version(),
			"vuln_id":        vulnID,
			"overall_status": string(status),
		},
	}
}

// recordLocalReplaceUnscannable persists a StatusUnscannable VulnerabilityRecord
// for each local-replace node and returns the count added to unscannableCount.
// Extracted from Scan to keep its cyclomatic complexity below the lint budget.
//
// A node whose record could not be stored fails the run rather than being
// counted: the count is what the summary reports as unscannable-and-recorded,
// and incrementing it for a record the store refused would claim a row that is
// not there.
func (uc *ScanWalkUseCase) recordLocalReplaceUnscannable(
	ctx context.Context,
	nodes []walkdomain.GraphNode,
	run *domain.WalkScanRun,
	params ScanWalkParams,
	snapshot *domain.DatabaseSnapshot,
	runSurface domain.AnalysisSurface,
	progressCount *int,
	total int,
) (int, error) {
	added := 0
	for _, node := range nodes {
		*progressCount++
		// No ArtefactIdentity: a local-replace node is unscannable precisely
		// because it is a working tree rather than a fetched artefact.
		//
		// The frame is unrecorded, and it is stated so rather than left off. No
		// analysis was rooted anywhere for this node: it is excluded from the scan
		// pool and from the target-rooted build alike, so naming a frame would
		// claim an analysis that was never attempted. Writing the constant makes
		// that a decision at the site rather than a field someone forgot.
		rec := domain.VulnerabilityRecord{
			Rooting: domain.RootingUnrecorded,
			// The surface is the run's, not this node's. No analysis was rooted
			// anywhere for a local-replace node, so it read no bytes from either
			// copy — but the record still has to be legible beside the rest of the
			// run's, and a blank field would read as one written before the field
			// existed rather than as this deliberate exclusion.
			AnalysisSurface:   runSurface,
			Ecosystem:         fetchdomain.EcosystemGo,
			Coordinate:        node.Coordinate,
			WalkID:            params.WalkID,
			OverallStatus:     domain.StatusUnscannable,
			UnscanReason:      domain.UnscanReasonLocalReplace,
			UnscannableReason: domain.LocalReplaceUnscannableReason(node.LocalPath),
			DatabaseSnapshot:  *snapshot,
			ScannedAt:         uc.clock.Now(),
			PipelineVersion:   uc.pipelineVersion,
		}
		var perr error
		rec, perr = uc.persistSealed(ctx, rec, "local-replace Unscannable")
		if perr != nil {
			return added, perr
		}
		added++
		run.PerModuleResults[node.Coordinate] = rec.ContentHash
		if params.Progress != nil {
			params.Progress(node.Coordinate, rec, *progressCount, total)
		}
	}
	return added, nil
}

// resolveWorkerCount sizes the module-scan pool.
//
// A non-zero requested count is an operator override and is returned unchanged:
// the operator is assumed to know their host, and silently shrinking an
// explicit --workers would make the flag lie.
//
// Otherwise the cap is max(1, min(NumCPU, cpuWorkerCap, available /
// perWorkerBudgetBytes)). The memory term is what stops a pool of large
// source-mode scans from exhausting the host and being OOM-killed, which does
// not report a slow scan — it reports every module as unanalysed. The floor of
// 1 is deliberate: a host too small for even one budgeted worker still gets a
// scan attempted, because a single govulncheck that might survive is a better
// answer than a pool of zero that certainly reports nothing.
//
// A memory reading that cannot be taken is never fatal. It degrades to the
// CPU-only cap and says so at debug, because an unreadable /proc is the normal
// case on every host that is not Linux and must not read as a fault.
//
// The budget is per-process. Two kanonarion runs on one host each measure the
// same free memory and each admit a full pool against it, so they can still
// exhaust it between them; that is documented in the inspect command's help
// rather than coordinated here, which would need a lock outside this process.
func (uc *ScanWalkUseCase) resolveWorkerCount(requested int) int {
	if requested > 0 {
		return requested
	}
	cpuCap := min(runtime.NumCPU(), cpuWorkerCap)
	if uc.hostMemory == nil {
		uc.logger.Debug("no host-memory reporter wired; sizing module scan pool by CPU alone",
			"workers", cpuCap)
		return cpuCap
	}
	available, err := uc.hostMemory.AvailableBytes()
	if err != nil {
		uc.logger.Debug("available memory unreadable; sizing module scan pool by CPU alone",
			"workers", cpuCap, "error", err)
		return cpuCap
	}
	// uint64 division, then a bounded conversion: min caps the quotient at cpuCap
	// (at most cpuWorkerCap, 4) before it is narrowed, so the result fits an int
	// on every platform regardless of how much memory the host reports.
	budgeted := available / perWorkerBudgetBytes
	workers := max(1, int(min(budgeted, uint64(cpuCap)))) // #nosec G115 -- min bounds the value by cpuWorkerCap before conversion.
	if workers < cpuCap {
		uc.logger.Info("module scan workers capped by available memory",
			"available_bytes", available,
			"per_worker_budget_bytes", perWorkerBudgetBytes,
			"workers", workers,
			"cpu_cap", cpuCap)
	}
	return workers
}

// runScanPool dispatches coordSlice to a bounded worker pool and returns all results.
// cgSem is a shared semaphore that limits concurrent callgraph subprocess spawns.
func (uc *ScanWalkUseCase) runScanPool(
	ctx context.Context,
	coordSlice []coordinate.ModuleCoordinate,
	workers int,
	cgSem chan struct{},
	params ScanWalkParams,
	snapshot *domain.DatabaseSnapshot,
	goModCache, vulnDBDir string,
	scanMode domain.ScanMode,
	knownVersions map[coordinate.ModuleCoordinate]struct{},
	selectedVersions map[coordinate.ModuleCoordinate]struct{},
) []moduleResult {
	ch := make(chan coordinate.ModuleCoordinate, len(coordSlice))
	for _, c := range coordSlice {
		ch <- c
	}
	close(ch)
	out := make(chan moduleResult, len(coordSlice))
	w := min(workers, len(coordSlice))
	var wg sync.WaitGroup
	for range w {
		// (*sync.WaitGroup).Go is standard library, added in Go 1.25; it performs
		// the Add(1)/Done() pairing itself. Static analysis has flagged this as a
		// non-existent method needing a rewrite to the pre-1.25 idiom — that is a
		// false positive against an older stdlib, and the go directive in go.mod
		// is the authority. Do not expand it back out.
		wg.Go(func() {
			for coord := range ch {
				rec, scanErr := uc.moduleScanner.Scan(ctx, ScanModuleParams{
					Coordinate:         coord,
					WalkID:             params.WalkID,
					Snapshot:           snapshot,
					Force:              params.Force,
					EnableReachability: params.EnableReachability,
					GoModCache:         goModCache,
					VulnDBDir:          vulnDBDir,
					ScanMode:           scanMode,
					CallGraphSem:       cgSem,
					KnownVersions:      knownVersions,
					SelectedVersions:   selectedVersions,
				})
				out <- moduleResult{coord: coord, record: rec, err: scanErr}
			}
		})
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	results := make([]moduleResult, 0, len(coordSlice))
	for r := range out {
		results = append(results, r)
	}
	return results
}

// prefetchMissing fetches any coordinates that are absent from the fact store.
// Errors are logged as warnings; individual failures do not abort the scan.
func (uc *ScanWalkUseCase) prefetchMissing(ctx context.Context, coords []coordinate.ModuleCoordinate) {
	if uc.fetcher == nil {
		return
	}
	for _, coord := range coords {
		if ctx.Err() != nil {
			return
		}
		fact, ok, err := uc.moduleScanner.getFetchRecord(ctx, coord)
		if err != nil {
			uc.logger.Warn("pre-fetch: error checking fact store", "module", coord, "error", err)
			continue
		}
		// A go.mod-only record holds no zip, so it does not satisfy the source a
		// scan needs. Re-fetch the full artefact; Execute upgrades the record in
		// place. Only a record with a zip lets us skip the fetch.
		if ok && !fact.IsGoModOnly() {
			continue
		}
		uc.logger.Info("pre-fetch: fetching missing module", "module", coord)
		if ferr := uc.fetcher.FetchModule(ctx, coord); ferr != nil {
			uc.logger.Warn("pre-fetch: failed to fetch module", "module", coord, "error", ferr)
		}
	}
}

// prefetchGoModOnly fetches the go.mod — and only the go.mod — of any coordinate
// absent from the fact store. It is the go.mod closure's fetch callback: those
// versions exist in the scan cache purely so the toolchain can read their
// requirements while rebuilding a module graph, never to be compiled, so
// downloading their zips (as prefetchMissing does) is discarded work. Any
// existing record — full or go.mod-only — already carries the go.mod, so its
// coordinate is skipped. Errors are logged as warnings; individual failures do
// not abort the scan.
func (uc *ScanWalkUseCase) prefetchGoModOnly(ctx context.Context, coords []coordinate.ModuleCoordinate) {
	if uc.fetcher == nil {
		return
	}
	for _, coord := range coords {
		if ctx.Err() != nil {
			return
		}
		_, ok, err := uc.moduleScanner.getFetchRecord(ctx, coord)
		if err != nil {
			uc.logger.Warn("pre-fetch(go.mod-only): error checking fact store", "module", coord, "error", err)
			continue
		}
		if ok {
			continue
		}
		uc.logger.Info("pre-fetch(go.mod-only): fetching missing module go.mod", "module", coord)
		if ferr := uc.fetcher.FetchModuleGoMod(ctx, coord); ferr != nil {
			uc.logger.Warn("pre-fetch(go.mod-only): failed to fetch module go.mod", "module", coord, "error", ferr)
		}
	}
}

// populatePrePruningGoMods supplies the go.mod files a pre-pruning module needs
// to rebuild its module graph offline.
//
// The traversal is rooted at the pre-pruning (go<1.17) nodes and follows their
// requirements transitively, writing the go.mod of any version the cache does
// not already hold. Rooting is the whole point. Only a pre-pruning MAIN module
// makes the toolchain load the complete, unpruned module graph; a module on
// go1.17 or later reads a pruned graph that the selected versions already
// satisfy. Seeding instead from the walk's superseded requirements and expanding
// outwards has no root and no stopping condition tied to what any module
// actually reads: on a 285-node graph that reaches 2431 versions and fetches
// 2345, where rooting at the 136 pre-pruning modules needs 249.
//
// Traversal continues THROUGH versions already in the cache, because a selected
// version's go.mod is how a deeper missing version is reached; it is simply not
// rewritten. Only go.mod files are written, never zips — a version reached this
// way is read for module-graph arithmetic and never compiled.
//
// Best-effort throughout: a failure degrades to that one version being
// unresolvable offline, which is reported rather than swallowed.
func (uc *ScanWalkUseCase) populatePrePruningGoMods(ctx context.Context, graph walkdomain.Graph, cacheDir string) {
	roots := uc.prePruningNodes(ctx, graph)
	if len(roots) == 0 {
		uc.logger.Debug("no pre-pruning module in graph; skipping module-graph go.mod population",
			"nodes", len(graph.Nodes))
		return
	}

	// Seed with the superseded versions those modules require, alongside the
	// modules themselves. The walk's edges record that requirement independently
	// of the go.mod text, so a root whose go.mod is unreadable still contributes
	// the versions the walk already knows it needs.
	rootSet := make(map[coordinate.ModuleCoordinate]struct{}, len(roots))
	for _, r := range roots {
		rootSet[r] = struct{}{}
	}
	edgeSeeds := graph.SupersededRequirementsFrom(rootSet)
	seeds := make([]coordinate.ModuleCoordinate, 0, len(roots)+len(edgeSeeds))
	seeds = append(seeds, roots...)
	seeds = append(seeds, edgeSeeds...)

	report := modcache.PopulateGoModClosure(
		ctx, uc.moduleScanner.factStore, uc.moduleScanner.blobs, cacheDir,
		seeds,
		func(ctx context.Context, batch []coordinate.ModuleCoordinate) { uc.prefetchGoModOnly(ctx, batch) },
	)
	uc.logger.Info("populated pre-pruning module-graph go.mod files for offline resolution",
		"written", report.Written, "reached", report.Requested, "roots", len(roots))
	if !report.Complete() {
		// Under GOPROXY=off there is no network fallback, so a hole here is the
		// difference between a module that resolves and one that is recorded as
		// a coverage gap. Name it rather than leaving the gap to be rediscovered
		// later as an unexplained resolution failure.
		uc.logger.Warn("incomplete pre-pruning go.mod set; modules needing these versions will fail to resolve offline",
			"written", report.Written, "reached", report.Requested,
			"failures", report.FailureSummary(populateFailureLogLimit))
	}
}

// populateScannedBuildListDeps supplies the module-graph metadata a scannable
// node's own isolated build list needs but the walk graph does not record.
//
// A node scanned in isolation is its own main module, and the toolchain rebuilds
// that module's build list from its published go.mod. That go.mod names versions
// the walk's MVS superseded or pruned away — golang.org/x/oauth2, for instance,
// requires cloud.google.com/go/compute v1.20.1 as an indirect dependency while
// the walk selected no cloud.google.com/go/compute node at all. The walk graph
// carries an edge only between selected nodes, so neither Populate nor
// populatePrePruningGoMods reaches these versions, and under GOPROXY=off the
// isolated scan then fails to resolve a version the store already holds.
//
// Two kinds of entry are supplied, matching exactly what the toolchain reads:
//
//   - the go.mod of every module a scannable node directly requires, for the
//     -mod=mod module-graph reconstruction: a pruned main module reads the
//     go.mod of each entry in its own require block (direct and indirect) to
//     rebuild the pruned graph; and
//   - the full source of any required module whose path is a proper ancestor of
//     another path in the node's build list — either another required module
//     (sibling-nested: cloud.google.com/go/compute is an ancestor of the also-
//     required cloud.google.com/go/compute/metadata) or the scanned node's own
//     module path (self-nested: google.golang.org/genproto is an ancestor of the
//     scanned google.golang.org/genproto/googleapis/rpc). Resolving an import
//     under the nested path makes the toolchain read the ancestor module's
//     source to confirm the ancestor does not itself provide the package, so the
//     ancestor needs its zip, not merely its go.mod. This is why an isolated
//     oauth2 scan fails naming the metadata import even though metadata's own
//     source is cached: the absent source is the parent module the toolchain
//     consults to disambiguate.
//
// Populates are idempotent — a coordinate already written as a selected node is
// skipped — so the common case where a required version is itself a selected
// node costs a stat, not a rewrite. Best-effort throughout: a version whose fact
// record or blob is missing degrades to that one version being unresolvable
// offline, which the population report names rather than swallows.
func (uc *ScanWalkUseCase) populateScannedBuildListDeps(ctx context.Context, coords []coordinate.ModuleCoordinate, cacheDir string) {
	goModSet := make(map[coordinate.ModuleCoordinate]struct{})
	sourceSet := make(map[coordinate.ModuleCoordinate]struct{})
	for _, node := range coords {
		requires, ok := uc.nodeGoModRequires(ctx, node)
		if !ok {
			continue
		}
		for _, r := range requires {
			goModSet[r] = struct{}{}
		}
		// A required module whose path is a proper ancestor of another path in
		// the build list needs its source, not just its go.mod: resolving an
		// import under the nested path makes the toolchain read the ancestor's
		// source to confirm the ancestor does not itself provide the package.
		// The nested descendant can be another required module (sibling-nested,
		// e.g. grpc requiring both cloud.google.com/go/compute and
		// .../compute/metadata) or the scanned node's own module path
		// (self-nested, e.g. google.golang.org/genproto/googleapis/rpc requiring
		// its own ancestor google.golang.org/genproto). Both make the toolchain
		// read the ancestor's source, so both seed the source set.
		for _, a := range requires {
			if strings.HasPrefix(node.Path(), a.Path()+"/") {
				sourceSet[a] = struct{}{}
			}
			for _, b := range requires {
				if a != b && strings.HasPrefix(b.Path(), a.Path()+"/") {
					sourceSet[a] = struct{}{}
				}
			}
		}
	}
	// A module supplied as source already carries its go.mod, so drop it from the
	// go.mod-only set rather than populate it twice.
	for c := range sourceSet {
		delete(goModSet, c)
	}
	if len(goModSet) == 0 && len(sourceSet) == 0 {
		return
	}

	if len(sourceSet) > 0 {
		src := coordSetSlice(sourceSet)
		uc.prefetchMissing(ctx, src)
		report := modcache.Populate(ctx, uc.moduleScanner.factStore, uc.moduleScanner.blobs, cacheDir, src)
		uc.logger.Info("populated nested-ancestor module sources for offline resolution",
			"written", report.Written, "requested", report.Requested)
		if !report.Complete() {
			uc.logger.Warn("some nested-ancestor sources could not be populated; imports under those paths may fail to resolve offline",
				"written", report.Written, "requested", report.Requested,
				"failures", report.FailureSummary(populateFailureLogLimit))
		}
	}
	if len(goModSet) > 0 {
		mods := coordSetSlice(goModSet)
		uc.prefetchGoModOnly(ctx, mods)
		report := modcache.PopulateGoMod(ctx, uc.moduleScanner.factStore, uc.moduleScanner.blobs, cacheDir, mods)
		uc.logger.Info("populated scanned-node build-list go.mod files for offline resolution",
			"written", report.Written, "requested", report.Requested)
		if !report.Complete() {
			uc.logger.Warn("some build-list go.mod files could not be populated; modules requiring these versions may fail to resolve offline",
				"written", report.Written, "requested", report.Requested,
				"failures", report.FailureSummary(populateFailureLogLimit))
		}
	}
}

// readNodeGoMod fetches and parses a node's stored go.mod. The bool is false
// when no go.mod could be read or parsed, so both callers rest on positive
// evidence rather than on an assumed-empty file.
func (uc *ScanWalkUseCase) readNodeGoMod(ctx context.Context, coord coordinate.ModuleCoordinate) (*modfile.File, bool) {
	fact, ok, err := uc.moduleScanner.getFetchRecord(ctx, coord)
	if err != nil || !ok {
		return nil, false
	}
	goModIdentity, hasGoMod, err := fetchports.GoModIdentity(fact)
	if err != nil || !hasGoMod {
		return nil, false
	}
	rc, err := uc.moduleScanner.blobs.Get(ctx, goModIdentity)
	if err != nil {
		return nil, false
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, false
	}
	f, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return nil, false
	}
	return f, true
}

// nodeGoModRequires reads the require directives from a node's stored go.mod.
// The bool is false when no go.mod could be read or parsed; both direct and
// indirect requirements are returned, since a pruned main module's graph load
// reads the go.mod of every entry in its require block regardless of block.
func (uc *ScanWalkUseCase) nodeGoModRequires(ctx context.Context, coord coordinate.ModuleCoordinate) ([]coordinate.ModuleCoordinate, bool) {
	f, ok := uc.readNodeGoMod(ctx, coord)
	if !ok {
		return nil, false
	}
	out := make([]coordinate.ModuleCoordinate, 0, len(f.Require))
	for _, req := range f.Require {
		if req == nil {
			continue
		}
		// A require line the constructor rejects is not a module to populate for,
		// on the same terms as the empty path or version this skipped before.
		coord, err := coordinate.NewModuleCoordinate(req.Mod.Path, req.Mod.Version)
		if err != nil {
			continue
		}
		out = append(out, coord)
	}
	return out, true
}

// coordSetSlice flattens a coordinate set into a slice for the populate helpers.
func coordSetSlice(set map[coordinate.ModuleCoordinate]struct{}) []coordinate.ModuleCoordinate {
	out := make([]coordinate.ModuleCoordinate, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	return out
}

// prePruningNodes returns the graph's nodes that declare a pre-pruning (go<1.17)
// go directive — the modules whose isolated scan makes the toolchain load the
// full, unpruned module graph. Nodes with no readable go.mod are skipped rather
// than assumed pre-pruning, so the set rests on positive evidence.
func (uc *ScanWalkUseCase) prePruningNodes(ctx context.Context, graph walkdomain.Graph) []coordinate.ModuleCoordinate {
	var roots []coordinate.ModuleCoordinate
	for _, node := range graph.Nodes {
		goVersion, ok := uc.nodeGoVersion(ctx, node.Coordinate)
		if !ok {
			continue
		}
		if walkdomain.PrePruning(goVersion) {
			roots = append(roots, node.Coordinate)
		}
	}
	return roots
}

// nodeGoVersion reads the go directive from a node's stored go.mod. The bool is
// false when no go.mod could be read; it is true (with a possibly empty version)
// when the go.mod was read, so a module with no go directive is reported as an
// empty version — which PrePruning treats as pre-pruning.
func (uc *ScanWalkUseCase) nodeGoVersion(ctx context.Context, coord coordinate.ModuleCoordinate) (string, bool) {
	f, ok := uc.readNodeGoMod(ctx, coord)
	if !ok {
		return "", false
	}
	if f.Go == nil {
		return "", true
	}
	return f.Go.Version, true
}

// resolveSnapshot returns the snapshot to use for a scan.
// If pinned is non-nil it is used directly. Otherwise the snapshot is fetched
// from the network (fresh=true) or loaded from the store, falling back to the
// network if the store has none.
func (uc *ScanWalkUseCase) resolveSnapshot(ctx context.Context, pinned *domain.DatabaseSnapshot, fresh bool) (*domain.DatabaseSnapshot, error) {
	if pinned != nil {
		return pinned, nil
	}
	if fresh {
		uc.logger.Info("fresh fetch requested: fetching vulnerability database snapshot from network")
		return uc.fetchAndPersistSnapshot(ctx, "resolving fresh snapshot", "persisting fresh database snapshot")
	}
	cached, ok, err := uc.vulnStore.GetLatestDatabaseSnapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking cached snapshot: %w", err)
	}
	if ok {
		uc.logger.Debug("using cached vulnerability database snapshot", "version", cached.Version(), "retrieved_at", cached.RetrievedAt())
		return &cached, nil
	}
	uc.logger.Info("no cached snapshot: fetching vulnerability database snapshot from network")
	return uc.fetchAndPersistSnapshot(ctx, "resolving snapshot", "persisting database snapshot")
}

// fetchAndPersistSnapshot fetches a fresh snapshot from the database source and
// stores it. errFetch and errPersist are used as error message prefixes.
func (uc *ScanWalkUseCase) fetchAndPersistSnapshot(ctx context.Context, errFetch, errPersist string) (*domain.DatabaseSnapshot, error) {
	s, body, err := uc.moduleScanner.database.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errFetch, err)
	}
	if body != nil {
		defer func() { _ = body.Close() }()
		if err := uc.vulnStore.PutDatabaseSnapshot(ctx, s, body); err != nil {
			return nil, fmt.Errorf("%s: %w", errPersist, err)
		}
	}
	return &s, nil
}

// firstSnapshotIntegrityFailure returns the snapshot integrity failure a module
// scan hit, if any, walking the coordinates in their stable order so the same
// corruption always reports the same module rather than a map-iteration lottery.
//
// It reaches here only when the shared pre-extraction did not run or did not
// serve this scan; when it did, the abort has already happened upstream. Both
// are kept because the two paths reach the store independently, and a decision
// enforced at only one of them is enforced only while the other stays unused.
func firstSnapshotIntegrityFailure(
	coords []coordinate.ModuleCoordinate,
	results map[coordinate.ModuleCoordinate]moduleResult,
) error {
	for _, coord := range coords {
		if r, ok := results[coord]; ok && errors.Is(r.err, ports.ErrSnapshotIntegrity) {
			return fmt.Errorf("scanning %s: %w", coord, r.err)
		}
	}
	return nil
}

// preExtractVulnDB extracts the snapshot ZIP to a temp dir so all module scans
// in a walk share a single extraction. Returns the dir path (empty when the
// extraction could not be shared) and a cleanup function.
//
// A snapshot integrity failure is returned rather than logged. Every finding in
// the run is derived from this snapshot, and the run's records name it, so a run
// that cannot vouch for the snapshot must not produce findings that claim it.
// The other failures — absent, unreadable, no temp dir — leave the per-module
// extraction path to answer, which is what the fallback was written for.
//
// The extracted database is then counted, and the count decides two things.
//
// A database holding no advisories fails the run rather than scanning against
// it. govulncheck answers such a database with "No vulnerabilities found." and
// exit 0, so every module would come back Clean and the run would seal verdicts
// that consulted nothing — a confident negative derived from no analysis, and
// indistinguishable from a measured clean. This is a precondition failure and is
// reported as one: the operator asked for a measurement the supplied database
// cannot produce.
//
// A database holding advisories records how many onto the snapshot, which every
// record in the run then names. That is what lets a later reader tell a clean
// scan against six thousand advisories from a clean scan against three. The
// guard itself cannot make that distinction — a truncated database that still
// parses counts, and nothing in the directory says how many entries it ought to
// have had — so the count is carried to the reader rather than judged here.
//
// A directory that was extracted and then could not be counted fails the run
// too. It is not the absent-snapshot case the fallback was written for: the
// bytes are here and unreadable, which is a fact worth stopping on rather than
// quietly re-extracting per module.
func (uc *ScanWalkUseCase) preExtractVulnDB(ctx context.Context, snapshot *domain.DatabaseSnapshot) (string, func(), error) {
	noop := func() {}
	content, err := uc.vulnStore.GetDatabaseSnapshot(ctx, *snapshot)
	if err != nil {
		if errors.Is(err, ports.ErrSnapshotIntegrity) {
			return "", noop, fmt.Errorf("pre-extracting the advisory database: %w", ports.SnapshotIntegrityAbort(*snapshot, err))
		}
		uc.logger.Warn("failed to retrieve snapshot for pre-extraction, each module scan will extract independently", "error", err)
		return "", noop, nil
	}
	defer func() { _ = content.Close() }()

	dbDir, err := os.MkdirTemp("", "kanonarion-vulndb-*")
	if err != nil {
		uc.logger.Warn("failed to create temp dir for snapshot pre-extraction, each module scan will extract independently", "error", err)
		return "", noop, nil
	}
	cleanup := func() { _ = os.RemoveAll(dbDir) }

	if err := ziparchive.ExtractStream(content, dbDir); err != nil {
		uc.logger.Warn("failed to pre-extract snapshot, each module scan will extract independently", "error", err)
		cleanup()
		return "", noop, nil
	}

	count, err := vulndbdir.CountAdvisories(dbDir)
	if err != nil {
		cleanup()
		return "", noop, fmt.Errorf("measuring the pre-extracted advisory database: %w", err)
	}
	if count == 0 {
		cleanup()
		return "", noop, fmt.Errorf("pre-extracting the advisory database: %w", ports.EmptySnapshotAbort(*snapshot, count))
	}
	counted, err := snapshot.WithAdvisoryCount(count)
	if err != nil {
		cleanup()
		return "", noop, fmt.Errorf("recording the advisory count on the snapshot: %w", err)
	}
	*snapshot = counted

	uc.logger.Info("pre-extracted vulnerability database snapshot", "path", dbDir, "advisories", count)
	return dbDir, cleanup, nil
}

// persistSealed seals rec with its content hash and persists it, returning the
// record that was stored.
//
// A record that could not be sealed or written fails the run. It is the same
// rule the isolated module scanner already applies — it returns the write error
// to its caller rather than logging it — so all three write legs of the stage
// agree: a verdict the store did not accept is not a verdict the run may claim.
// Logging and continuing let a run report a progress line, a summary and a
// findings count for a module whose record was never stored, which reads to an
// operator as a measured module. The store is a shared precondition, not one
// module's bookkeeping: when it refuses one write it refuses them all, so
// carrying on buys no coverage and only delays the report.
//
// Both callers are paths that report an outcome of the run rather than a
// reading of an artefact — a worker that failed before reaching a verdict, and
// a local-replace node that is unscannable by construction. They seal all the
// same: the store refuses an unsealed record, and a record nothing can check is
// exactly the record a tamper would choose.
func (uc *ScanWalkUseCase) persistSealed(
	ctx context.Context,
	rec domain.VulnerabilityRecord,
	kind string,
) (domain.VulnerabilityRecord, error) {
	sealed, herr := domain.VulnerabilityRecordHasher{}.SetContentHash(rec)
	if herr != nil {
		return rec, fmt.Errorf("hashing %s vulnerability record for %s: %w", kind, rec.Coordinate, herr)
	}
	if perr := uc.vulnStore.PutVulnerabilityRecord(ctx, sealed); perr != nil {
		return sealed, fmt.Errorf("persisting %s vulnerability record for %s: %w", kind, sealed.Coordinate, perr)
	}
	return sealed, nil
}

// prepareModCache resolves the GOMODCACHE the scan's govulncheck runs against
// and returns it with a release function the caller must defer. An empty
// directory means no cache could be prepared and the toolchain will download
// what it needs; release is always non-nil.
func (uc *ScanWalkUseCase) prepareModCache(ctx context.Context, walk walkdomain.WalkRecord) (string, func()) {
	goModCache := ""
	release := func() {}
	if uc.realModcacheDir != "" {
		// --from-modcache: the caller's Go module cache already holds every
		// dependency (verified against go.sum by the build). Point govulncheck at
		// it directly — no temp cache, no blob reads, no network.
		goModCache = uc.realModcacheDir
		uc.logger.Info("using existing GOMODCACHE for scan", "dir", goModCache)
	} else if cacheDir, err := os.MkdirTemp("", "kanonarion-modcache-*"); err != nil {
		uc.logger.Warn("failed to create temp GOMODCACHE, govulncheck will download dependencies", "error", err)
	} else {
		// govulncheck workers run with GOMODCACHE=cacheDir and the Go toolchain
		// writes any downloaded entries read-only; modcache.Remove restores write
		// permission before deleting so the (potentially multi-GB) tree does not
		// leak in TMPDIR. Surface a removal failure rather than discarding it.
		release = func() {
			if rerr := modcache.Remove(cacheDir); rerr != nil {
				uc.logger.Warn("failed to remove temp GOMODCACHE", "error", rerr, "dir", cacheDir)
			}
		}
		// local-replace nodes have no remote artefact to populate the
		// modcache with; exclude them from prefetch and Populate.
		// local_analysed nodes DO have a FactRecord (local FS zip) and
		// are included so their source can be scanned.
		coords := make([]coordinate.ModuleCoordinate, 0, len(walk.Graph.Nodes))
		for _, node := range walk.Graph.Nodes {
			if node.ResolutionSource == walkdomain.ResolutionLocalReplace {
				continue
			}
			// The synthetic standard-library node ships with the toolchain and has
			// no proxy artefact; it is scanned from advisory metadata, so exclude it
			// from the module cache prefetch/populate.
			if node.ResolutionSource == walkdomain.ResolutionStdlib {
				continue
			}
			// The local main module (a project walk's root) has no proxy artefact
			// to populate the cache with; the project-rooted scan reads its live
			// working tree, not a stored blob. Skip it so pre-fetch does not
			// pointlessly query the proxy for an unpublishable @local coordinate.
			if node.Coordinate.IsLocal() {
				continue
			}
			coords = append(coords, node.Coordinate)
		}

		// Pre-fetch any modules that are missing from the fact store so Populate
		// has a complete set of blobs. Errors are logged as warnings to preserve
		// best-effort semantics.
		uc.prefetchMissing(ctx, coords)

		report := modcache.Populate(ctx, uc.moduleScanner.factStore, uc.moduleScanner.blobs, cacheDir, coords)
		if report.Written == 0 && report.Requested > 0 {
			uc.logger.Warn("failed to pre-populate GOMODCACHE, govulncheck will download dependencies",
				"requested", report.Requested, "failures", report.FailureSummary(populateFailureLogLimit))
		} else {
			goModCache = cacheDir
			uc.logger.Info("pre-populated GOMODCACHE from blob store",
				"modules", report.Written, "requested", report.Requested, "dir", cacheDir)
			if !report.Complete() {
				uc.logger.Warn("some modules could not be populated into the scan cache; their scans may fail to resolve offline",
					"written", report.Written, "requested", report.Requested,
					"failures", report.FailureSummary(populateFailureLogLimit))
			}
			// A pre-pruning (go<1.17) module makes the toolchain load its full,
			// unpruned module graph, reading go.mod files the selected-version
			// cache above omits. Supply those, rooted at the pre-pruning modules,
			// so the scan resolves fully offline instead of falling back to the
			// network for graph bookkeeping.
			uc.populatePrePruningGoMods(ctx, walk.Graph, cacheDir)

			// A pruned (go>=1.17) node scanned in isolation still reads its OWN
			// go.mod's require block, which names versions the walk's MVS
			// superseded or pruned away and that the graph records no edge to.
			// Supply those so the isolated scan resolves them offline.
			uc.populateScannedBuildListDeps(ctx, coords, cacheDir)
		}
	}
	return goModCache, release
}
