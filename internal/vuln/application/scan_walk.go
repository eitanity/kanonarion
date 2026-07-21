package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"sync"

	"golang.org/x/mod/modfile"

	"github.com/eitanity/kanonarion/internal/adapters/modcache"
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
}

// NewScanWalkUseCase returns a new ScanWalkUseCase.
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
	// Workers controls the module scan pool size. Zero means min(NumCPU, 4).
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
	// isolation. Empty on a coordinate-keyed walk, where the isolated path runs.
	ProjectDir string
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

	// 1. Walk Retrieval
	walk, err := uc.walkStore.GetWalk(ctx, params.WalkID)
	if err != nil {
		return domain.WalkScanRun{}, fmt.Errorf("retrieving walk %q: %w", params.WalkID, err)
	}

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
	run.Snapshot = *snapshot

	// 3a. Extract the vulnerability database snapshot once, shared across all module scans.
	vulnDBDir, cleanupDB := uc.preExtractVulnDB(ctx, snapshot)
	defer cleanupDB()

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

	workers := params.Workers
	if workers <= 0 {
		workers = min(runtime.NumCPU(), 4)
	}
	if workers > total {
		workers = total
	}

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

	scanPool := func(coordSlice []coordinate.ModuleCoordinate, scanMode domain.ScanMode) []moduleResult {
		return uc.runScanPool(ctx, coordSlice, workers, cgSem, params, snapshot, goModCache, vulnDBDir, scanMode, knownVersions)
	}

	// finalResults maps each coordinate to its definitive scan result.
	finalResults := make(map[coordinate.ModuleCoordinate]moduleResult, total)

	switch {
	case walk.Target.IsLocal() && params.ProjectDir != "":
		// A project walk is rooted at the local main module. Its verdict is the
		// project's resolved, pruned build — derive it from a single
		// project-rooted scan of the live working tree, not from re-scanning each
		// dependency in isolation (which re-selects versions the project never
		// builds and reports a self-inflicted version-not-in-toolchain gap).
		uc.logger.Info("project-rooted vuln scan", "walk_id", params.WalkID, "root", walk.Target, "project_dir", params.ProjectDir)
		uc.scanProjectRooted(ctx, walk, allCoords, params, snapshot, vulnDBDir, finalResults)
	case params.BinaryModePrePass:
		// Pass 1: fast binary-mode scan across all modules.
		uc.logger.Info("binary pre-pass: scanning all modules in binary mode", "count", total)
		pass1 := scanPool(allCoords, domain.ScanModeBinary)

		// Modules flagged Affected by binary mode need source-mode re-scan for call-graph precision.
		var needSourceScan []coordinate.ModuleCoordinate
		for _, r := range pass1 {
			if r.err == nil && r.record.OverallStatus == domain.StatusAffected {
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

	progressCount := 0
	counts := uc.tallyModuleResults(ctx, allCoords, finalResults, &run, params, snapshot, &progressCount, total)

	// emit a deterministic StatusUnscannable record for each
	// local-replace node so absence isn't silently dropped.
	counts.unscannable += uc.recordLocalReplaceUnscannable(ctx, localReplaceNodes, &run, params, snapshot, &progressCount, len(walk.Graph.Nodes))

	// 5. Overall Status Determination
	run.CompletedAt = uc.clock.Now()
	run.OverallStatus = domain.DetermineWalkScanStatus(
		counts.failed, counts.affected, counts.unscannable, len(walk.Graph.Nodes),
	)

	// 6. Hash & Persist
	hash, err := uc.computeContentHash(run)
	if err != nil {
		return domain.WalkScanRun{}, fmt.Errorf("hashing walk scan run: %w", err)
	}
	run.ContentHash = hash
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

// scanCounts is the overall module-count breakdown recorded on a
// vuln_scan_completed audit event.
type scanCounts struct {
	affected, clean, unscannable, failed int
}

// tallyModuleResults walks the per-module results in deterministic allCoords
// order, persisting a StatusScanFailed record for any worker error, recording
// each module's content hash in run.PerModuleResults, driving Progress, and
// accumulating the status breakdown. It advances *progressCount in place.
func (uc *ScanWalkUseCase) tallyModuleResults(
	ctx context.Context,
	allCoords []coordinate.ModuleCoordinate,
	finalResults map[coordinate.ModuleCoordinate]moduleResult,
	run *domain.WalkScanRun,
	params ScanWalkParams,
	snapshot *domain.DatabaseSnapshot,
	progressCount *int,
	total int,
) scanCounts {
	var counts scanCounts
	for _, coord := range allCoords {
		r := finalResults[coord]
		*progressCount++
		if r.err != nil {
			uc.logger.Error("failed to scan module in walk", "walk_id", params.WalkID, "module", r.coord, "error", r.err)
			counts.failed++
			failedRecord := domain.VulnerabilityRecord{
				Ecosystem:        fetchdomain.EcosystemGo,
				Coordinate:       r.coord,
				WalkID:           params.WalkID,
				OverallStatus:    domain.StatusScanFailed,
				ErrorDetail:      r.err.Error(),
				DatabaseSnapshot: *snapshot,
				ScannedAt:        uc.clock.Now(),
				PipelineVersion:  uc.pipelineVersion,
			}
			if perr := uc.vulnStore.PutVulnerabilityRecord(ctx, failedRecord); perr != nil {
				uc.logger.Error("failed to persist ScanFailed record", "module", r.coord, "error", perr)
			} else {
				run.PerModuleResults[r.coord] = ""
			}
			if params.Progress != nil {
				params.Progress(r.coord, failedRecord, *progressCount, total)
			}
			continue
		}

		run.PerModuleResults[r.coord] = r.record.ContentHash
		switch r.record.OverallStatus {
		case domain.StatusAffected:
			counts.affected++
		case domain.StatusScanFailed:
			counts.failed++
		case domain.StatusUnscannable:
			counts.unscannable++
		case domain.StatusClean:
			counts.clean++
		}
		if params.Progress != nil {
			params.Progress(r.coord, r.record, *progressCount, total)
		}
	}
	return counts
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
			"snapshot_source":  run.Snapshot.Source,
			"snapshot_version": run.Snapshot.Version,
			"overall_status":   string(run.OverallStatus),
			"affected":         counts.affected,
			"clean":            counts.clean,
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
			"module":         coord.Path,
			"version":        coord.Version,
			"vuln_id":        vulnID,
			"overall_status": string(status),
		},
	}
}

// recordLocalReplaceUnscannable persists a StatusUnscannable VulnerabilityRecord
// for each local-replace node and returns the count added to unscannableCount.
// Extracted from Scan to keep its cyclomatic complexity below the lint budget
func (uc *ScanWalkUseCase) recordLocalReplaceUnscannable(
	ctx context.Context,
	nodes []walkdomain.GraphNode,
	run *domain.WalkScanRun,
	params ScanWalkParams,
	snapshot *domain.DatabaseSnapshot,
	progressCount *int,
	total int,
) int {
	added := 0
	for _, node := range nodes {
		added++
		*progressCount++
		rec := domain.VulnerabilityRecord{
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
		if perr := uc.vulnStore.PutVulnerabilityRecord(ctx, rec); perr != nil {
			uc.logger.Error("failed to persist local-replace Unscannable record", "module", node.Coordinate, "error", perr)
		} else {
			run.PerModuleResults[node.Coordinate] = ""
		}
		if params.Progress != nil {
			params.Progress(node.Coordinate, rec, *progressCount, total)
		}
	}
	return added
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
) []moduleResult {
	ch := make(chan coordinate.ModuleCoordinate, len(coordSlice))
	for _, c := range coordSlice {
		ch <- c
	}
	close(ch)
	out := make(chan moduleResult, len(coordSlice))
	w := min(workers, len(coordSlice))
	var wg sync.WaitGroup
	for i := 0; i < w; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
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
				})
				out <- moduleResult{coord: coord, record: rec, err: scanErr}
			}
		}()
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
		_, ok, err := uc.moduleScanner.getFetchRecord(ctx, coord)
		if err != nil {
			uc.logger.Warn("pre-fetch: error checking fact store", "module", coord, "error", err)
			continue
		}
		if ok {
			continue
		}
		uc.logger.Info("pre-fetch: fetching missing module", "module", coord)
		if ferr := uc.fetcher.FetchModule(ctx, coord); ferr != nil {
			uc.logger.Warn("pre-fetch: failed to fetch module", "module", coord, "error", ferr)
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
		seeds, uc.moduleScanner.fetchPipelineVersion,
		func(ctx context.Context, batch []coordinate.ModuleCoordinate) { uc.prefetchMissing(ctx, batch) },
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
	fact, ok, err := uc.moduleScanner.getFetchRecord(ctx, coord)
	if err != nil || !ok || fact.GoModLocation == "" {
		return "", false
	}
	rc, err := uc.moduleScanner.blobs.Get(ctx, fetchports.BlobHandle(fact.GoModLocation))
	if err != nil {
		return "", false
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(rc)
	if err != nil {
		return "", false
	}
	f, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
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
		uc.logger.Debug("using cached vulnerability database snapshot", "version", cached.Version, "retrieved_at", cached.RetrievedAt)
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

// preExtractVulnDB extracts the snapshot ZIP to a temp dir so all module scans
// in a walk share a single extraction. Returns the dir path (empty on failure)
// and a cleanup function.
func (uc *ScanWalkUseCase) preExtractVulnDB(ctx context.Context, snapshot *domain.DatabaseSnapshot) (string, func()) {
	noop := func() {}
	content, err := uc.vulnStore.GetDatabaseSnapshot(ctx, *snapshot)
	if err != nil {
		uc.logger.Warn("failed to retrieve snapshot for pre-extraction, each module scan will extract independently", "error", err)
		return "", noop
	}
	defer func() { _ = content.Close() }()

	dbDir, err := os.MkdirTemp("", "kanonarion-vulndb-*")
	if err != nil {
		uc.logger.Warn("failed to create temp dir for snapshot pre-extraction, each module scan will extract independently", "error", err)
		return "", noop
	}
	cleanup := func() { _ = os.RemoveAll(dbDir) }

	if err := ziparchive.ExtractStream(content, dbDir); err != nil {
		uc.logger.Warn("failed to pre-extract snapshot, each module scan will extract independently", "error", err)
		cleanup()
		return "", noop
	}
	uc.logger.Info("pre-extracted vulnerability database snapshot", "path", dbDir)
	return dbDir, cleanup
}

func (uc *ScanWalkUseCase) computeContentHash(r domain.WalkScanRun) (string, error) {
	data, err := walkScanRunMarshal(r)
	if err != nil {
		return "", fmt.Errorf("marshalling walk scan run for content hash: %w", err)
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// walkScanRunMarshal is a seam over json.Marshal used to test the
// marshal-failure guard's wrapping and propagation logic. No field in
// WalkScanRun can currently make json.Marshal fail (no NaN/Inf floats, no
// unsupported types), so this proves the guard's error handling is correct,
// not that the guard is reachable with a real value today — it exists for
// the never-silent-failure invariant, not a known failure mode.
var walkScanRunMarshal = json.Marshal

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

		report := modcache.Populate(ctx, uc.moduleScanner.factStore, uc.moduleScanner.blobs, cacheDir, coords, uc.moduleScanner.fetchPipelineVersion)
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
		}
	}
	return goModCache, release
}
