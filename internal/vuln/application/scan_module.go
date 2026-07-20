package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// PipelineVersion identifies the vuln scan pipeline. It gates record reuse: a
// cached record is only reused when its PipelineVersion matches. It was bumped
// from "v1" when metadata-path findings began carrying advisory remediation
// detail (summary, affected range, fixed version, at-risk symbols) — cached
// metadata-only records from the old pipeline stored only the bare finding ID,
// so they are re-scanned and re-populated rather than served stale. It was
// bumped again to "v3" when scanner-reported Unscannable results (no go.mod,
// OOM kill) began routing through the OSV metadata path: a no-go.mod module
// cached under "v2" persisted a confident "no findings" even when advisories
// matched, so those records must be re-scanned rather than served stale. It was
// bumped to "v4" when a pre-populated GOMODCACHE began scanning with -mod=mod
// so the toolchain computes the go.sum entries a multi-module member's
// published go.sum omits for a cache-resolved sibling: modules cached under
// "v3" as Unscannable/missing-go-sum now resolve to a real source-level verdict
// and must be re-scanned rather than served stale. It was bumped to "v5" when
// the scan became hermetic (GOPROXY=off): resolution is pinned to the verified
// store, so a scan analyses only the versions the project's toolchain actually
// resolved, never a version fetched fresh from the network. Modules whose
// isolated build re-selects an out-of-toolchain version flip from a
// network-fabricated verdict to a truthful Unscannable (version-not-in-toolchain),
// so "v4" records must be re-scanned rather than served stale.
const PipelineVersion = "v5"

// ScanModuleUseCase orchestrates a single module's vulnerability scan.
type ScanModuleUseCase struct {
	factStore                 fetchports.FactStore
	blobs                     fetchports.BlobStore
	vulnStore                 ports.VulnerabilityStore
	walkStore                 walkports.WalkStore
	scanner                   ports.VulnerabilityScanner
	database                  ports.VulnerabilityDatabase
	reachability              ports.ReachabilityAnalyser
	callGraphLoader           ports.CallGraphLoader
	callGraphSpawner          ports.CallGraphSpawner
	clock                     fetchports.Clock
	pipelineVersion           string
	fetchPipelineVersion      string
	localFetchPipelineVersion string
	logger                    *slog.Logger
}

// NewScanModuleUseCase returns a new ScanModuleUseCase.
func NewScanModuleUseCase(
	factStore fetchports.FactStore,
	blobs fetchports.BlobStore,
	vulnStore ports.VulnerabilityStore,
	walkStore walkports.WalkStore,
	scanner ports.VulnerabilityScanner,
	database ports.VulnerabilityDatabase,
	reachability ports.ReachabilityAnalyser,
	clock fetchports.Clock,
	pipelineVersion string,
	fetchPipelineVersion string,
	logger *slog.Logger,
) *ScanModuleUseCase {
	return &ScanModuleUseCase{
		factStore:            factStore,
		blobs:                blobs,
		vulnStore:            vulnStore,
		walkStore:            walkStore,
		scanner:              scanner,
		database:             database,
		reachability:         reachability,
		clock:                clock,
		pipelineVersion:      pipelineVersion,
		fetchPipelineVersion: fetchPipelineVersion,
		logger:               logger,
	}
}

// WithCallGraphLoader sets the loader used to retrieve call graph records for
// reachability analysis. Returns the receiver for chaining.
func (uc *ScanModuleUseCase) WithCallGraphLoader(loader ports.CallGraphLoader) *ScanModuleUseCase {
	uc.callGraphLoader = loader
	return uc
}

// WithCallGraphSpawner sets the spawner used to run on-demand callgraph
// extraction subprocesses for modules with findings but no cached callgraph.
// Returns the receiver for chaining.
func (uc *ScanModuleUseCase) WithCallGraphSpawner(spawner ports.CallGraphSpawner) *ScanModuleUseCase {
	uc.callGraphSpawner = spawner
	return uc
}

// WithLocalFetchPipelineVersion sets the pipeline version under which locally
// ingested modules (local-replace targets and the project-walk root) persist
// their FactRecord, so their source is fully scanned instead of degrading to
// a metadata-only scan. Returns the receiver for chaining.
func (uc *ScanModuleUseCase) WithLocalFetchPipelineVersion(v string) *ScanModuleUseCase {
	uc.localFetchPipelineVersion = v
	return uc
}

// getFetchRecord looks up the FactRecord for coord under the fetch pipeline
// version first (a proxy-verified record always wins), then the local-ingest
// pipeline version.
func (uc *ScanModuleUseCase) getFetchRecord(ctx context.Context, coord coordinate.ModuleCoordinate) (fetchdomain.FactRecord, bool, error) {
	for _, v := range []string{uc.fetchPipelineVersion, uc.localFetchPipelineVersion} {
		if v == "" {
			continue
		}
		r, ok, err := uc.factStore.GetFetchRecord(ctx, coord, v)
		if err != nil {
			return fetchdomain.FactRecord{}, false, fmt.Errorf("checking fetch record (pipeline %s): %w", v, err)
		}
		if ok {
			return r, true, nil
		}
	}
	return fetchdomain.FactRecord{}, false, nil
}

// Preflight delegates to the underlying scanner's availability check so a
// walk-wide scan can fail fast before any expensive setup.
func (uc *ScanModuleUseCase) Preflight(ctx context.Context) error {
	if err := uc.scanner.Preflight(ctx); err != nil {
		return fmt.Errorf("scanner preflight: %w", err)
	}
	return nil
}

// ScanModuleParams defines the input for a module scan.
type ScanModuleParams struct {
	Coordinate         coordinate.ModuleCoordinate
	WalkID             string
	Snapshot           *domain.DatabaseSnapshot // nil = use latest
	Force              bool
	EnableReachability bool
	GoModCache         string          // pre-populated GOMODCACHE dir; empty = govulncheck downloads as needed
	VulnDBDir          string          // pre-extracted vuln DB dir; empty = extract from store on each call
	ScanMode           domain.ScanMode // source or binary; empty defaults to source
	// CallGraphSem is a shared semaphore that limits concurrent callgraph subprocess
	// spawns across all module scans in the same walk. nil means no concurrency limit.
	CallGraphSem chan struct{}
}

// Scan performs the scan.
func (uc *ScanModuleUseCase) Scan(ctx context.Context, params ScanModuleParams) (domain.VulnerabilityRecord, error) {
	// 1. Snapshot Resolution
	var snapshot domain.DatabaseSnapshot
	if params.Snapshot != nil {
		snapshot = *params.Snapshot
	} else {
		var err error
		var body io.ReadCloser
		snapshot, body, err = uc.database.Snapshot(ctx)
		if err != nil {
			return domain.VulnerabilityRecord{}, fmt.Errorf("getting latest database snapshot: %w", err)
		}
		if body != nil {
			defer func() { _ = body.Close() }()
			// Persist the snapshot if it's new
			if err := uc.vulnStore.PutDatabaseSnapshot(ctx, snapshot, body); err != nil {
				return domain.VulnerabilityRecord{}, fmt.Errorf("persisting database snapshot: %w", err)
			}
		}
	}

	// 2. Cache Check (T1: Memoization).
	if rec, handled, err := uc.tryReuseCachedRecord(ctx, params, snapshot); handled || err != nil {
		return rec, err
	}

	// 3. Dependency Check (T2: Structural Dependency)
	fact, ok, err := uc.getFetchRecord(ctx, params.Coordinate)
	if err != nil {
		return domain.VulnerabilityRecord{}, fmt.Errorf("getting fetch record: %w", err)
	}
	if !ok {
		// Module not in the blob store (e.g. a node from a shallow walk).
		// Fall back to OSV metadata: check module coordinates against the vuln DB
		// without govulncheck. Records marked metadata-only have no AffectedSymbols
		// and nil Reachable, signalling that call-graph analysis was not performed.
		// A coordinate with no matching advisory is a real answer here, so the
		// empty status is Clean.
		note := "metadata-only: module not fetched (shallow walk)"
		if params.Coordinate.Path == domain.StdlibModulePath {
			// The standard library is toolchain-provided, never fetched as a module.
			// Its advisories are resolved from OSV metadata by coordinate — the
			// definitive verdict for stdlib, not a coverage-gap fallback.
			note = "Go standard library (toolchain-provided); advisories resolved from OSV metadata by coordinate"
		}
		return uc.scanMetadataOnly(ctx, params, snapshot, note, "", domain.StatusClean)
	}

	// 3.5 Metadata-based Filtering (Optimization)
	// Check if this module or any of its dependencies have known vulnerabilities.
	if !params.Force {
		isVulnerable, err := uc.checkVulnerabilities(ctx, params.Coordinate, fact, params.WalkID)
		switch {
		case err == nil && !isVulnerable:
			uc.logger.Info("metadata check: no known vulnerabilities in module or dependencies, skipping heavy scan", "coordinate", params.Coordinate)
			now := uc.clock.Now()
			record := domain.VulnerabilityRecord{
				Ecosystem:        fetchdomain.EcosystemGo,
				Coordinate:       params.Coordinate,
				WalkID:           params.WalkID,
				Findings:         nil,
				OverallStatus:    domain.StatusClean,
				DatabaseSnapshot: snapshot,
				ScannedAt:        now,
				FirstScannedAt:   now,
				PipelineVersion:  uc.pipelineVersion,
			}
			hash, err := uc.computeContentHash(record)
			if err != nil {
				return domain.VulnerabilityRecord{}, fmt.Errorf("hashing clean record: %w", err)
			}
			record.ContentHash = hash
			if err := uc.vulnStore.PutVulnerabilityRecord(ctx, record); err != nil {
				return domain.VulnerabilityRecord{}, fmt.Errorf("persisting clean record: %w", err)
			}
			return record, nil
		case err != nil:
			uc.logger.Warn("metadata check failed, proceeding with full scan", "error", err)
		case isVulnerable:
			uc.logger.Info("metadata check: potential vulnerabilities found, proceeding with heavy scan", "coordinate", params.Coordinate)
		}
	}

	// 4. Source Retrieval
	blob, err := uc.blobs.Get(ctx, fetchports.BlobHandle(fact.ContentLocation))
	if err != nil {
		return domain.VulnerabilityRecord{}, fmt.Errorf("retrieving module content: %w", err)
	}
	defer func() { _ = blob.Close() }()

	// 5. Execution (T3: Deterministic Scan)
	record, err := uc.scanner.Scan(ctx, params.Coordinate, blob, snapshot, params.GoModCache, params.VulnDBDir, params.ScanMode)
	if err != nil {
		uc.logger.Error("vulnerability scan failed", "coordinate", params.Coordinate, "error", err)
		record = domain.VulnerabilityRecord{
			Coordinate:       params.Coordinate,
			OverallStatus:    domain.StatusScanFailed,
			ErrorDetail:      err.Error(),
			DatabaseSnapshot: snapshot,
		}
	} else {
		uc.logger.Info("vulnerability scan completed", "coordinate", params.Coordinate, "status", record.OverallStatus, "findings", len(record.Findings))
	}
	// Record identity is owned here, not by the scanner adapter: a record
	// persisted without Ecosystem is rejected fail-closed on every read
	// (VulnerabilityRecord.UnmarshalJSON), so stamp it on both branches.
	record.Ecosystem = fetchdomain.EcosystemGo
	record.WalkID = params.WalkID
	now := uc.clock.Now()
	record.ScannedAt = now
	// First-insert default; the store keeps the original on conflict so a force
	// re-scan never resets the first-seen anchor.
	record.FirstScannedAt = now
	record.PipelineVersion = uc.pipelineVersion

	// 5b. Coverage recovery: a source-mode failure caused by the module not
	// building under the host toolchain is not a scanner fault and must not be
	// left as a bare failure. Fall back to metadata-only matching so known
	// advisories are still attributed; when none match, record an Unscannable
	// coverage gap (never a clean) so the limitation is visible in roll-ups.
	if record.OverallStatus == domain.StatusScanFailed && domain.IsBuildIncompatibility(record.ErrorDetail) {
		category := domain.ClassifyBuildIncompatibility(record.ErrorDetail)
		reason := domain.StructuredUnscanReason(record.ErrorDetail)
		uc.logMetadataFallback(params.Coordinate, reason, category, record.ErrorDetail)
		note := "source analysis unavailable: " + category + "; results are metadata-only with no reachability"
		return uc.scanMetadataOnly(ctx, params, snapshot, note, reason, domain.StatusUnscannable)
	}

	// 5c. Scanner-side coverage gap: the scanner itself declared the module
	// Unscannable (no go.mod in the zip, OOM kill, …) and returned no findings.
	// Mirror the build-incompatibility fallback above so known advisories are
	// still attributed from OSV metadata rather than silently dropped — without
	// this routing, a no-go.mod module persists as a confident "no findings"
	// even when matching advisories exist. The empty status stays Unscannable
	// (a coverage gap, never a clean) so the missing-reachability caveat is
	// preserved, and the scanner's UnscanReason carries through unchanged.
	if record.OverallStatus == domain.StatusUnscannable {
		note := record.UnscannableReason
		if note == "" {
			note = "source analysis unavailable; results are metadata-only with no reachability"
		}
		uc.logger.Warn("vuln-scan: scanner reported unscannable, falling back to metadata",
			"coordinate", params.Coordinate, "reason", record.UnscanReason)
		return uc.scanMetadataOnly(ctx, params, snapshot, note, record.UnscanReason, domain.StatusUnscannable)
	}

	// 6. Reachability Analysis (T4: Conditional Static Analysis)
	if params.EnableReachability && uc.reachability != nil && uc.callGraphLoader != nil && len(record.Findings) > 0 {
		completeness, algorithm := uc.applyReachability(ctx, params, record.Findings)
		// Stamp the fidelity that backed these reachability verdicts so a later
		// scan-run diff can assert completeness parity before reporting a finding
		// resolved or a reachability flip as unaffected.
		record.CallGraphCompleteness = completeness
		record.CallGraphAlgorithm = algorithm
	}

	// 7. Deterministic Identity (T5: Hash-based Identity)
	hash, err := uc.computeContentHash(record)
	if err != nil {
		return domain.VulnerabilityRecord{}, fmt.Errorf("hashing vulnerability record: %w", err)
	}
	record.ContentHash = hash

	// 8. Durability (T6: Aggregate Persistence)
	if err := uc.vulnStore.PutVulnerabilityRecord(ctx, record); err != nil {
		return domain.VulnerabilityRecord{}, fmt.Errorf("persisting vulnerability record: %w", err)
	}

	return record, nil
}

// tryReuseCachedRecord serves a memoized record for this coordinate/snapshot
// when a usable one exists. handled is true when the caller should return
// (rec, err) directly; false means proceed with a fresh scan.
//
// A local coordinate (the project-walk root) is never served from cache: the
// working tree mutates between runs, so its records are recomputed fresh every
// time. ScanFailed is also never served from cache: it represents a transient
// infrastructure failure (govulncheck crash, temp dir cleaned up, network blip)
// not a stable analysis verdict — caching it would permanently block retry
// without --force. A store lookup error is treated as a cache miss.
func (uc *ScanModuleUseCase) tryReuseCachedRecord(ctx context.Context, params ScanModuleParams, snapshot domain.DatabaseSnapshot) (domain.VulnerabilityRecord, bool, error) {
	if params.Force || params.Coordinate.IsLocal() {
		return domain.VulnerabilityRecord{}, false, nil
	}
	rec, ok, err := uc.vulnStore.GetVulnerabilityRecord(ctx, params.Coordinate, uc.pipelineVersion, snapshot)
	if err != nil || !ok {
		return domain.VulnerabilityRecord{}, false, nil //nolint:nilerr // a lookup failure is treated as a cache miss; the scan proceeds fresh
	}
	if rec.OverallStatus == domain.StatusScanFailed {
		uc.logger.Debug("vulnerability scan cache miss: stored result is ScanFailed, retrying", "coordinate", params.Coordinate)
		return domain.VulnerabilityRecord{}, false, nil
	}
	uc.logger.Debug("vulnerability scan cache hit, re-attributing to current run", "coordinate", params.Coordinate, "status", rec.OverallStatus)
	// The cached verdict is reused, but its provenance must follow the run the
	// user actually invoked: re-stamp the walk reference and scan time so a later
	// query reflects this run, never the unrelated earlier walk that first
	// produced the record. The analysis result is unchanged; only walk_id and
	// scanned_at move forward. ContentHash is cleared before recompute so it is
	// hashed over an empty hash field, matching how fresh records are hashed.
	rec.WalkID = params.WalkID
	rec.ScannedAt = uc.clock.Now()
	rec.ContentHash = ""
	hash, err := uc.computeContentHash(rec)
	if err != nil {
		return domain.VulnerabilityRecord{}, false, fmt.Errorf("hashing reused vulnerability record: %w", err)
	}
	rec.ContentHash = hash
	if perr := uc.vulnStore.PutVulnerabilityRecord(ctx, rec); perr != nil {
		return domain.VulnerabilityRecord{}, false, fmt.Errorf("re-attributing reused vulnerability record: %w", perr)
	}
	rec.Reused = true
	return rec, true, nil
}

// logMetadataFallback records a source-mode-to-metadata fallback. An
// out-of-toolchain module is the expected outcome of a hermetic scan, not a
// coverage fault, so it logs at info level (and names reachability --local, the
// project-rooted answer); genuine build incompatibilities stay at warn.
func (uc *ScanModuleUseCase) logMetadataFallback(coord coordinate.ModuleCoordinate, reason domain.UnscanReason, category, detail string) {
	if reason.ExpectedOutOfToolchain() {
		uc.logger.Info("vuln-scan: metadata-only, version outside the project build (expected); use reachability --local for project-rooted reachability",
			"coordinate", coord)
		return
	}
	uc.logger.Warn("vuln-scan: source analysis unavailable, falling back to metadata",
		"coordinate", coord, "category", category, "detail", detail)
}

// scanMetadataOnly performs an OSV metadata-only vulnerability check by module
// coordinate, without building the module — used when source-mode analysis is
// not possible (the module was never fetched, or it does not build under the
// host toolchain). Findings carry the advisory's summary, affected range, fixed
// version and at-risk symbols, but a nil Reachable to signal that call-graph
// reachability was not computed. note records why the scan was metadata-only.
// emptyStatus is the status when no advisory matches: Clean when that is a
// genuine answer, or Unscannable when metadata is a fallback for a module that
// could not be analysed from source (a coverage gap, not a clean).
func (uc *ScanModuleUseCase) scanMetadataOnly(ctx context.Context, params ScanModuleParams, snapshot domain.DatabaseSnapshot, note string, unscanReason domain.UnscanReason, emptyStatus domain.VulnerabilityStatus) (domain.VulnerabilityRecord, error) {
	uc.logger.Info("vuln-scan: metadata-only", "coordinate", params.Coordinate, "reason", note)
	findings, err := uc.database.LookupFindings(ctx, params.Coordinate)
	if err != nil {
		return domain.VulnerabilityRecord{}, fmt.Errorf("metadata check for %s: %w", params.Coordinate, err)
	}

	status := emptyStatus
	if len(findings) > 0 {
		status = domain.StatusAffected
	}

	now := uc.clock.Now()
	record := domain.VulnerabilityRecord{
		Ecosystem:         fetchdomain.EcosystemGo,
		Coordinate:        params.Coordinate,
		WalkID:            params.WalkID,
		Findings:          findings,
		OverallStatus:     status,
		UnscanReason:      unscanReason,
		UnscannableReason: note,
		DatabaseSnapshot:  snapshot,
		ScannedAt:         now,
		FirstScannedAt:    now,
		PipelineVersion:   uc.pipelineVersion,
	}
	hash, err := uc.computeContentHash(record)
	if err != nil {
		return domain.VulnerabilityRecord{}, fmt.Errorf("hashing metadata-only record: %w", err)
	}
	record.ContentHash = hash
	if perr := uc.vulnStore.PutVulnerabilityRecord(ctx, record); perr != nil {
		return domain.VulnerabilityRecord{}, fmt.Errorf("persisting metadata-only record: %w", perr)
	}
	return record, nil
}

func (uc *ScanModuleUseCase) computeContentHash(r domain.VulnerabilityRecord) (string, error) {
	// FirstScannedAt is first-seen provenance, not part of the verdict, so it is
	// excluded from the canonical hash: a reused record whose ScannedAt advances
	// must not change identity on account of an anchor that never moves. r is a
	// value copy, so zeroing it here does not affect the persisted record.
	r.FirstScannedAt = time.Time{}
	// Canonical JSON hashing
	data, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("marshalling vulnerability record for content hash: %w", err)
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// applyReachability runs reachability analysis for each finding that has
// AffectedSymbols, spawning a callgraph subprocess on demand when needed.
// Findings with no AffectedSymbols are left untouched.
// applyReachability returns the call-graph fidelity (completeness level and
// algorithm/devirt tier) that backed the reachability verdicts, so the caller
// can record it for later diff-parity checks. Both are empty when no graph was
// consulted (spawn failed, or no finding carried symbols).
func (uc *ScanModuleUseCase) applyReachability(ctx context.Context, params ScanModuleParams, findings []domain.VulnerabilityFinding) (completeness, algorithm string) {
	spawnNote := uc.maybeEnsureCallGraph(ctx, params, findings)

	// Read the fidelity signature once from the projection; a reachability
	// verdict is only ever as sound as the graph it was computed over.
	if spawnNote == "" {
		if proj, lerr := uc.callGraphLoader.Load(ctx, params.Coordinate); lerr == nil {
			completeness, algorithm = proj.Completeness, proj.Algorithm
		}
	}

	for i, finding := range findings {
		syms := buildSymbolRefs(params.Coordinate.Path, finding.AffectedSymbols)
		if len(syms) == 0 {
			continue
		}
		if spawnNote != "" {
			findings[i].ReachabilityNote = spawnNote
			continue
		}
		result, rerr := uc.reachability.Analyse(ctx, params.Coordinate, syms, uc.callGraphLoader)
		if rerr != nil {
			uc.logger.Warn("reachability analysis failed", "coordinate", params.Coordinate, "finding", finding.ID, "error", rerr)
			continue
		}
		findings[i].Reachable = &result
	}
	return completeness, algorithm
}

// maybeEnsureCallGraph ensures a callgraph record is present in the store for
// params.Coordinate when any finding has symbol-level detail. It returns a
// non-empty failure note when an on-demand spawn was attempted and failed;
// callers must set ReachabilityNote on affected findings in that case.
//
// When the spawner is nil or no finding has AffectedSymbols, it returns "".
// When the store already has a record and force is false, it returns "" without
// spawning. The callgraph store is treated as an implementation detail of the
// loader; absence is detected via errors.Is(err, ports.ErrCallGraphNotFound).
func (uc *ScanModuleUseCase) maybeEnsureCallGraph(ctx context.Context, params ScanModuleParams, findings []domain.VulnerabilityFinding) string {
	if uc.callGraphSpawner == nil {
		return ""
	}

	hasSymbols := false
	for _, f := range findings {
		if len(f.AffectedSymbols) > 0 {
			hasSymbols = true
			break
		}
	}
	if !hasSymbols {
		return ""
	}

	if !params.Force {
		_, loadErr := uc.callGraphLoader.Load(ctx, params.Coordinate)
		if loadErr == nil {
			return "" // callgraph already in store
		}
		if !errors.Is(loadErr, ports.ErrCallGraphNotFound) {
			// Integrity or other store error — don't spawn over a broken record.
			uc.logger.Warn("callgraph store check failed before spawn", "coordinate", params.Coordinate, "error", loadErr)
			return fmt.Sprintf("callgraph store check failed: %v", loadErr)
		}
		// Not found — fall through to spawn.
	}

	// Acquire concurrency slot before spawning the SSA-heavy child process.
	if params.CallGraphSem != nil {
		select {
		case params.CallGraphSem <- struct{}{}:
			defer func() { <-params.CallGraphSem }()
		case <-ctx.Done():
			return "callgraph spawn cancelled: " + ctx.Err().Error()
		}
	}

	uc.logger.Info("spawning callgraph subprocess", "coordinate", params.Coordinate, "force", params.Force)
	stderr, spawnErr := uc.callGraphSpawner.Spawn(ctx, params.Coordinate, params.Force)
	if spawnErr != nil {
		note := buildCallGraphSpawnNote(spawnErr, stderr)
		uc.logger.Warn("callgraph subprocess failed", "coordinate", params.Coordinate, "note", note)
		return note
	}
	uc.logger.Info("callgraph subprocess succeeded", "coordinate", params.Coordinate)
	return ""
}

// buildCallGraphSpawnNote formats the ReachabilityNote for a failed callgraph
// subprocess, capturing the exec error and any stderr output.
func buildCallGraphSpawnNote(execErr error, stderr []byte) string {
	stderrStr := strings.TrimSpace(string(stderr))
	if stderrStr != "" {
		return fmt.Sprintf("callgraph subprocess failed (%v): %s", execErr, stderrStr)
	}
	return fmt.Sprintf("callgraph subprocess failed: %v", execErr)
}

// buildSymbolRefs converts short symbol strings from govulncheck (e.g.
// "FuncName" or "(*T).Method") into SymbolReference values scoped to module.
func buildSymbolRefs(module string, affectedSymbols []string) []ports.SymbolReference {
	refs := make([]ports.SymbolReference, 0, len(affectedSymbols))
	for _, sym := range affectedSymbols {
		refs = append(refs, ports.SymbolReference{Module: module, Symbol: sym})
	}
	return refs
}

func (uc *ScanModuleUseCase) checkVulnerabilities(ctx context.Context, coord coordinate.ModuleCoordinate, fact fetchdomain.FactRecord, walkID string) (bool, error) {
	// If walkID is empty, we can't look up dependencies in a walk graph.
	// This might happen during direct module scans outside a walk context.
	if walkID == "" || uc.walkStore == nil {
		vulns, err := uc.database.CheckVulnerable(ctx, []coordinate.ModuleCoordinate{coord})
		if err != nil {
			return true, fmt.Errorf("checking vulnerabilities: %w", err)
		}
		return len(vulns) > 0, nil
	}

	// 1. Get module dependencies
	walk, err := uc.walkStore.GetWalk(ctx, walkID)
	if err != nil {
		return true, fmt.Errorf("getting walk: %w", err)
	}

	// BFS from coord through graph edges to collect only the transitive
	// dependencies of this module, not every node in the walk.
	visited := map[coordinate.ModuleCoordinate]bool{coord: true}
	queue := []coordinate.ModuleCoordinate{coord}
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		for _, e := range walk.Graph.Edges {
			if e.From == curr && !visited[e.To] {
				visited[e.To] = true
				queue = append(queue, e.To)
			}
		}
	}
	deps := make([]coordinate.ModuleCoordinate, 0, len(visited))
	for c := range visited {
		deps = append(deps, c)
	}

	vulns, err := uc.database.CheckVulnerable(ctx, deps)
	if err != nil {
		return true, fmt.Errorf("checking vulnerabilities: %w", err)
	}

	return len(vulns) > 0, nil
}
