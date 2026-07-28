package application

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"golang.org/x/mod/modfile"

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
// so "v4" records must be re-scanned rather than served stale. It was bumped to
// "v6" when the scan environment began setting GOWORK=off: a module shipping a
// go.work in its published zip put the toolchain into workspace mode, which
// rejects the scan's -mod=mod and was recorded under "v5" as a misdiagnosed
// Unscannable/build-incompatible. Those modules now scan from source, so "v5"
// records must be re-scanned rather than served stale. It was bumped to "v7"
// when the hermetic cache began carrying the full transitive closure of
// superseded go.mod files: a pre-pruning (go<1.17) module needs that closure to
// load its module graph offline, and without it such modules were recorded under
// "v6" as metadata-only coverage gaps when they are in fact scannable from
// source. The same bump covers metadata-only records now retaining the
// originating toolchain error in error_detail, which "v6" records dropped. It
// was bumped to "v8" when a module zip carrying no go.mod began being scanned
// against a synthesised one: govulncheck's refusal is a precondition on the
// scan directory, not a property of the artefact, so modules recorded under
// "v7" as Unscannable/no-go-mod are in fact scannable from source and must be
// re-scanned rather than served stale. It was bumped to "v9" when advisory
// matching by coordinate became unconditional rather than a fallback from scan
// failure: a module scanned in isolation is govulncheck's main module and a main
// module has no version, so a successful source scan could never match an
// advisory about the module itself. Every "v8" Clean record produced by a
// successful scan is therefore an unchecked verdict rather than a confirmed one
// and must be re-scanned. It was bumped to "v10" when govulncheck's JSON stream
// began being framed by JSON value instead of by newline: govulncheck writes its
// messages indent-formatted, so a line-framed parse could never see a whole
// finding message and discarded every one of them. Every "v9" record was
// produced by a parse that reported no source findings at all — Clean verdicts
// that were never checked, and Affected verdicts missing their reachability and
// symbols — so all of them must be re-scanned. The same bump covers the
// project-rooted path, where advisory matching by coordinate is now
// unconditional rather than absent. It was bumped to "v11" when a
// coordinate-keyed walk began deriving its verdicts from a single scan rooted at
// the walk target instead of scanning each dependency in isolation: an isolated
// scan points `./...` at the dependency, loading every package it contains
// including ones no consumer can import, so a "v10" record could be a coverage
// gap caused by a package the target never builds, and its reachability was
// rooted at packages no consumer can reach. Every "v10" record on that path
// describes a different analysis and must be re-scanned. It was bumped to "v12"
// to correct the reachability of an advisory matched by coordinate on the walk
// target itself: the target is the versionless main module of the target-rooted
// analysis, which OSV matching structurally cannot reach a verdict on, so such a
// finding is now recorded with no reachability rather than a fabricated
// not-reachable/high-confidence. A "v11" record whose target is itself a
// vulnerable library carries that fabricated verdict and must be re-scanned; a
// walk whose target carries no advisory about itself is unaffected in content
// but re-scans under the new version like any other. It was bumped to "v13" when
// a version-not-in-toolchain verdict began being verified rather than asserted:
// the offline resolution failure's dominant shape attributes the failure to a
// source position and names no coordinate, so the incomplete-scan-cache check
// silently never ran and the reason was kept by default. Recovery now resolves
// the unimportable package to its module and reads the version the scanned
// module's own go.mod selects, and a failure whose version cannot be recovered
// is recorded as version-not-in-toolchain-unverified rather than an asserted
// out-of-toolchain outcome. A "v12" record on that path carries the unverified
// reason as if established and must be re-scanned. It was bumped to "v14" when
// the walk-scan aggregate gained separate coverage and findings axes: a
// WalkScanRun now stores CoverageStatus, FindingsStatus and the module counts
// alongside the collapsed OverallStatus, and a run recorded before the split
// carries neither axis, so a consumer that reads FindingsStatus off it silently
// loses the finding. The per-module record content is unchanged by this bump;
// the version moves so a walk scanned in the collapsed-status era re-runs as a
// whole and produces a run carrying both axes, rather than reusing cached
// per-module verdicts under a run that has neither. It was bumped to "v15" when
// two record-shape changes landed together, both of which alter the canonical
// bytes a record hashes over.
//
// First, the per-module record gained the same two verdict axes the walk-scan
// aggregate got at v14: CoverageStatus and FindingsStatus now sit beside the
// collapsed OverallStatus, whose four values answered two different questions.
// The projection is total and lossless, so a "v14" record loses nothing —
// migration 11 back-fills the columns and RecordAxes recovers the axes on read
// — but a record written from v15 onward carries them in its blob and therefore
// hashes differently.
//
// Second, DatabaseSnapshot.ContentHash is now populated. It was already part of
// the record's canonical shape and was empty on every record ever written, so
// the advisory database — the evidence every finding is derived from — was the
// one input to a verdict that could not be checked against the bytes it was
// reached from. Populating it changes stored record hashes; migration 10 seals
// the snapshot blobs the store already holds so an existing store can verify
// them too.
const PipelineVersion = "v15"

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

// metadataOnlyNote returns the note recorded on a metadata-only scan, naming why
// no source was analysed: the stdlib is toolchain-provided and resolved by
// coordinate; a go.mod-only record carries no source; otherwise the module was
// never fetched (a shallow walk).
func metadataOnlyNote(coord coordinate.ModuleCoordinate, goModOnly bool) string {
	switch {
	case coord.Path() == domain.StdlibModulePath:
		return "Go standard library (toolchain-provided); advisories resolved from OSV metadata by coordinate"
	case goModOnly:
		return "metadata-only: only go.mod fetched for module-graph resolution; module source not retrieved"
	default:
		return "metadata-only: module not fetched (shallow walk)"
	}
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
			return r.FactRecord, true, nil
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
	// KnownVersions is the set of module versions the walk knows this scan may
	// need: its nodes plus the superseded requirements recorded on its edges. It
	// discriminates the two ways an offline resolution can fail. A version in
	// this set was one kanonarion undertook to supply, so failing to resolve it
	// is an incomplete scan cache — a fault. A version outside it was selected by
	// the module's own isolated build and never belonged to the project's
	// toolchain, which is the expected consequence of hermetic scanning. Built
	// once per walk and read concurrently; never written during a scan. A nil map
	// disables the discrimination and every failure reads as out-of-toolchain,
	// preserving the behaviour of callers that scan without a graph.
	KnownVersions map[coordinate.ModuleCoordinate]struct{}
	// SelectedVersions is the set of module versions the walk actually fetched —
	// one per node, always the version the project's build selected. It seeds the
	// require directives of a go.mod synthesised for a module zip published
	// before Go modules, so the isolated scan resolves the project's own
	// versions. It is deliberately not KnownVersions: that set also carries the
	// coordinate a replaced node stands in for, which names a module whose source
	// was never fetched, and requiring it would fail every scan that used it.
	SelectedVersions map[coordinate.ModuleCoordinate]struct{}
}

// openModuleSource opens a module's zip for scanning, addressed by the artefact
// identity the record carries rather than by a handle read off it. Any store
// holding those bytes answers, whichever mode acquired them.
func (uc *ScanModuleUseCase) openModuleSource(ctx context.Context, fact fetchdomain.FactRecord) (io.ReadCloser, error) {
	zipIdentity, hasZip, err := fetchports.ZipIdentity(fact)
	if err != nil {
		return nil, fmt.Errorf("deriving zip address for %s: %w", fact.Coordinate(), err)
	}
	if !hasZip {
		return nil, fmt.Errorf("fact record for %s carries no module zip to scan", fact.Coordinate())
	}
	blob, err := uc.blobs.Get(ctx, zipIdentity)
	if err != nil {
		return nil, fmt.Errorf("retrieving module content: %w", err)
	}
	return blob, nil
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
	// A go.mod-only record holds no zip; using it as source would silently
	// degrade this scan to metadata-only. It must not satisfy the source path —
	// treat it like an absent record so the fallback is explicit rather than a
	// scan that quietly analysed nothing. The full path re-fetches the zip (see
	// prefetchMissing) before a node is scanned, so this is a defensive guard.
	// Which bytes this scan is about. A module held only as a go.mod still names
	// an artefact — its go.mod — and a module never fetched at all names none, so
	// the metadata-only records below carry an identity in the first case and an
	// honestly empty one in the second. No !ok guard is needed: an absent record
	// is the zero FactRecord, whose hashes are absent rather than malformed, so
	// derivedFromFact reads it as the zero derivedFrom without error.
	derived, derr := derivedFromFact(fact)
	if derr != nil {
		return domain.VulnerabilityRecord{}, derr
	}

	if !ok || fact.IsGoModOnly() {
		// Module not in the blob store (e.g. a node from a shallow walk), or held
		// only as a go.mod (module-graph resolution). Fall back to OSV metadata:
		// check module coordinates against the vuln DB without govulncheck. Records
		// marked metadata-only have no AffectedSymbols and nil Reachable, signalling
		// that call-graph analysis was not performed. A coordinate with no matching
		// advisory is a real answer here, so the empty status is Clean.
		note := metadataOnlyNote(params.Coordinate, ok && fact.IsGoModOnly())
		return uc.scanMetadataOnly(ctx, params, snapshot, derived, note, "", "", domain.StatusClean)
	}

	// 3.5 Metadata-based Filtering (Optimization)
	// Check if this module or any of its dependencies have known vulnerabilities.
	if !params.Force {
		isVulnerable, err := uc.checkVulnerabilities(ctx, params.Coordinate, params.WalkID)
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
			derived.stamp(&record)
			sealed, herr := domain.VulnerabilityRecordHasher{}.SetContentHash(record)
			if herr != nil {
				return domain.VulnerabilityRecord{}, fmt.Errorf("hashing clean record: %w", herr)
			}
			if perr := uc.vulnStore.PutVulnerabilityRecord(ctx, sealed); perr != nil {
				return domain.VulnerabilityRecord{}, fmt.Errorf("persisting clean record: %w", perr)
			}
			return sealed, nil
		case err != nil:
			uc.logger.Warn("metadata check failed, proceeding with full scan", "error", err)
		case isVulnerable:
			uc.logger.Info("metadata check: potential vulnerabilities found, proceeding with heavy scan", "coordinate", params.Coordinate)
		}
	}

	// 4. Source Retrieval, addressed by the artefact's identity so any store
	// holding these bytes answers, whichever mode acquired them.
	blob, err := uc.openModuleSource(ctx, fact)
	if err != nil {
		return domain.VulnerabilityRecord{}, err
	}
	defer func() { _ = blob.Close() }()

	// 5. Execution (T3: Deterministic Scan)
	record, err := uc.scanner.Scan(ctx, ports.ScanRequest{
		Coordinate:   params.Coordinate,
		ModuleSource: blob,
		Snapshot:     snapshot,
		GoModCache:   params.GoModCache,
		DBDir:        params.VulnDBDir,
		ScanMode:     params.ScanMode,
		// The walk's own build list. A module zip with no go.mod gets one
		// synthesised from these, so its isolated scan resolves the versions the
		// project selected rather than whatever a network tidy would pick.
		BuildList: params.SelectedVersions,
	})
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
	// The verdict names the bytes it was reached from, on both branches: a scan
	// that failed still failed on a specific artefact.
	derived.stamp(&record)

	// 5b/5c. Coverage recovery: route a scan that could not analyse the source to
	// metadata-only matching rather than leaving it a bare failure or a confident
	// "no findings".
	if rec, handled, ferr := uc.routeCoverageFallback(ctx, params, snapshot, derived, record); handled || ferr != nil {
		return rec, ferr
	}

	// 5d. Coordinate-based detection, run unconditionally rather than as a
	// fallback from failure.
	//
	// A module scanned in isolation is govulncheck's MAIN module, and a main
	// module has no version — `go list -m` in the extracted directory prints the
	// path alone, while the same module seen as a dependency prints its version.
	// OSV matching is version-range based, so the source analysis is structurally
	// incapable of reporting an advisory about the very module it was asked to
	// scan. Without this step a module that builds and scans successfully reports
	// Clean whether or not it is vulnerable, and its advisory set is consulted
	// only when the scan FAILS — so improving scan success silently removes
	// detection.
	//
	// Matching by coordinate every time makes the source analysis contribute
	// reachability to the findings rather than decide whether they are looked for
	// at all. A Clean verdict then means "advisories were matched and none
	// applied", never "no advisories could have been matched". This runs before
	// reachability so a coordinate-matched finding is still eligible for the
	// call-graph analysis below.
	if err := uc.attributeCoordinateFindings(ctx, &record, params.Coordinate); err != nil {
		return domain.VulnerabilityRecord{}, err
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
	record, err = domain.VulnerabilityRecordHasher{}.SetContentHash(record)
	if err != nil {
		return domain.VulnerabilityRecord{}, fmt.Errorf("hashing vulnerability record: %w", err)
	}

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
	// Whether a stored verdict is worth reusing is a coverage question — a failed
	// attempt is a fault to retry, not an analysis to serve — so it is asked of the
	// coverage axis rather than the collapsed word.
	if coverage, _ := domain.RecordAxes(rec); coverage == domain.CoverageFailedScan {
		uc.logger.Debug("vulnerability scan cache miss: stored result is ScanFailed, retrying", "coordinate", params.Coordinate)
		return domain.VulnerabilityRecord{}, false, nil
	}
	uc.logger.Debug("vulnerability scan cache hit, re-attributing to current run", "coordinate", params.Coordinate, "status", rec.OverallStatus)
	// The cached verdict is reused, but its provenance must follow the run the
	// user actually invoked: re-stamp the walk reference and scan time so a later
	// query reflects this run, never the unrelated earlier walk that first
	// produced the record. The analysis result is unchanged; only walk_id and
	// scanned_at move forward. The hasher hashes over an empty hash field, so
	// the re-stamped record is sealed exactly as a fresh one is.
	rec.WalkID = params.WalkID
	rec.ScannedAt = uc.clock.Now()
	rec, err = domain.VulnerabilityRecordHasher{}.SetContentHash(rec)
	if err != nil {
		return domain.VulnerabilityRecord{}, false, fmt.Errorf("hashing reused vulnerability record: %w", err)
	}
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
//
// Both branches carry the category and detail. The level says how alarmed to be;
// it must not decide whether the evidence survives. An "expected" verdict whose
// supporting error has been deleted cannot be checked by anyone — which is how a
// scan cache that was quietly failing to resolve versions the walk knew about
// went unnoticed, since the toolchain's message naming the missing version was
// discarded on exactly this path.
func (uc *ScanModuleUseCase) logMetadataFallback(coord coordinate.ModuleCoordinate, reason domain.UnscanReason, category, detail string) {
	if reason.ExpectedOutOfToolchain() {
		uc.logger.Info("vuln-scan: metadata-only, version outside the project build (expected); use reachability --local for project-rooted reachability",
			"coordinate", coord, "category", category, "detail", detail)
		return
	}
	uc.logger.Warn("vuln-scan: source analysis unavailable, falling back to metadata",
		"coordinate", coord, "category", category, "detail", detail)
}

// routeCoverageFallback sends a record that carries no usable source analysis to
// metadata-only matching. handled is true when the caller should return
// (rec, err) directly; false means the source verdict stands and the scan
// continues.
//
// Two shapes reach it. A source-mode failure caused by the module not building
// under the host toolchain is not a scanner fault, so known advisories are still
// attributed rather than the module being left a bare failure. And a module the
// scanner itself declared Unscannable (no go.mod in the zip, OOM kill, …) must
// not persist as a confident "no findings" when matching advisories exist. In
// both, the empty status stays Unscannable — a coverage gap, never a clean — so
// the missing-reachability caveat survives into roll-ups.
func (uc *ScanModuleUseCase) routeCoverageFallback(
	ctx context.Context,
	params ScanModuleParams,
	snapshot domain.DatabaseSnapshot,
	derived derivedFrom,
	record domain.VulnerabilityRecord,
) (domain.VulnerabilityRecord, bool, error) {
	// Routing is decided on the coverage axis: both shapes below are statements
	// about whether the module could be analysed, which is the axis's question. The
	// scanner adapters state only the collapsed word, so RecordAxes derives it here
	// from the diagnostics they set beside it.
	coverage, _ := domain.RecordAxes(record)
	if coverage == domain.CoverageFailedScan && domain.IsBuildIncompatibility(record.ErrorDetail) {
		category := domain.ClassifyBuildIncompatibility(record.ErrorDetail)
		reason := domain.StructuredUnscanReason(record.ErrorDetail)
		// An offline resolution failure must be established, not asserted: the
		// version the toolchain could not resolve decides whether this is a scan
		// cache the walk should have filled or a module reaching outside the
		// project, and one recovered as neither leaves the reason unverified.
		if reason == domain.UnscanReasonVersionNotInToolchain {
			reason, category = uc.verifyOfflineResolution(ctx, params, record.ErrorDetail)
		}
		uc.logMetadataFallback(params.Coordinate, reason, category, record.ErrorDetail)
		note := "source analysis unavailable: " + category + "; results are metadata-only with no reachability"
		rec, err := uc.scanMetadataOnly(ctx, params, snapshot, derived, note, reason, record.ErrorDetail, domain.StatusUnscannable)
		return rec, true, err
	}

	if coverage == domain.CoverageUnscannable {
		note := record.UnscannableReason
		if note == "" {
			note = "source analysis unavailable; results are metadata-only with no reachability"
		}
		uc.logger.Warn("vuln-scan: scanner reported unscannable, falling back to metadata",
			"coordinate", params.Coordinate, "reason", record.UnscanReason)
		rec, err := uc.scanMetadataOnly(ctx, params, snapshot, derived, note, record.UnscanReason, record.ErrorDetail, domain.StatusUnscannable)
		return rec, true, err
	}

	return domain.VulnerabilityRecord{}, false, nil
}

// verifyOfflineResolution establishes the reason and category prose for a
// version-not-in-toolchain failure by recovering the version the toolchain could
// not resolve and handing the evidence to domain.ClassifyOfflineResolution.
// Recovery — which reads the scanned module's go.mod for the source-position
// shape — runs only when there is a walk graph to verify against; a bare
// per-module scan skips it and keeps the conservative reading.
func (uc *ScanModuleUseCase) verifyOfflineResolution(ctx context.Context, params ScanModuleParams, detail string) (domain.UnscanReason, string) {
	var (
		coord     coordinate.ModuleCoordinate
		recovered bool
	)
	if len(params.KnownVersions) > 0 {
		coord, recovered = uc.recoverUnresolvedCoordinate(ctx, params, detail)
	}
	return domain.ClassifyOfflineResolution(detail, coord, recovered, params.KnownVersions)
}

// recoverUnresolvedCoordinate identifies the module version an offline
// resolution failure could not resolve, across both error shapes, and
// establishes it against the scanned module's own dependencies rather than
// asserting it from the error text.
//
// Both shapes first yield a module path — the direct shape names it in a
// coordinate, the source-position shape via longest-prefix match of the
// unimportable package against the walk's module paths. That path is then
// resolved to a version through the scanned module's own go.mod. A coordinate
// the scanned module does not require in its own closure cannot sustain a
// verdict about that module: the toolchain can name a version an unrelated
// build-list entry demanded (a synthesised go.mod requiring the whole walk is
// the case that produced this), which says nothing about the module being
// scanned. Reading the version the module itself selects is what makes the
// verdict its own. ok is false when no path can be recovered or the module does
// not require it.
func (uc *ScanModuleUseCase) recoverUnresolvedCoordinate(ctx context.Context, params ScanModuleParams, detail string) (coordinate.ModuleCoordinate, bool) {
	// Direct coordinate shape: the error names "<path>@<version>". The version is
	// re-derived from the scanned module's own go.mod, not read from the error, so
	// a version an unrelated build-list entry demanded cannot sustain a verdict
	// about the module being scanned; a path the module does not require yields no
	// coordinate.
	if coord, ok := domain.UnresolvedCoordinate(detail); ok {
		return uc.requiredCoordinate(ctx, params.Coordinate, coord.Path())
	}

	// Source-position shape: the error names an unimportable package but no
	// coordinate. Resolve it to the version the toolchain could not fetch.
	importPath, ok := domain.UnresolvedImportPath(detail)
	if !ok {
		return coordinate.ModuleCoordinate{}, false
	}
	// First against the scanned module's own build list: the package's module is
	// often one the walk never built (a test/tool/example dependency), so it is
	// invisible to a match against the walk's node paths alone and recoverable
	// only from the scanned module's own go.mod requires.
	if coord, ok := uc.resolveImportInModule(ctx, params.Coordinate, importPath, modulePaths(params.KnownVersions)); ok {
		return coord, true
	}
	// Then against the dependency whose source contains the import: the failing
	// file path names a cached module, and the version it selects for the package
	// — not any version the scanned module or the walk pins — is the one that was
	// missing. This is the parent/ancestor-module source case.
	if site, ok := domain.ImportSiteModule(detail, importPath); ok && site != params.Coordinate {
		if coord, ok := uc.resolveImportInModule(ctx, site, importPath, nil); ok {
			return coord, true
		}
	}
	return coordinate.ModuleCoordinate{}, false
}

// resolveImportInModule maps an unimportable package to the coordinate the
// module at coord selects for it, reading that module's go.mod. The package is
// resolved to a module path by longest-prefix match over the module's own
// require paths, unioned with extra (the walk's known paths, when the scanned
// module is being consulted). ok is false when the go.mod cannot be read or
// requires no module covering the package — membership in the module's own
// require closure is what ties the version to it rather than to an unrelated
// build-list entry.
func (uc *ScanModuleUseCase) resolveImportInModule(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	importPath string,
	extra map[string]struct{},
) (coordinate.ModuleCoordinate, bool) {
	f, ok := uc.scannedGoMod(ctx, coord)
	if !ok {
		return coordinate.ModuleCoordinate{}, false
	}
	universe := goModModulePaths(f)
	for p := range extra {
		universe[p] = struct{}{}
	}
	modulePath, ok := domain.LongestModulePrefix(importPath, universe)
	if !ok {
		return coordinate.ModuleCoordinate{}, false
	}
	return coordinateFromModFile(f, modulePath)
}

// requiredCoordinate returns the coordinate the scanned module's own go.mod
// selects for modulePath — the version its isolated build, running MVS as its
// own main module, would resolve. ok is false when the go.mod cannot be read or
// does not require modulePath, in which case no coordinate can be established.
func (uc *ScanModuleUseCase) requiredCoordinate(ctx context.Context, scanned coordinate.ModuleCoordinate, modulePath string) (coordinate.ModuleCoordinate, bool) {
	f, ok := uc.scannedGoMod(ctx, scanned)
	if !ok {
		return coordinate.ModuleCoordinate{}, false
	}
	return coordinateFromModFile(f, modulePath)
}

// coordinateFromModFile returns the coordinate a parsed go.mod selects for
// modulePath: the required version, redirected through a module-to-module
// replace that applies to it. ok is false when the go.mod does not require
// modulePath — the require-closure membership is what ties the version to this
// module rather than to an unrelated build-list entry.
func coordinateFromModFile(f *modfile.File, modulePath string) (coordinate.ModuleCoordinate, bool) {
	version, found := "", false
	for _, r := range f.Require {
		if r.Mod.Path == modulePath {
			version, found = r.Mod.Version, true
			break
		}
	}
	if !found {
		return coordinate.ModuleCoordinate{}, false
	}
	// A module-to-module replace redirects the selection. A versioned replace
	// ("foo v1 => bar v2") applies only to that exact version; an unversioned one
	// ("foo => bar v2") applies to every version. Honouring the same scoping the
	// toolchain's MVS does keeps a replace that does not apply to the required
	// version from being read as if it did.
	for _, r := range f.Replace {
		if r.Old.Path != modulePath || r.New.Version == "" {
			continue
		}
		if r.Old.Version == "" || r.Old.Version == version {
			coord, err := coordinate.NewModuleCoordinate(r.New.Path, r.New.Version)
			if err != nil {
				return coordinate.ModuleCoordinate{}, false
			}
			return coord, true
		}
	}
	coord, err := coordinate.NewModuleCoordinate(modulePath, version)
	if err != nil {
		return coordinate.ModuleCoordinate{}, false
	}
	return coord, true
}

// goModModulePaths returns the set of module paths a parsed go.mod requires —
// the universe an unimportable package is resolved against by longest-prefix
// match. Both direct and indirect requirements are included, since either can be
// the module whose version the toolchain could not fetch offline.
func goModModulePaths(f *modfile.File) map[string]struct{} {
	paths := make(map[string]struct{}, len(f.Require))
	for _, r := range f.Require {
		if r != nil && r.Mod.Path != "" {
			paths[r.Mod.Path] = struct{}{}
		}
	}
	return paths
}

// scannedGoMod reads and parses the scanned module's own go.mod from the blob
// store. ok is false when no go.mod is recorded for it or it cannot be read or
// parsed — treated as a recovery miss, never a fabricated requirement.
func (uc *ScanModuleUseCase) scannedGoMod(ctx context.Context, scanned coordinate.ModuleCoordinate) (*modfile.File, bool) {
	fact, ok, err := uc.getFetchRecord(ctx, scanned)
	if err != nil || !ok {
		return nil, false
	}
	goModIdentity, hasGoMod, err := fetchports.GoModIdentity(fact)
	if err != nil || !hasGoMod {
		return nil, false
	}
	rc, err := uc.blobs.Get(ctx, goModIdentity)
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

// modulePaths projects a set of coordinates onto their distinct module paths,
// the universe LongestModulePrefix resolves an unimportable package against.
func modulePaths(known map[coordinate.ModuleCoordinate]struct{}) map[string]struct{} {
	paths := make(map[string]struct{}, len(known))
	for coord := range known {
		paths[coord.Path()] = struct{}{}
	}
	return paths
}

// attributeCoordinateFindings matches the module's advisory set from the pinned
// database by coordinate and merges it into a record produced by source
// analysis.
//
// It applies only to a record that carries a scan verdict. A ScanFailed record
// is a fault to be retried, not a verdict to enrich, and the Unscannable and
// build-incompatibility paths already route through scanMetadataOnly, which
// performs the same coordinate match.
//
// A finding the source analysis already reported wins, because it carries
// call-graph reachability the coordinate match cannot know. A coordinate match
// the source analysis did not report is added with a nil Reachable: the advisory
// applies to this version, and whether it is reachable is decided by the
// reachability step that follows, or left undetermined. Findings are never
// dropped in either direction.
func (uc *ScanModuleUseCase) attributeCoordinateFindings(ctx context.Context, record *domain.VulnerabilityRecord, coord coordinate.ModuleCoordinate) error {
	// "Did an analysis produce this record" is the coverage axis's question, and
	// the two-word test was an open-coded projection of it. The Unscannable and
	// build-incompatibility paths route through scanMetadataOnly, which performs
	// the same coordinate match and states the coverage gap itself.
	if coverage, _ := domain.RecordAxes(*record); coverage != domain.CoverageAnalysed {
		return nil
	}
	matched, err := uc.database.LookupFindings(ctx, coord)
	if err != nil {
		return fmt.Errorf("coordinate advisory match for %s: %w", coord, err)
	}
	reported := make(map[string]struct{}, len(record.Findings))
	for _, f := range record.Findings {
		reported[f.ID] = struct{}{}
	}
	added := 0
	for _, f := range matched {
		if _, ok := reported[f.ID]; ok {
			continue
		}
		record.Findings = append(record.Findings, f)
		added++
	}
	if added > 0 {
		uc.logger.Info("vuln-scan: advisories matched by coordinate that source analysis cannot report",
			"coordinate", coord, "matched", added, "reported_by_source", len(reported))
		// Record identity hashes over the findings, so a merged set must be
		// ordered rather than left as "whatever the source reported, then
		// whatever the coordinate match added".
		domain.SortFindings(record.Findings)
	}
	if len(record.Findings) > 0 {
		// This is a verdict decision, so it states the axis it decided and lets the
		// domain collapse the summary, rather than open-coding the word. Coverage
		// comes from the record's own evidence: the guard above admits only a
		// record the scanner analysed, and the scanner's analysed results carry no
		// diagnostic, so this reads Analysed — asserted from the record rather than
		// assumed here, so a record that did carry a coverage gap could not have
		// one written over it.
		record.CoverageStatus = domain.DetermineRecordCoverage(*record)
		record.FindingsStatus = domain.FindingsRecordAffected
		record.OverallStatus = domain.DetermineRecordOverallStatus(record.CoverageStatus, record.FindingsStatus)
	}
	return nil
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
func (uc *ScanModuleUseCase) scanMetadataOnly(ctx context.Context, params ScanModuleParams, snapshot domain.DatabaseSnapshot, derived derivedFrom, note string, unscanReason domain.UnscanReason, errorDetail string, emptyStatus domain.VulnerabilityStatus) (domain.VulnerabilityRecord, error) {
	uc.logger.Info("vuln-scan: metadata-only", "coordinate", params.Coordinate, "reason", note)
	findings, err := uc.database.LookupFindings(ctx, params.Coordinate)
	if err != nil {
		return domain.VulnerabilityRecord{}, fmt.Errorf("metadata check for %s: %w", params.Coordinate, err)
	}

	// Both axes are asserted here rather than left for the seal to project off the
	// summary word, because this is the one path whose two answers cannot both fit
	// in that word.
	//
	// Coverage is Unscannable on every metadata-only record, whichever entry point
	// arrived here: no module source was analysed, so no reachability was
	// established and note always says why. That is true even when emptyStatus is
	// Clean — a coordinate matched against the advisory database with no advisory
	// applying is a real answer about FINDINGS, and says nothing about coverage.
	// Conflating the two is what left 74 stored records claiming a module was
	// analysed when only its coordinate was: the coverage this call was passed was
	// discarded the moment an advisory matched, surviving only as UnscanReason.
	coverage := domain.CoverageUnscannable
	findingsAxis := domain.FindingsRecordClean
	if len(findings) > 0 {
		findingsAxis = domain.FindingsRecordAffected
	}
	// The summary word is unchanged: emptyStatus as the caller chose it, promoted
	// to Affected by a match. Collapsing the axes instead would report Unscannable
	// for a matched advisory — correct for ranking, since coverage outranks
	// findings, but it would retire a finding from every consumer that reads the
	// summary. A finding never decays into a coverage word; the gap travels beside
	// it on the coverage axis, which is why that axis is stored.
	status := emptyStatus
	if findingsAxis == domain.FindingsRecordAffected {
		status = domain.StatusAffected
	}

	now := uc.clock.Now()
	record := domain.VulnerabilityRecord{
		Ecosystem:         fetchdomain.EcosystemGo,
		Coordinate:        params.Coordinate,
		WalkID:            params.WalkID,
		Findings:          findings,
		OverallStatus:     status,
		CoverageStatus:    coverage,
		FindingsStatus:    findingsAxis,
		UnscanReason:      unscanReason,
		UnscannableReason: note,
		// The originating toolchain error is carried onto the metadata-only
		// record. Without it the record states a verdict and destroys the
		// evidence for it, leaving an operator no way to tell a module that
		// genuinely cannot be analysed from one the scanner failed to set up.
		ErrorDetail:      errorDetail,
		DatabaseSnapshot: snapshot,
		ScannedAt:        now,
		FirstScannedAt:   now,
		PipelineVersion:  uc.pipelineVersion,
	}
	// Empty when the module was never fetched: a coordinate matched against the
	// advisory database read no artefact, and must not claim to have read one.
	derived.stamp(&record)
	record, err = domain.VulnerabilityRecordHasher{}.SetContentHash(record)
	if err != nil {
		return domain.VulnerabilityRecord{}, fmt.Errorf("hashing metadata-only record: %w", err)
	}
	if perr := uc.vulnStore.PutVulnerabilityRecord(ctx, record); perr != nil {
		return domain.VulnerabilityRecord{}, fmt.Errorf("persisting metadata-only record: %w", perr)
	}
	return record, nil
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
		syms := buildSymbolRefs(params.Coordinate.Path(), finding.AffectedSymbols)
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

func (uc *ScanModuleUseCase) checkVulnerabilities(ctx context.Context, coord coordinate.ModuleCoordinate, walkID string) (bool, error) {
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
