package application

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// RescanWalkUseCase re-runs a vulnerability scan for an existing walk against a
// fresh (or explicitly pinned) database snapshot, producing a new WalkScanRun
// without modifying any prior scan runs.
type RescanWalkUseCase struct {
	walkStore       walkports.WalkStore
	vulnStore       ports.VulnerabilityStore
	moduleScanner   *ScanModuleUseCase
	vcsHosts        fetchdomain.VCSHostAllowlist
	fetcher         ports.ModuleFetcher
	clock           fetchports.Clock
	pipelineVersion string
	logger          *slog.Logger
	audit           ports.AuditSink  // optional; propagated to the delegated scan
	realModcacheDir string           // --from-modcache; propagated to the delegated scan
	hostMemory      ports.HostMemory // optional; propagated to the delegated scan
	// vendoredClosure is the reader that lets the delegated scan reach a
	// project's working tree. Without it a re-scan of a project walk cannot
	// reproduce the frame the run it re-scans was analysed in — see
	// projectFrameDir, which refuses rather than re-deriving under another one.
	vendoredClosure ports.VendoredClosureReader
}

// FrameNotReproducibleError reports that a re-scan would have to change the
// analysis frame of the run it re-scans, and refuses.
//
// A re-scan is asked for the SAME evidence against a newer advisory database.
// Silently answering a different question instead is the failure this names: a
// walk rooted at a project, re-scanned without the wiring that reaches the
// project's tree, re-derives every module in isolation — and an isolated
// "not reachable" then outranks the consumer's route on the compose ladder, so
// the operator who asked for a refresh is handed a stand-down.
//
// It is deliberately a refusal and not the degradation the scan path performs.
// The scan path is asked "scan this walk" and answering with what it can still
// measure is a narrower answer to the question asked; a re-scan is asked to
// reproduce a frame, and an answer in a different frame is not narrower, it is
// about something else.
type FrameNotReproducibleError struct {
	WalkID string
	// ProjectDir is the working tree the walk was taken from — the frame that
	// cannot be reproduced.
	ProjectDir string
	// Reason states what stopped it, in the tool's own voice.
	Reason string
}

func (e *FrameNotReproducibleError) Error() string {
	// Two openings for two provenances. The walk usually names the tree it was
	// taken from, and quoting it is the most useful thing the refusal can say.
	// When it names none the refusal is driven by the run's OWN records instead,
	// and printing an empty path there would read as a tree at "", so the
	// sentence says where the frame was actually read from.
	where := fmt.Sprintf("the walk was taken from the project at %s and its scan is rooted there", e.ProjectDir)
	if e.ProjectDir == "" {
		where = "the walk records no project directory, but the run being re-scanned recorded a project-rooted analysis frame"
	}
	return fmt.Sprintf(
		"re-scanning walk %s would change its analysis frame: %s, but %s. Every module would be re-derived in isolation, which answers a different question than the run being re-scanned — whether each module reaches its own vulnerable code when built alone, not whether this project's build does",
		e.WalkID, where, e.Reason)
}

// WithVendoredClosure wires the reader that lets a re-scan reach the working
// tree its walk was taken from, so a project-rooted run re-scans project-rooted.
// Optional in the type system and required in practice: without it a re-scan of
// a project walk refuses rather than silently changing frame.
func (uc *RescanWalkUseCase) WithVendoredClosure(r ports.VendoredClosureReader) *RescanWalkUseCase {
	uc.vendoredClosure = r
	return uc
}

// NewRescanWalkUseCase returns a new RescanWalkUseCase.
// WithVCSHosts sets the effective VCS forge allowlist for the pre-fetch the
// delegated scan may perform. A rescan re-runs the same pipeline, so it must be
// bound by the same policy; leaving it out would restore the divergence this
// exists to remove, one command over.
func (uc *RescanWalkUseCase) WithVCSHosts(hosts fetchdomain.VCSHostAllowlist) *RescanWalkUseCase {
	uc.vcsHosts = hosts
	return uc
}

func NewRescanWalkUseCase(
	walkStore walkports.WalkStore,
	vulnStore ports.VulnerabilityStore,
	moduleScanner *ScanModuleUseCase,
	fetcher ports.ModuleFetcher,
	clock fetchports.Clock,
	pipelineVersion string,
	logger *slog.Logger,
) *RescanWalkUseCase {
	return &RescanWalkUseCase{
		walkStore:       walkStore,
		vulnStore:       vulnStore,
		moduleScanner:   moduleScanner,
		fetcher:         fetcher,
		clock:           clock,
		pipelineVersion: pipelineVersion,
		logger:          logger,
	}
}

// WithAudit wires an audit sink that the delegated walk scan uses to append
// assurance-log events. Optional (nil disables emission); returns the receiver
// for chaining.
func (uc *RescanWalkUseCase) WithAudit(sink ports.AuditSink) *RescanWalkUseCase {
	uc.audit = sink
	return uc
}

// WithHostMemory propagates the host-memory reporter to the delegated walk
// scan, so a re-scan sizes its module-scan pool against the same memory budget
// a first scan does. Optional (nil keeps the CPU-only cap); returns the
// receiver for chaining.
func (uc *RescanWalkUseCase) WithHostMemory(mem ports.HostMemory) *RescanWalkUseCase {
	uc.hostMemory = mem
	return uc
}

// WithRealModcache propagates --from-modcache to the delegated walk scan, so the
// re-scan reads govulncheck's dependencies from the existing module cache at dir
// instead of a blob-store-populated temp cache. Empty (the default) keeps the
// blob-store path. Returns the receiver for chaining.
func (uc *RescanWalkUseCase) WithRealModcache(dir string) *RescanWalkUseCase {
	uc.realModcacheDir = dir
	return uc
}

// projectFrameDir returns the working tree the re-scan must root its analysis
// at to reproduce the frame of the run it re-scans, or an error when it cannot.
//
// The three answers, and what each is:
//
//   - A walk of a published coordinate roots its analysis at the target module
//     itself, which the delegated scan does from the walk alone. Nothing to
//     reproduce, nothing to wire: the empty directory is correct here, not a gap.
//   - A walk of a local project that recorded no directory may still have been
//     scanned project-rooted: the directory reaches the walk through provenance
//     the walk hash deliberately excludes, and the scan can be handed one
//     directly (--gomod, --project, the local driver). So the run being
//     re-scanned is asked, not only the walk — see priorRunWasProjectRooted.
//     "The walk names no tree" was previously taken as proof that no frame was
//     at stake and the degradation was merely logged, which is the same silent
//     frame change this type exists to refuse, reached by a different route.
//   - A walk of a local project that DID record a directory was scanned rooted
//     there. Reproducing that is the whole of this method, and failing to is a
//     refusal.
func (uc *RescanWalkUseCase) projectFrameDir(ctx context.Context, walk walkdomain.WalkRecord) (string, error) {
	if !walk.Target.IsLocal() {
		return "", nil
	}
	if walk.ProjectDir == "" {
		rooted, rerr := uc.priorRunWasProjectRooted(ctx, walk.ID)
		if rerr != nil {
			return "", rerr
		}
		if rooted {
			return "", &FrameNotReproducibleError{
				WalkID: walk.ID, ProjectDir: "",
				Reason: "this re-scan has no directory to root that analysis at — the walk carries none and none was supplied",
			}
		}
		uc.logger.Info("rescan: neither the walk nor the run being re-scanned records a project-rooted frame, so none is being reproduced",
			"walk_id", walk.ID, "root", walk.Target)
		return "", nil
	}
	if uc.vendoredClosure == nil {
		return "", &FrameNotReproducibleError{
			WalkID: walk.ID, ProjectDir: walk.ProjectDir,
			Reason: "this re-scan has no reader for the project's module closure wired, so it cannot analyse that tree at all",
		}
	}
	if _, serr := os.Stat(walk.ProjectDir); serr != nil {
		return "", &FrameNotReproducibleError{
			WalkID: walk.ID, ProjectDir: walk.ProjectDir,
			Reason: fmt.Sprintf("that directory is not readable from here (%v)", serr),
		}
	}
	uc.logger.Info("rescan: reproducing the project-rooted frame the walk was scanned in",
		"walk_id", walk.ID, "project_dir", walk.ProjectDir)
	return walk.ProjectDir, nil
}

// priorRunWasProjectRooted reports whether the newest scan run of walkID
// recorded a target-rooted analysis frame.
//
// It reads the frame off the records the run produced rather than off the walk,
// because the walk is not where the frame is decided: a scan can be pointed at a
// working tree the walk never named, and the record each module carries is the
// only place that choice is written down. Any target-rooted record is enough —
// this branch is reached only for a walk whose target is local, so the target
// that was rooted at is that project.
//
// A read fault is propagated, never read as "no frame". Answering "isolated is
// fine" because the ledger could not be read is how a refusal turns into the
// silent frame change it exists to prevent.
func (uc *RescanWalkUseCase) priorRunWasProjectRooted(ctx context.Context, walkID string) (bool, error) {
	runs, err := uc.vulnStore.ListWalkScanRuns(ctx, walkID)
	if err != nil {
		return false, fmt.Errorf("reading the scan runs of walk %q to settle its analysis frame: %w", walkID, err)
	}
	if len(runs) == 0 {
		return false, nil
	}
	// Ordered newest first by the store, so runs[0] is the generation a re-scan
	// is asked to reproduce.
	recs, err := uc.vulnStore.ListVulnerabilityRecords(ctx, runs[0].ID)
	if err != nil {
		return false, fmt.Errorf("reading the records of scan run %q to settle its analysis frame: %w", runs[0].ID, err)
	}
	for _, rec := range recs {
		if domain.RecordRooting(rec).IsTargetRooted() {
			return true, nil
		}
	}
	return false, nil
}

// RescanRequest defines the input for a re-scan operation.
type RescanRequest struct {
	WalkID             string
	Snapshot           *domain.DatabaseSnapshot // nil = take a fresh snapshot from the network
	EnableReachability bool
	Operator           string
	// Progress is called after each module is re-scanned, exactly as it is on a
	// scan. It may be nil.
	//
	// A re-scan forces every module in the walk through the scanner, so it is the
	// most expensive thing the CLI runs; without this it emitted nothing at all
	// between the command being typed and the run finishing, and a caller could
	// not tell it from a hang.
	Progress func(coord coordinate.ModuleCoordinate, record domain.VulnerabilityRecord, current, total int)
}

// Rescan performs the re-scan scan and returns the new WalkScanRun.
// It always forces a fresh scan (bypassing per-module cache) so that the new
// snapshot is actually consulted, and it never modifies existing scan runs.
func (uc *RescanWalkUseCase) Rescan(ctx context.Context, req RescanRequest) (domain.WalkScanRun, error) {
	// 1. Validate walk exists.
	walk, err := uc.walkStore.GetWalk(ctx, req.WalkID)
	if err != nil {
		return domain.WalkScanRun{}, fmt.Errorf("retrieving walk %q: %w", req.WalkID, err)
	}

	// 1b. Settle the frame before anything is fetched or scanned. A frame this
	// run cannot reproduce is a refusal, and a refusal is worth nothing after a
	// snapshot download and a full re-scan.
	projectDir, err := uc.projectFrameDir(ctx, walk)
	if err != nil {
		return domain.WalkScanRun{}, err
	}

	// 2. Resolve snapshot: if provided, use it; otherwise fetch a fresh one from
	// the network and persist it alongside any earlier snapshots.
	snapshot := req.Snapshot
	if snapshot == nil {
		uc.logger.Info("rescan: fetching fresh vulnerability database snapshot")
		s, body, err := uc.moduleScanner.database.Snapshot(ctx)
		if err != nil {
			return domain.WalkScanRun{}, fmt.Errorf("fetching fresh snapshot: %w", err)
		}
		if body != nil {
			defer func() { _ = body.Close() }()
			if err := uc.vulnStore.PutDatabaseSnapshot(ctx, s, body); err != nil {
				return domain.WalkScanRun{}, fmt.Errorf("persisting fresh snapshot: %w", err)
			}
			// Assurance log: a re-scan's whole purpose is to judge against a newer
			// advisory set, so the moment that set arrived is the fact the re-scan
			// rests on. Emitted after the write; a caller-supplied snapshot acquired
			// nothing here and appends nothing.
			if err := emitSnapshotRecorded(uc.audit, s, snapshotRouteRescan); err != nil {
				return domain.WalkScanRun{}, err
			}
		}
		snapshot = &s
	}

	// 3. Delegate to ScanWalkUseCase with Force=true so every module is
	// re-scanned against the resolved snapshot, bypassing the per-module cache.
	scanWalk := NewScanWalkUseCase(
		uc.walkStore,
		uc.vulnStore,
		uc.moduleScanner,
		uc.fetcher,
		uc.clock,
		uc.pipelineVersion,
		uc.logger,
	).WithAudit(uc.audit).WithRealModcache(uc.realModcacheDir).WithHostMemory(uc.hostMemory).
		WithVCSHosts(uc.vcsHosts).WithVendoredClosure(uc.vendoredClosure)

	run, err := scanWalk.Scan(ctx, ScanWalkParams{
		WalkID:             req.WalkID,
		Snapshot:           snapshot,
		Force:              true,
		EnableReachability: req.EnableReachability,
		Operator:           req.Operator,
		// Passed explicitly rather than left to the delegated scan's own
		// recollection of the walk: that path adopts the directory only while it
		// still holds a vendored tree, which is the right rule for a scan (it
		// reaches for the directory to reach the vendored SURFACE) and the wrong
		// one here (this reaches for it to reproduce the ROOT). A project that
		// never vendored would otherwise re-scan isolated.
		ProjectDir: projectDir,
		Progress:   req.Progress,
	})
	if err != nil {
		return domain.WalkScanRun{}, fmt.Errorf("rescan scan: %w", err)
	}

	uc.logger.Info("rescan completed",
		"walk_id", req.WalkID,
		"run_id", run.ID,
		"snapshot_version", snapshot.Version(),
		"status", run.OverallStatus,
	)
	return run, nil
}
