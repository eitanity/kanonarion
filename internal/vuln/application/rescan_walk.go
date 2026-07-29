package application

import (
	"context"
	"fmt"
	"log/slog"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
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

// RescanRequest defines the input for a re-scan operation.
type RescanRequest struct {
	WalkID             string
	Snapshot           *domain.DatabaseSnapshot // nil = take a fresh snapshot from the network
	EnableReachability bool
	Operator           string
}

// Rescan performs the re-scan scan and returns the new WalkScanRun.
// It always forces a fresh scan (bypassing per-module cache) so that the new
// snapshot is actually consulted, and it never modifies existing scan runs.
func (uc *RescanWalkUseCase) Rescan(ctx context.Context, req RescanRequest) (domain.WalkScanRun, error) {
	// 1. Validate walk exists.
	_, err := uc.walkStore.GetWalk(ctx, req.WalkID)
	if err != nil {
		return domain.WalkScanRun{}, fmt.Errorf("retrieving walk %q: %w", req.WalkID, err)
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
		WithVCSHosts(uc.vcsHosts)

	run, err := scanWalk.Scan(ctx, ScanWalkParams{
		WalkID:             req.WalkID,
		Snapshot:           snapshot,
		Force:              true,
		EnableReachability: req.EnableReachability,
		Operator:           req.Operator,
	})
	if err != nil {
		return domain.WalkScanRun{}, fmt.Errorf("rescan scan: %w", err)
	}

	uc.logger.Info("rescan completed",
		"walk_id", req.WalkID,
		"run_id", run.ID,
		"snapshot_version", snapshot.Version,
		"status", run.OverallStatus,
	)
	return run, nil
}
