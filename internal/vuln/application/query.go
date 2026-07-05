package application

import (
	"context"
	"fmt"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// QueryVulnUseCase provides read-only access to vulnerability records.
type QueryVulnUseCase struct {
	store ports.VulnerabilityStore
}

// NewQueryVulnUseCase constructs a QueryVulnUseCase.
func NewQueryVulnUseCase(store ports.VulnerabilityStore) *QueryVulnUseCase {
	return &QueryVulnUseCase{store: store}
}

// GetRecord retrieves a vulnerability record by coordinate, pipeline version, and snapshot.
func (uc *QueryVulnUseCase) GetRecord(
	ctx context.Context,
	coord fetchdomain.ModuleCoordinate,
	pipelineVersion string,
	snapshot domain.DatabaseSnapshot,
) (domain.VulnerabilityRecord, bool, error) {
	rec, found, err := uc.store.GetVulnerabilityRecord(ctx, coord, pipelineVersion, snapshot)
	if err != nil {
		return domain.VulnerabilityRecord{}, false, fmt.Errorf("getting vulnerability record for %s: %w", coord, err)
	}
	return rec, found, nil
}

// GetLatestRecord returns the most recently scanned record for a coordinate and pipeline version.
func (uc *QueryVulnUseCase) GetLatestRecord(
	ctx context.Context,
	coord fetchdomain.ModuleCoordinate,
	pipelineVersion string,
) (domain.VulnerabilityRecord, bool, error) {
	rec, found, err := uc.store.GetLatestVulnerabilityRecord(ctx, coord, pipelineVersion)
	if err != nil {
		return domain.VulnerabilityRecord{}, false, fmt.Errorf("getting latest vulnerability record for %s: %w", coord, err)
	}
	return rec, found, nil
}

// GetLatestRecordForWalk returns the most recently scanned record for a coordinate, pipeline version, and walk ID.
func (uc *QueryVulnUseCase) GetLatestRecordForWalk(
	ctx context.Context,
	coord fetchdomain.ModuleCoordinate,
	pipelineVersion string,
	walkID string,
) (domain.VulnerabilityRecord, bool, error) {
	rec, found, err := uc.store.GetLatestVulnerabilityRecordForWalk(ctx, coord, pipelineVersion, walkID)
	if err != nil {
		return domain.VulnerabilityRecord{}, false, fmt.Errorf("getting latest vulnerability record for %s (walk %s): %w", coord, walkID, err)
	}
	return rec, found, nil
}

// ListRecordsForModule returns all stored scan records for a coordinate and pipeline version.
func (uc *QueryVulnUseCase) ListRecordsForModule(
	ctx context.Context,
	coord fetchdomain.ModuleCoordinate,
	pipelineVersion string,
) ([]domain.VulnerabilityRecord, error) {
	recs, err := uc.store.ListVulnerabilityRecordsForModule(ctx, coord, pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("listing vulnerability records for %s: %w", coord, err)
	}
	return recs, nil
}

// ListRecordsByFindingID returns all vulnerability records containing a finding with the given ID.
func (uc *QueryVulnUseCase) ListRecordsByFindingID(ctx context.Context, findingID string) ([]domain.VulnerabilityRecord, error) {
	recs, err := uc.store.ListVulnerabilityRecordsByFindingID(ctx, findingID)
	if err != nil {
		return nil, fmt.Errorf("listing vulnerability records by finding ID %q: %w", findingID, err)
	}
	return recs, nil
}

// QueryScanRunsUseCase provides read-only access to walk scan runs and database snapshots.
type QueryScanRunsUseCase struct {
	store ports.VulnerabilityStore
}

// NewQueryScanRunsUseCase constructs a QueryScanRunsUseCase.
func NewQueryScanRunsUseCase(store ports.VulnerabilityStore) *QueryScanRunsUseCase {
	return &QueryScanRunsUseCase{store: store}
}

// GetRun retrieves a walk scan run by its ID.
func (uc *QueryScanRunsUseCase) GetRun(ctx context.Context, id string) (domain.WalkScanRun, bool, error) {
	run, found, err := uc.store.GetWalkScanRun(ctx, id)
	if err != nil {
		return domain.WalkScanRun{}, false, fmt.Errorf("getting scan run %q: %w", id, err)
	}
	return run, found, nil
}

// ListRunsForWalk returns all scan runs for the given walk ID.
func (uc *QueryScanRunsUseCase) ListRunsForWalk(ctx context.Context, walkID string) ([]domain.WalkScanRun, error) {
	runs, err := uc.store.ListWalkScanRuns(ctx, walkID)
	if err != nil {
		return nil, fmt.Errorf("listing scan runs for walk %q: %w", walkID, err)
	}
	return runs, nil
}

// ListAllRuns returns all scan runs across all walks, most recent first.
func (uc *QueryScanRunsUseCase) ListAllRuns(ctx context.Context) ([]domain.WalkScanRun, error) {
	runs, err := uc.store.ListAllWalkScanRuns(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing all scan runs: %w", err)
	}
	return runs, nil
}

// ListSnapshots returns all stored vulnerability database snapshot metadata, most recent first.
func (uc *QueryScanRunsUseCase) ListSnapshots(ctx context.Context) ([]domain.DatabaseSnapshot, error) {
	snaps, err := uc.store.ListDatabaseSnapshots(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing database snapshots: %w", err)
	}
	return snaps, nil
}

// GetLatestSnapshot returns the most recently stored snapshot metadata.
func (uc *QueryScanRunsUseCase) GetLatestSnapshot(ctx context.Context) (domain.DatabaseSnapshot, bool, error) {
	snap, found, err := uc.store.GetLatestDatabaseSnapshot(ctx)
	if err != nil {
		return domain.DatabaseSnapshot{}, false, fmt.Errorf("getting latest database snapshot: %w", err)
	}
	return snap, found, nil
}
