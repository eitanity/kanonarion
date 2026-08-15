package application

import (
	"context"
	"errors"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"

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
	coord coordinate.ModuleCoordinate,
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
	coord coordinate.ModuleCoordinate,
	pipelineVersion string,
) (domain.VulnerabilityRecord, bool, error) {
	rec, found, err := uc.store.GetLatestVulnerabilityRecord(ctx, coord, pipelineVersion)
	if err != nil {
		return domain.VulnerabilityRecord{}, false, fmt.Errorf("getting latest vulnerability record for %s: %w", coord, err)
	}
	return rec, found, nil
}

// ListRecordsForModuleInWalk returns every generation of a coordinate the named
// walk's scan runs covered — the candidates, not an answer.
//
// Candidates, because ranking them needs an analysis frame the store does not
// have: a walk's membership index carries none, so its candidate set spans every
// frame the coordinate was measured in at that generation. The caller knows
// which build it asked about and selects on it (domain.ComposeAt). There is
// deliberately no frame-blind convenience beside this: the one that existed
// answered walk-pinned questions from other projects' scans.
func (uc *QueryVulnUseCase) ListRecordsForModuleInWalk(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	pipelineVersion string,
	walkID string,
) ([]domain.VulnerabilityRecord, error) {
	recs, err := uc.store.ListVulnerabilityRecordsForModuleInWalk(ctx, coord, pipelineVersion, walkID)
	if err != nil {
		return nil, fmt.Errorf("listing vulnerability records for %s (walk %s): %w", coord, walkID, err)
	}
	return recs, nil
}

// ListRecordsForModule returns all stored scan records for a coordinate and pipeline version.
func (uc *QueryVulnUseCase) ListRecordsForModule(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	pipelineVersion string,
) ([]domain.VulnerabilityRecord, error) {
	recs, err := uc.store.ListVulnerabilityRecordsForModule(ctx, coord, pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("listing vulnerability records for %s: %w", coord, err)
	}
	return recs, nil
}

// ListRecordsForModuleAllGenerations returns every stored scan record for a
// coordinate, at every pipeline version the store holds it at, newest first.
//
// It is the read behind a history listing. ListRecordsForModule above keys on
// the pipeline version and so goes empty for a coordinate whose whole history
// predates a bump; a history that disappeared at a bump was never a history.
// Nothing point-in-time is answered from it: a caller rendering these rows says
// which generation each came from.
func (uc *QueryVulnUseCase) ListRecordsForModuleAllGenerations(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
) ([]domain.VulnerabilityRecord, error) {
	recs, err := uc.store.ListVulnerabilityRecordsForModuleAllGenerations(ctx, coord)
	if err != nil {
		return nil, fmt.Errorf("listing vulnerability records across generations for %s: %w", coord, err)
	}
	return recs, nil
}

// ListRecordGenerationsForModule reports which pipeline versions the store
// holds records for a coordinate at, and how much it holds at each.
//
// It is a diagnostic read, not an answer: it exists so a caller whose keyed read
// came back empty can say whether the store holds nothing for the coordinate or
// holds it only at generations this build no longer serves. Those are different
// facts with different remedies, and the keyed reads cannot tell them apart.
func (uc *QueryVulnUseCase) ListRecordGenerationsForModule(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
) ([]ports.VulnerabilityRecordGeneration, error) {
	gens, err := uc.store.ListVulnerabilityRecordGenerationsForModule(ctx, coord)
	if err != nil {
		return nil, fmt.Errorf("listing vulnerability record generations for %s: %w", coord, err)
	}
	return gens, nil
}

// ListRecordsForRun returns the vulnerability records one scan run wrote — the
// per-module verdicts that run established, not the latest verdict each module
// has since acquired. It is the read a caller serving a stored run needs: a
// report assembled from "latest per module" could mix generations and present a
// summary no single run ever produced.
func (uc *QueryVulnUseCase) ListRecordsForRun(ctx context.Context, runID string) ([]domain.VulnerabilityRecord, error) {
	recs, err := uc.store.ListVulnerabilityRecords(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("listing vulnerability records for scan run %q: %w", runID, err)
	}
	return recs, nil
}

// ListRecordsByFindingID returns the vulnerability records containing a finding
// with the given ID. An empty walkID spans the whole store; a non-empty one
// restricts the answer to the modules that walk's scan runs covered.
func (uc *QueryVulnUseCase) ListRecordsByFindingID(ctx context.Context, findingID, walkID string) ([]domain.VulnerabilityRecord, error) {
	// The walk is not repeated here: every store error on the scoped path
	// already names it, and three mentions of one ULID is not three facts.
	recs, err := uc.store.ListVulnerabilityRecordsByFindingID(ctx, findingID, walkID)
	if err != nil {
		return nil, fmt.Errorf("listing vulnerability records by finding ID %q: %w", findingID, err)
	}
	return recs, nil
}

// ErrWalkPresenceUnavailable is returned when a caller asks whether a run's
// inputs still resolve and this use case was constructed without a walk-presence
// port. It is deliberately an error rather than an assumed "resolves": a reader
// that cannot check must not answer the question, because the wrong answer here
// presents a run whose subject is gone as ordinary evidence.
var ErrWalkPresenceUnavailable = errors.New(
	"walk presence unavailable: cannot state whether a scan run's inputs resolve")

// QueryScanRunsUseCase provides read-only access to walk scan runs and database snapshots.
type QueryScanRunsUseCase struct {
	store ports.VulnerabilityStore
	walks ports.WalkPresence
}

// NewQueryScanRunsUseCase constructs a QueryScanRunsUseCase.
//
// walks is what lets a caller state that a run's inputs no longer resolve. It is
// a constructor argument rather than an optional builder so that every reader of
// scan runs is built having decided whether it can answer that; a nil one makes
// UnresolvedWalks and WalkPresent fail rather than assume.
func NewQueryScanRunsUseCase(store ports.VulnerabilityStore, walks ports.WalkPresence) *QueryScanRunsUseCase {
	return &QueryScanRunsUseCase{store: store, walks: walks}
}

// UnresolvedWalks returns the walk ids named by runs that this store no longer
// holds — the runs whose inputs cannot be resolved. A run in the result reports
// what was found by a scan whose subject is gone: the finding rows survive, the
// walk that says what was scanned, at which versions, from which root, does not.
//
// It is derived on every read rather than stamped on the rows. A stamp would
// need a migration, would classify only the runs present when it ran, and would
// go stale the moment a later purge stranded another run; a live probe of the
// walks table classifies every run, present and future, at the cost of one
// indexed read per listing.
func (uc *QueryScanRunsUseCase) UnresolvedWalks(
	ctx context.Context, runs []domain.WalkScanRun,
) (map[string]bool, error) {
	if uc.walks == nil {
		return nil, ErrWalkPresenceUnavailable
	}
	ids := make([]string, 0, len(runs))
	seen := make(map[string]struct{}, len(runs))
	for _, run := range runs {
		if run.WalkID == "" {
			continue
		}
		if _, dup := seen[run.WalkID]; dup {
			continue
		}
		seen[run.WalkID] = struct{}{}
		ids = append(ids, run.WalkID)
	}
	present, err := uc.walks.PresentWalks(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("checking whether the walks these runs name still exist: %w", err)
	}
	unresolved := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !present[id] {
			unresolved[id] = true
		}
	}
	return unresolved, nil
}

// WalkPresent reports whether the store still holds walkID. It answers for a
// walk named directly by a caller — a history query names one — where there may
// be no run to derive the id from.
func (uc *QueryScanRunsUseCase) WalkPresent(ctx context.Context, walkID string) (bool, error) {
	if uc.walks == nil {
		return false, ErrWalkPresenceUnavailable
	}
	present, err := uc.walks.PresentWalks(ctx, []string{walkID})
	if err != nil {
		return false, fmt.Errorf("checking whether walk %q still exists: %w", walkID, err)
	}
	return present[walkID], nil
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
//
// The runs the store could verify are returned even when it also reports rows
// it could not — see ports.UnreadableRuns. Discarding them here would put the
// choice beyond every caller's reach: a survey command could then only print a
// list that omits the faulty rows without saying so, or nothing at all.
func (uc *QueryScanRunsUseCase) ListRunsForWalk(ctx context.Context, walkID string) ([]domain.WalkScanRun, error) {
	runs, err := uc.store.ListWalkScanRuns(ctx, walkID)
	if err != nil {
		return runs, fmt.Errorf("listing scan runs for walk %q: %w", walkID, err)
	}
	return runs, nil
}

// ListAllRuns returns all scan runs across all walks, most recent first, on the
// same partial-result terms as ListRunsForWalk.
func (uc *QueryScanRunsUseCase) ListAllRuns(ctx context.Context) ([]domain.WalkScanRun, error) {
	runs, err := uc.store.ListAllWalkScanRuns(ctx)
	if err != nil {
		return runs, fmt.Errorf("listing all scan runs: %w", err)
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
