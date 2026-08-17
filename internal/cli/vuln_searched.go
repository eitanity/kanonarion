package cli

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
)

// negativeSearcher is the read-time call-graph search a stored record's
// negatives are put through. It is an interface here so the decorator below can
// be tested without a call-graph store, and so nothing in the CLI depends on the
// reachability adapter's concrete type.
type negativeSearcher interface {
	Search(ctx context.Context, rec *vulndomain.VulnerabilityRecord)
}

// searchedVulnQuery wraps a QueryVulnUseCase so that every record any read
// surface receives has already been through the search.
//
// It is wrapped once, at the seam every vuln read passes through, rather than
// called at each surface. Five surfaces render a negative's soundness — the
// finding label, the reachability query, vuln-by-id, context and the local
// probe's seed — and a search wired into some of them would have them printing
// different rungs for the same stored finding, which is worse than none of them
// printing the better one.
//
// The read stays a read: the search attaches a field the record does not
// serialise, so nothing here changes a stored byte or a content hash.
type searchedVulnQuery struct {
	inner    QueryVulnUseCase
	searcher negativeSearcher
}

// newSearchedVulnQuery returns uc with the search applied to its results, or uc
// itself when there is no searcher to apply.
func newSearchedVulnQuery(uc QueryVulnUseCase, searcher negativeSearcher) QueryVulnUseCase {
	if searcher == nil {
		return uc
	}
	return &searchedVulnQuery{inner: uc, searcher: searcher}
}

func (q *searchedVulnQuery) search(ctx context.Context, rec vulndomain.VulnerabilityRecord) vulndomain.VulnerabilityRecord {
	q.searcher.Search(ctx, &rec)
	return rec
}

func (q *searchedVulnQuery) searchAll(ctx context.Context, recs []vulndomain.VulnerabilityRecord) []vulndomain.VulnerabilityRecord {
	for i := range recs {
		q.searcher.Search(ctx, &recs[i])
	}
	return recs
}

func (q *searchedVulnQuery) GetRecord(
	ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string, snapshot vulndomain.DatabaseSnapshot,
) (vulndomain.VulnerabilityRecord, bool, error) {
	rec, found, err := q.inner.GetRecord(ctx, coord, pipelineVersion, snapshot)
	if err != nil || !found {
		return rec, found, err //nolint:wrapcheck // the inner use case's error is the answer; wrapping it here would double-name the read
	}
	return q.search(ctx, rec), true, nil
}

func (q *searchedVulnQuery) GetLatestRecord(
	ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string,
) (vulndomain.VulnerabilityRecord, bool, error) {
	rec, found, err := q.inner.GetLatestRecord(ctx, coord, pipelineVersion)
	if err != nil || !found {
		return rec, found, err //nolint:wrapcheck // as above
	}
	return q.search(ctx, rec), true, nil
}

func (q *searchedVulnQuery) ListRecordsForModuleInWalk(
	ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion, walkID string,
) ([]vulndomain.VulnerabilityRecord, error) {
	recs, err := q.inner.ListRecordsForModuleInWalk(ctx, coord, pipelineVersion, walkID)
	if err != nil {
		return nil, fmt.Errorf("listing records in walk: %w", err)
	}
	return q.searchAll(ctx, recs), nil
}

func (q *searchedVulnQuery) ListRecordsForModule(
	ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string,
) ([]vulndomain.VulnerabilityRecord, error) {
	recs, err := q.inner.ListRecordsForModule(ctx, coord, pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("listing records for module: %w", err)
	}
	return q.searchAll(ctx, recs), nil
}

func (q *searchedVulnQuery) ListRecordsForModuleAllGenerations(
	ctx context.Context, coord coordinate.ModuleCoordinate,
) ([]vulndomain.VulnerabilityRecord, error) {
	recs, err := q.inner.ListRecordsForModuleAllGenerations(ctx, coord)
	if err != nil {
		return nil, fmt.Errorf("listing every generation for module: %w", err)
	}
	return q.searchAll(ctx, recs), nil
}

func (q *searchedVulnQuery) ListRecordsByFindingID(
	ctx context.Context, findingID, walkID string,
) ([]vulndomain.VulnerabilityRecord, error) {
	recs, err := q.inner.ListRecordsByFindingID(ctx, findingID, walkID)
	if err != nil {
		return nil, fmt.Errorf("listing records by finding id: %w", err)
	}
	return q.searchAll(ctx, recs), nil
}

func (q *searchedVulnQuery) ListRecordsForRun(
	ctx context.Context, runID string,
) ([]vulndomain.VulnerabilityRecord, error) {
	recs, err := q.inner.ListRecordsForRun(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("listing records for run: %w", err)
	}
	return q.searchAll(ctx, recs), nil
}

// ListRecordGenerationsForModule is a census of pipeline versions, not of
// records, so there is nothing here to search.
func (q *searchedVulnQuery) ListRecordGenerationsForModule(
	ctx context.Context, coord coordinate.ModuleCoordinate,
) ([]vulnports.VulnerabilityRecordGeneration, error) {
	gens, err := q.inner.ListRecordGenerationsForModule(ctx, coord)
	if err != nil {
		return nil, fmt.Errorf("listing record generations: %w", err)
	}
	return gens, nil
}

// searchedDiffScanRuns puts the findings a scan diff carries through the same
// search, so a rung the diff prints is the rung vuln-show prints for the same
// finding. The diff reads the store on its own path rather than through
// QueryVuln, and a surface left out of the search would state a different
// soundness for one stored answer, which is the disagreement this is wrapped
// once to prevent.
type searchedDiffScanRuns struct {
	inner    DiffScanRunsUseCase
	searcher negativeSearcher
}

// newSearchedDiffScanRuns returns uc with the search applied to its diff, or uc
// itself when there is no searcher to apply.
func newSearchedDiffScanRuns(uc DiffScanRunsUseCase, searcher negativeSearcher) DiffScanRunsUseCase {
	if searcher == nil {
		return uc
	}
	return &searchedDiffScanRuns{inner: uc, searcher: searcher}
}

func (d *searchedDiffScanRuns) Diff(ctx context.Context, runIDA, runIDB string) (vulndomain.ScanRunDiff, error) {
	diff, err := d.inner.Diff(ctx, runIDA, runIDB)
	if err != nil {
		return diff, fmt.Errorf("diffing scan runs: %w", err)
	}
	for _, deltas := range [][]vulndomain.FindingDelta{
		diff.NewFindings, diff.ResolvedFindings, diff.WithdrawnFindings,
	} {
		for i := range deltas {
			d.searchFinding(ctx, deltas[i].Coordinate, &deltas[i].Finding)
		}
	}
	for i := range diff.ReachabilityChanges {
		d.searchFinding(ctx, diff.ReachabilityChanges[i].Coordinate, &diff.ReachabilityChanges[i].Finding)
	}
	for i := range diff.UnresolvedFindings {
		d.searchFinding(ctx, diff.UnresolvedFindings[i].Coordinate, &diff.UnresolvedFindings[i].Finding)
	}
	return diff, nil
}

// searchFinding searches one finding the diff carries loose, out of the record
// it came from. The frame is read off the finding's own derivation, which is
// where the record's rooting was stamped precisely so a travelling finding does
// not have to be interpreted against a parent it no longer has.
func (d *searchedDiffScanRuns) searchFinding(
	ctx context.Context, coord coordinate.ModuleCoordinate, f *vulndomain.VulnerabilityFinding,
) {
	if f.Reachable == nil {
		return
	}
	rec := vulndomain.VulnerabilityRecord{
		Coordinate: coord,
		Rooting:    f.Reachable.DerivedBy.Rooting,
		Findings:   []vulndomain.VulnerabilityFinding{*f},
	}
	d.searcher.Search(ctx, &rec)
	*f = rec.Findings[0]
}
