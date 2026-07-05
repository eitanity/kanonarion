package cli

import (
	"context"
	"fmt"
	"sort"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// vulnBatchCtx holds snapshot and scan-run data fetched once for a walk batch,
// eliminating redundant ListWalks / ListWalkScanRuns calls per module.
type vulnBatchCtx struct {
	hasSnapshot bool
	snap        vuldomain.DatabaseSnapshot
	// runs maps walkID → scan runs; populated for the walkLimit most recent walks.
	runs map[string][]vuldomain.WalkScanRun
	// walkUC backs the lazy graph loader used to filter walk-level annotations
	// by transitive reachability. nil when no snapshot exists.
	walkUC QueryWalksUseCase
	// graphCache memoises GetWalk per walkID. A nil entry records a load failure
	// so a missing/broken walk is not re-fetched per module.
	graphCache map[string]*walkdomain.Graph
	// affectedCache memoises the affected-module set per walkID.
	affectedCache map[string]map[fetchdomain.ModuleCoordinate]struct{}
}

func loadVulnBatchCtx(ctx context.Context, runsUC QueryScanRunsUseCase, walkUC QueryWalksUseCase) (*vulnBatchCtx, error) {
	const walkLimit = 10
	snap, found, err := runsUC.GetLatestSnapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading vuln snapshot: %w", err)
	}
	if !found {
		return &vulnBatchCtx{}, nil
	}
	walks, err := walkUC.ListWalks(ctx, walkports.WalkFilter{Limit: walkLimit})
	if err != nil {
		return nil, fmt.Errorf("listing walks: %w", err)
	}
	runsMap := make(map[string][]vuldomain.WalkScanRun, len(walks))
	for _, w := range walks {
		runs, err := runsUC.ListRunsForWalk(ctx, w.ID)
		if err != nil {
			continue
		}
		runsMap[w.ID] = runs
	}
	return &vulnBatchCtx{
		hasSnapshot:   true,
		snap:          snap,
		runs:          runsMap,
		walkUC:        walkUC,
		graphCache:    make(map[string]*walkdomain.Graph),
		affectedCache: make(map[string]map[fetchdomain.ModuleCoordinate]struct{}),
	}, nil
}

// graphFor lazily loads and caches the dependency graph for walkID. The second
// return is false when the graph cannot be loaded, in which case reachability
// filtering is skipped and the generic walk annotation is left intact.
func (b *vulnBatchCtx) graphFor(ctx context.Context, walkID string) (*walkdomain.Graph, bool) {
	if b.graphCache == nil || b.walkUC == nil {
		return nil, false
	}
	if g, ok := b.graphCache[walkID]; ok {
		return g, g != nil
	}
	rec, err := b.walkUC.GetWalk(ctx, walkID)
	if err != nil {
		b.graphCache[walkID] = nil
		return nil, false
	}
	g := rec.Graph
	b.graphCache[walkID] = &g
	return &g, true
}

// affectedFor lazily computes and caches the set of module coordinates that are
// Affected in the most recent scan run for walkID. A module whose record is
// unreadable is included conservatively: it was part of the scan but cannot be
// confirmed Clean (absence is never presented as a confident negative).
func (b *vulnBatchCtx) affectedFor(ctx context.Context, walkID string, vulnUC QueryVulnUseCase) map[fetchdomain.ModuleCoordinate]struct{} {
	if b.affectedCache == nil {
		return nil
	}
	if s, ok := b.affectedCache[walkID]; ok {
		return s
	}
	runs := b.runs[walkID]
	affected := make(map[fetchdomain.ModuleCoordinate]struct{})
	if len(runs) > 0 {
		run := runs[0] // most recent (DESC by started_at)
		for coord := range run.PerModuleResults {
			rec, found, err := vulnUC.GetLatestRecordForWalk(ctx, coord, vulnPipelineVersion, run.WalkID)
			if err != nil || !found {
				affected[coord] = struct{}{}
				continue
			}
			if rec.OverallStatus == vuldomain.StatusAffected {
				affected[coord] = struct{}{}
			}
		}
	}
	b.affectedCache[walkID] = affected
	return affected
}

// filterWalkAnnotation replaces the generic walk-level vulnerability annotation
// with the specific affected peers that lie in coord's own transitive
// dependency closure. A walk-level "Affected" status only matters to this
// module when an affected peer is actually reachable from it; otherwise the
// annotation implies a relationship that does not exist, so it is suppressed.
//
// Non-Affected walk statuses (e.g. Partial) describe scan completeness rather
// than affected peers, so they are left untouched. The annotation is also left
// intact when the module's own status already matches the walk status (nothing
// to filter) or when the graph cannot be loaded (no basis to narrow it).
func (b *vulnBatchCtx) filterWalkAnnotation(ctx context.Context, result *contextVulnerabilities, coord fetchdomain.ModuleCoordinate, run vuldomain.WalkScanRun, vulnUC QueryVulnUseCase) {
	if result.WalkStatus == "" || result.WalkStatus == result.Status {
		return
	}
	if run.OverallStatus != vuldomain.WalkStatusAffected {
		return
	}
	graph, ok := b.graphFor(ctx, run.WalkID)
	if !ok {
		return
	}

	reachable := graph.ReachableFrom(coord)
	affected := b.affectedFor(ctx, run.WalkID, vulnUC)

	var peers []string
	for ac := range affected {
		if ac == coord {
			continue
		}
		if _, inClosure := reachable[ac]; inClosure {
			peers = append(peers, ac.String())
		}
	}
	sort.Strings(peers)

	if len(peers) == 0 {
		// No affected peer in this module's dependency closure: the walk-level
		// status is irrelevant to this module. Suppress the annotation entirely.
		result.WalkStatus = ""
		return
	}
	result.WalkAffected = peers
}

func buildVulnerabilitiesFromBatch(ctx context.Context, coord fetchdomain.ModuleCoordinate, vulnUC QueryVulnUseCase, batch *vulnBatchCtx) contextVulnerabilities {
	// A store read failure must surface as read_error like every other
	// section — analysed-but-unreadable presented as not_run is the
	// absence-as-answer defect class. A later run may still read
	// fine, so remember the first error and keep going.
	var readErr error
	for _, runs := range batch.runs {
		for _, run := range runs {
			if _, ok := run.PerModuleResults[coord]; !ok {
				continue
			}
			// Use run.Snapshot (the snapshot used during the scan), not the latest snapshot.
			rec, found, err := vulnUC.GetRecord(ctx, coord, vulnPipelineVersion, run.Snapshot)
			if err != nil {
				if readErr == nil {
					readErr = err
				}
				continue
			}
			if !found {
				continue
			}
			result := vulnRecordToContext(&rec, string(run.OverallStatus))
			batch.filterWalkAnnotation(ctx, &result, coord, run, vulnUC)
			return result
		}
	}
	// Fall back to GetLatestVulnerabilityRecord in case the module was scanned
	// outside the batch's walk window.
	rec, found, err := vulnUC.GetLatestRecord(ctx, coord, vulnPipelineVersion)
	switch {
	case err != nil:
		return contextVulnerabilities{Status: sectionStatusReadError, Error: err.Error()}
	case found:
		return vulnRecordToContext(&rec, "")
	case readErr != nil:
		return contextVulnerabilities{Status: sectionStatusReadError, Error: readErr.Error()}
	}
	return contextVulnerabilities{Status: sectionStatusNotRun}
}

func vulnRecordToContext(rec *vuldomain.VulnerabilityRecord, walkStatus string) contextVulnerabilities {
	out := contextVulnerabilities{
		ExtractedAt:     isoTime(rec.ScannedAt),
		Status:          string(rec.OverallStatus),
		WalkStatus:      walkStatus,
		Reason:          rec.UnscannableReason,
		WalkID:          rec.WalkID,
		LastValidatedAt: isoTime(rec.ScannedAt),
		SnapshotVersion: rec.DatabaseSnapshot.Version,
	}
	if !rec.FirstScannedAt.IsZero() {
		out.FirstValidatedAt = isoTime(rec.FirstScannedAt)
	}
	if !rec.DatabaseSnapshot.RetrievedAt.IsZero() {
		out.SnapshotRetrievedAt = isoTime(rec.DatabaseSnapshot.RetrievedAt)
		out.SnapshotAgeDays = vuldomain.SnapshotAgeDays(rec.ScannedAt, rec.DatabaseSnapshot.RetrievedAt)
	}
	for _, f := range rec.Findings {
		cve := contextCVE{
			ID:      f.ID,
			Aliases: f.Aliases,
			Summary: f.Summary,
			FixedIn: f.FixedIn,
		}
		if f.Severity != nil {
			cve.Score = f.Severity.Score
		}
		if f.Reachable != nil {
			r := f.Reachable.IsReachable
			cve.Reachable = &r
		}
		out.Findings = append(out.Findings, cve)
	}
	return out
}
