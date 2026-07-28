package cli

import (
	"context"
	"fmt"
	"sort"

	"github.com/eitanity/kanonarion/internal/coordinate"

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
	affectedCache map[string]map[coordinate.ModuleCoordinate]struct{}
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
		affectedCache: make(map[string]map[coordinate.ModuleCoordinate]struct{}),
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
// Affected in the most recent scan run for walkID.
//
// A store read error is a fault, not a verdict: it is propagated, never
// fabricated into an Affected entry — presenting a peer as affected when the
// store could only not be read is the same absence/error-as-answer defect this
// codebase removes elsewhere. A not-found record is a coverage gap (the run
// lists the coordinate but nothing backs a verdict): it is no evidence of
// Affected, so it is skipped rather than fabricated. Only a real StatusAffected
// record adds a coordinate. A failed read is not cached, so a later read may
// still succeed.
func (b *vulnBatchCtx) affectedFor(ctx context.Context, walkID string, vulnUC QueryVulnUseCase) (map[coordinate.ModuleCoordinate]struct{}, error) {
	if b.affectedCache == nil {
		return nil, nil
	}
	if s, ok := b.affectedCache[walkID]; ok {
		return s, nil
	}
	runs := b.runs[walkID]
	affected := make(map[coordinate.ModuleCoordinate]struct{})
	if len(runs) > 0 {
		run := runs[0] // most recent (DESC by started_at)
		for coord := range run.PerModuleResults {
			rec, found, err := vulnUC.GetLatestRecordForWalk(ctx, coord, vulnPipelineVersion, run.WalkID)
			if err != nil {
				return nil, fmt.Errorf("reading walk-peer verdict for %s in walk %s: %w", coord, run.WalkID, err)
			}
			if !found {
				continue
			}
			// "Is this peer affected" is a findings question, so it is asked of the
			// findings axis. The collapsed word answers it only for a module that
			// was analysed: a metadata-only peer whose coordinate matched an advisory
			// carries the finding on the axis, and reading the word would have
			// dropped it from the closure the moment its coverage word won the
			// collapse.
			if _, findings := vuldomain.RecordAxes(rec); findings == vuldomain.FindingsRecordAffected {
				affected[coord] = struct{}{}
			}
		}
	}
	b.affectedCache[walkID] = affected
	return affected, nil
}

// filterWalkAnnotation names the affected peers that lie in coord's own
// transitive dependency closure, so the walk-level finding is surfaced only
// where it is actionable for this module.
//
// It is driven by the findings axis alone (run.FindingsStatus): a run that found
// vulnerabilities may carry an affected peer in this module's closure regardless
// of whether coverage was complete. Keying on the collapsed OverallStatus was
// the collapse defect — a single unscannable module made the run Partial, so this
// narrowing never ran and a reachable advisory in a direct dependency was
// silently dropped. The coverage axis is carried independently on
// result.WalkCoverage and rendered separately, so an incomplete-coverage run no
// longer suppresses a real finding. The graph is required to narrow to the
// closure; when it cannot be loaded there is no basis to narrow, so no peer is
// named.
func (b *vulnBatchCtx) filterWalkAnnotation(ctx context.Context, result *contextVulnerabilities, coord coordinate.ModuleCoordinate, run vuldomain.WalkScanRun, vulnUC QueryVulnUseCase) {
	if run.FindingsStatus != vuldomain.FindingsAffected {
		return
	}
	graph, ok := b.graphFor(ctx, run.WalkID)
	if !ok {
		return
	}

	reachable := graph.ReachableFrom(coord)
	affected, err := b.affectedFor(ctx, run.WalkID, vulnUC)
	if err != nil {
		// A peer's verdict could not be read. Do not fabricate an affected peer
		// from a store fault, and do not misattribute the fault to this module's
		// own verdict (which read fine) by turning the whole section into a read
		// error. Record the fault so the peer set reads as uncertain rather than
		// as a confident finding.
		result.WalkError = err.Error()
		return
	}

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
	result.WalkAffected = peers
}

func buildVulnerabilitiesFromBatch(ctx context.Context, coord coordinate.ModuleCoordinate, vulnUC QueryVulnUseCase, batch *vulnBatchCtx) contextVulnerabilities {
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
			result := vulnRecordToContext(&rec, string(run.OverallStatus), walkCoverageCaveat(run))
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
		return vulnRecordToContext(&rec, "", "")
	case readErr != nil:
		return contextVulnerabilities{Status: sectionStatusReadError, Error: readErr.Error()}
	}
	return contextVulnerabilities{Status: sectionStatusNotRun}
}

// walkCoverageCaveat returns the coverage-axis annotation for a run when it left
// modules unanalysed, and empty when coverage is complete (or unknown, as on a
// legacy run whose CoverageStatus was never stored). It is independent of the
// findings axis: an incomplete-coverage run carries this caveat whether or not
// it also found a vulnerability.
func walkCoverageCaveat(run vuldomain.WalkScanRun) string {
	switch run.CoverageStatus {
	case vuldomain.CoveragePartial, vuldomain.CoverageFailed:
		return string(run.CoverageStatus)
	default:
		return ""
	}
}

func vulnRecordToContext(rec *vuldomain.VulnerabilityRecord, walkStatus, walkCoverage string) contextVulnerabilities {
	out := contextVulnerabilities{
		ExtractedAt:     isoTime(rec.ScannedAt),
		Status:          string(rec.OverallStatus),
		WalkStatus:      walkStatus,
		WalkCoverage:    walkCoverage,
		Reason:          rec.UnscannableReason,
		WalkID:          rec.WalkID,
		LastValidatedAt: isoTime(rec.ScannedAt),
		SnapshotVersion: rec.DatabaseSnapshot.Version,
		PipelineVersion: rec.PipelineVersion,
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
