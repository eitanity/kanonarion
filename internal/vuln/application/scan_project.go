package application

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// scanProjectRooted derives a per-module vulnerability verdict for a project
// walk from a single project-rooted scan of the resolved, pruned build graph the
// walk captured — the build the project actually produces — instead of scanning
// each dependency in isolation as its own main module. Findings attribute to the
// module that owns the vulnerable symbol; every other in-build module is
// analysed-and-clean. Because no dependency is re-resolved alone, the
// version-not-in-toolchain gap the isolated path manufactures cannot arise here.
//
// It writes one moduleResult per coordinate into out and persists each record,
// mirroring how the isolated worker pool persists via the module scanner, so the
// shared tally/status/run-persist path downstream is unchanged.
func (uc *ScanWalkUseCase) scanProjectRooted(
	ctx context.Context,
	walk walkdomain.WalkRecord,
	allCoords []coordinate.ModuleCoordinate,
	params ScanWalkParams,
	snapshot *domain.DatabaseSnapshot,
	vulnDBDir string,
	out map[coordinate.ModuleCoordinate]moduleResult,
) {
	root := walk.Target

	result, err := uc.moduleScanner.scanner.ScanProject(ctx, params.ProjectDir, *snapshot, vulnDBDir)
	if err != nil {
		uc.logger.Error("project-rooted scan failed", "root", root, "error", err)
		uc.fillProjectFault(ctx, allCoords, params, snapshot, out, domain.StatusScanFailed, "", "", err.Error())
		return
	}
	if result.Status == domain.StatusUnscannable || result.Status == domain.StatusScanFailed {
		// A genuine fault — no go.mod, OOM, a real build break — surfaces
		// honestly across the build rather than as a false clean.
		uc.logger.Warn("project-rooted scan could not analyse the project", "root", root, "status", result.Status)
		uc.fillProjectFault(ctx, allCoords, params, snapshot, out, result.Status, result.UnscanReason, result.UnscannableReason, result.ErrorDetail)
		return
	}

	for _, coord := range allCoords {
		// The synthetic standard-library node is analysed like any other module:
		// govulncheck already reasons over standard-library symbols when run against
		// the project, so the grouped parse attributes reachable stdlib advisories —
		// carrying Reachable and AffectedSymbols — to the {stdlib, ""} key.
		// projectFindingsFor resolves the node's toolchain-versioned coordinate to
		// that key, so the stdlib verdict is call-graph-analysed against the build,
		// consistent with fetched modules, rather than reachability-independent OSV
		// metadata.
		findings := copyFindings(projectFindingsFor(result.FindingsByModule, coord))

		// Every module here is a dependency of the live project: the analysis
		// examined it at its real version, so its silence is a reachability
		// answer. The project's own main module is versioned "(devel)" and never
		// coordinate-matches an advisory, so it does not reach the false case.
		findings, err := uc.mergeCoordinateFindings(ctx, coord, findings, true)
		if err != nil {
			// A coordinate whose advisory set could not be read has not been
			// checked. Reporting it Clean would be the exact false negative this
			// path is being fixed for, so it carries the fault instead.
			uc.logger.Error("project-rooted scan: advisory match by coordinate failed", "coordinate", coord, "error", err)
			rec := uc.persistProjectRecord(ctx, coord, nil, domain.StatusScanFailed, "", "", err.Error(), params, snapshot)
			out[coord] = moduleResult{coord: coord, record: rec}
			continue
		}

		status := domain.StatusClean
		if len(findings) > 0 {
			status = domain.StatusAffected
		}
		rec := uc.persistProjectRecord(ctx, coord, findings, status, "", "", "", params, snapshot)
		out[coord] = moduleResult{coord: coord, record: rec}
	}
}

// mergeCoordinateFindings matches coord's advisory set from the pinned snapshot
// and merges it with what the project-rooted analysis attributed to that module.
//
// It runs for every module in the build, unconditionally. Without it a Clean
// verdict on this path means only "the grouped parse attributed nothing here",
// which is indistinguishable from "the grouped parse dropped it" — one
// attribution failure silently converts an affected module into a clean one, and
// the run reads AllClean. With it, Clean means "advisories were matched and none
// applied", the same guarantee the isolated path gives, and the project-rooted
// analysis contributes reachability to the findings rather than deciding whether
// they are looked for at all.
//
// A finding the analysis reported wins: it carries the call path and symbols
// that whole-build analysis alone can establish. A coordinate match the analysis
// did not report is handled per reachabilityAnswerable. When true — the analysis
// examined this module at its real version from real entry points, as it does for
// every dependency — its silence about a symbol is an answer, so the match is
// added as not-reachable with high confidence. When false, the analysis could not
// have reported this advisory at all, so reachability was not computed and the
// match is added with a nil Reachable rather than a fabricated verdict. The only
// module where it is false is the analysis's own main module: a main module has
// no version, so version-range OSV matching never fires on it and its silence is
// structural inability, not a reachability answer. Findings are never dropped in
// either direction.
func (uc *ScanWalkUseCase) mergeCoordinateFindings(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	reported []domain.VulnerabilityFinding,
	reachabilityAnswerable bool,
) ([]domain.VulnerabilityFinding, error) {
	matched, err := uc.moduleScanner.database.LookupFindings(ctx, coord)
	if err != nil {
		return nil, fmt.Errorf("coordinate advisory match for %s: %w", coord, err)
	}
	seen := make(map[string]struct{}, len(reported))
	for _, f := range reported {
		seen[f.ID] = struct{}{}
	}
	added := 0
	for _, f := range matched {
		if _, ok := seen[f.ID]; ok {
			continue
		}
		if reachabilityAnswerable {
			f.Reachable = &domain.ReachabilityResult{IsReachable: false, Confidence: domain.ConfidenceHigh}
		}
		reported = append(reported, f)
		added++
	}
	if added > 0 {
		uc.logger.Info("project-rooted scan: advisories matched by coordinate the build analysis did not reach",
			"coordinate", coord, "matched", added, "reported_by_analysis", len(seen))
		// Record identity hashes over the findings, so a merged set must be
		// ordered rather than left as "whatever the analysis reported, then
		// whatever the coordinate match added".
		domain.SortFindings(reported)
	}
	return reported, nil
}

// projectFindingsFor returns the findings a project scan attributed to coord.
// The synthetic stdlib node is resolved to the version-less {stdlib, ""} key the
// grouped parse collapses every toolchain-tagged stdlib frame onto. Otherwise an
// exact coordinate match wins; a path-only match is the fallback for the rare
// case where govulncheck reports a version string that differs cosmetically from
// the walk node's (a pruned build carries one version per path, so this cannot
// mis-attribute between two versions of the same module).
func projectFindingsFor(byModule map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding, coord coordinate.ModuleCoordinate) []domain.VulnerabilityFinding {
	if coord.Path == domain.StdlibModulePath {
		return byModule[coordinate.ModuleCoordinate{Path: domain.StdlibModulePath}]
	}
	if fs, ok := byModule[coord]; ok {
		return fs
	}
	for k, fs := range byModule {
		if k.Path != domain.StdlibModulePath && k.Path == coord.Path {
			return fs
		}
	}
	return nil
}

// copyFindings returns a copy so a root record that appends stdlib findings does
// not mutate the shared slice the project scan attributed to a module.
func copyFindings(in []domain.VulnerabilityFinding) []domain.VulnerabilityFinding {
	if len(in) == 0 {
		return nil
	}
	out := make([]domain.VulnerabilityFinding, len(in))
	copy(out, in)
	return out
}

// fillProjectFault records the same honest fault status for every in-build
// module when the whole project scan could not be produced, so the coverage gap
// is visible per row rather than silently dropped.
func (uc *ScanWalkUseCase) fillProjectFault(
	ctx context.Context,
	allCoords []coordinate.ModuleCoordinate,
	params ScanWalkParams,
	snapshot *domain.DatabaseSnapshot,
	out map[coordinate.ModuleCoordinate]moduleResult,
	status domain.VulnerabilityStatus,
	unscanReason domain.UnscanReason,
	unscannableReason, errorDetail string,
) {
	for _, coord := range allCoords {
		rec := uc.persistProjectRecord(ctx, coord, nil, status, unscanReason, unscannableReason, errorDetail, params, snapshot)
		out[coord] = moduleResult{coord: coord, record: rec}
	}
}

// persistProjectRecord builds, hashes and persists one live project-rooted
// vulnerability record. Record identity (Ecosystem, timestamps, pipeline) is
// stamped here exactly as the module scanner stamps an isolated record, so the
// downstream tally, run persistence and queries treat both paths uniformly.
func (uc *ScanWalkUseCase) persistProjectRecord(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	findings []domain.VulnerabilityFinding,
	status domain.VulnerabilityStatus,
	unscanReason domain.UnscanReason,
	unscannableReason, errorDetail string,
	params ScanWalkParams,
	snapshot *domain.DatabaseSnapshot,
) domain.VulnerabilityRecord {
	now := uc.clock.Now()
	rec := domain.VulnerabilityRecord{
		Ecosystem:         fetchdomain.EcosystemGo,
		Coordinate:        coord,
		WalkID:            params.WalkID,
		Findings:          findings,
		OverallStatus:     status,
		UnscanReason:      unscanReason,
		UnscannableReason: unscannableReason,
		ErrorDetail:       errorDetail,
		DatabaseSnapshot:  *snapshot,
		ScannedAt:         now,
		FirstScannedAt:    now,
		PipelineVersion:   uc.pipelineVersion,
	}
	domain.SortFindings(rec.Findings)
	if hash, err := uc.moduleScanner.computeContentHash(rec); err != nil {
		uc.logger.Error("project-rooted scan: failed to compute content hash", "coordinate", coord, "error", err)
	} else {
		rec.ContentHash = hash
	}
	if perr := uc.vulnStore.PutVulnerabilityRecord(ctx, rec); perr != nil {
		uc.logger.Error("project-rooted scan: failed to persist record", "coordinate", coord, "error", perr)
	}
	return rec
}
