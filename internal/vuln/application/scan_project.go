package application

import (
	"context"

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
	allCoords []fetchdomain.ModuleCoordinate,
	params ScanWalkParams,
	snapshot *domain.DatabaseSnapshot,
	vulnDBDir string,
	out map[fetchdomain.ModuleCoordinate]moduleResult,
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
		status := domain.StatusClean
		if len(findings) > 0 {
			status = domain.StatusAffected
		}
		rec := uc.persistProjectRecord(ctx, coord, findings, status, "", "", "", params, snapshot)
		out[coord] = moduleResult{coord: coord, record: rec}
	}
}

// projectFindingsFor returns the findings a project scan attributed to coord.
// The synthetic stdlib node is resolved to the version-less {stdlib, ""} key the
// grouped parse collapses every toolchain-tagged stdlib frame onto. Otherwise an
// exact coordinate match wins; a path-only match is the fallback for the rare
// case where govulncheck reports a version string that differs cosmetically from
// the walk node's (a pruned build carries one version per path, so this cannot
// mis-attribute between two versions of the same module).
func projectFindingsFor(byModule map[fetchdomain.ModuleCoordinate][]domain.VulnerabilityFinding, coord fetchdomain.ModuleCoordinate) []domain.VulnerabilityFinding {
	if coord.Path == domain.StdlibModulePath {
		return byModule[fetchdomain.ModuleCoordinate{Path: domain.StdlibModulePath}]
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
	allCoords []fetchdomain.ModuleCoordinate,
	params ScanWalkParams,
	snapshot *domain.DatabaseSnapshot,
	out map[fetchdomain.ModuleCoordinate]moduleResult,
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
	coord fetchdomain.ModuleCoordinate,
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
	rec.ContentHash = uc.moduleScanner.computeContentHash(rec)
	if perr := uc.vulnStore.PutVulnerabilityRecord(ctx, rec); perr != nil {
		uc.logger.Error("project-rooted scan: failed to persist record", "coordinate", coord, "error", perr)
	}
	return rec
}
