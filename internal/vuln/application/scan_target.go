package application

import (
	"context"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// scanTargetRooted derives a per-module verdict for a coordinate-keyed walk from
// a single scan rooted at the walk target, the way scanProjectRooted does for a
// walk rooted at a local project. It reports whether it produced verdicts; false
// leaves finalResults untouched so the caller falls back to isolated per-module
// scanning.
//
// The defect it exists to remove is on the package axis. Scanning a dependency
// in isolation points `govulncheck ./...` at that dependency, and `./...`
// matches every package it contains regardless of whether any consumer can
// reach it — commands (which are unimportable by definition), examples, and
// internal tooling. Each such package drags in its own imports, which demand
// module versions the target's build has no reason to hold, so the module is
// recorded as a coverage gap because a package the target never builds could not
// be loaded. Supplying the missing versions would not fix that; it would mean
// analysing code the build never links.
//
// Rooting at the target instead makes package loading import-driven, which is
// how Go selects packages: loading starts at the pattern's packages and follows
// imports. A dependency therefore contributes exactly the packages the target
// imports. Unimportable commands fall out as a consequence rather than as a
// special case, and so do library packages no consumer reaches — the larger set,
// and the one an exclusion rule for main packages could never have addressed.
//
// Falling back rather than filling a fault across the walk is deliberate. A
// target that cannot be built as a whole would otherwise take every module in
// the graph down with it, turning one module's build failure into a walk-wide
// coverage gap; the isolated path still answers per module, which is a worse
// analysis but a real one.
func (uc *ScanWalkUseCase) scanTargetRooted(
	ctx context.Context,
	walk walkdomain.WalkRecord,
	allCoords []coordinate.ModuleCoordinate,
	params ScanWalkParams,
	snapshot *domain.DatabaseSnapshot,
	vulnDBDir, goModCache string,
	buildList map[coordinate.ModuleCoordinate]struct{},
	out map[coordinate.ModuleCoordinate]moduleResult,
) bool {
	target := walk.Target

	fact, ok, err := uc.moduleScanner.getFetchRecord(ctx, target)
	if err != nil {
		uc.logger.Warn("target-rooted scan: could not read the target's fetch record, falling back to isolated scans",
			"target", target, "error", err)
		return false
	}
	if !ok {
		// A shallow walk holds no zip for the target, so there is nothing to root
		// the analysis at. The isolated path is the honest answer here.
		uc.logger.Info("target-rooted scan: target module not in the blob store, falling back to isolated scans",
			"target", target)
		return false
	}

	blob, err := uc.moduleScanner.blobs.Get(ctx, fetchports.BlobHandle(fact.ContentLocation))
	if err != nil {
		uc.logger.Warn("target-rooted scan: could not retrieve the target's module content, falling back to isolated scans",
			"target", target, "error", err)
		return false
	}
	defer func() { _ = blob.Close() }()

	result, err := uc.moduleScanner.scanner.ScanTargetModule(ctx, ports.TargetScanRequest{
		Coordinate:   target,
		ModuleSource: blob,
		Snapshot:     *snapshot,
		GoModCache:   goModCache,
		DBDir:        vulnDBDir,
		BuildList:    buildList,
	})
	if err != nil {
		uc.logger.Warn("target-rooted scan failed, falling back to isolated scans", "target", target, "error", err)
		return false
	}
	if result.Status == domain.StatusUnscannable || result.Status == domain.StatusScanFailed {
		uc.logger.Warn("target-rooted scan could not analyse the target, falling back to isolated scans",
			"target", target, "status", result.Status, "reason", result.UnscannableReason, "error_detail", result.ErrorDetail)
		return false
	}

	for _, coord := range allCoords {
		findings := copyFindings(projectFindingsFor(result.FindingsByModule, coord))

		// Coordinate matching runs for every module, unconditionally. The target is
		// the main module of this analysis and a main module has no version, so the
		// analysis alone could never match an advisory about the target itself; and
		// for any module, a Clean verdict must mean "advisories were matched and
		// none applied" rather than "the grouped parse attributed nothing here".
		//
		// Reachability is answerable for every module except the target. A
		// dependency was analysed at its real version from the target's entry
		// points, so a coordinate match the analysis did not report was genuinely
		// not reached. The target itself was the versionless main module, which
		// OSV matching structurally cannot reach a verdict on, so its coordinate
		// matches carry no reachability rather than a fabricated not-reachable.
		findings, err := uc.mergeCoordinateFindings(ctx, coord, findings, coord != target)
		if err != nil {
			// A coordinate whose advisory set could not be read has not been
			// checked. Recording it Clean would be a false negative, so it carries
			// the fault instead.
			uc.logger.Error("target-rooted scan: advisory match by coordinate failed", "coordinate", coord, "error", err)
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
	uc.logger.Info("target-rooted scan derived verdicts for the walk", "target", target, "modules", len(allCoords))
	return true
}
