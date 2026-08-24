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
// scanning. A store that refused one of the records it derived is returned as an
// error instead of a fallback: a write failure is not an analysis failure the
// isolated path could answer better, so retrying per module would only repeat it
// while the run went on claiming verdicts it had not kept.
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
//
// The fallback is not free of consequence, and frameGaps is where the cost is
// recorded. When the target itself could not be LOADED, the run's own frame
// produced nothing about the target: a record from any other frame — an isolated
// scan, whether run now or reused from an earlier walk — answers a different
// question and must not be counted as this run's coverage of its own root. The
// target is entered into frameGaps with a record stating the refusal, and the
// caller counts that rather than the fallback's, so the run reports Partial
// coverage instead of a completeness it never established.
func (uc *ScanWalkUseCase) scanTargetRooted(
	ctx context.Context,
	walk walkdomain.WalkRecord,
	allCoords []coordinate.ModuleCoordinate,
	params ScanWalkParams,
	snapshot *domain.DatabaseSnapshot,
	vulnDBDir, goModCache string,
	buildList map[coordinate.ModuleCoordinate]struct{},
	out map[coordinate.ModuleCoordinate]moduleResult,
	frameGaps map[coordinate.ModuleCoordinate]domain.VulnerabilityRecord,
) (bool, error) {
	target := walk.Target
	root := target
	// Fetched surface, unconditionally. This path roots the analysis at the
	// target's published zip extracted into a scratch directory; there is no
	// working tree, so there is no vendor/ tree that could be the surface.

	fact, ok, err := uc.moduleScanner.getFetchRecord(ctx, target)
	if err != nil {
		uc.logger.Warn("target-rooted scan: could not read the target's fetch record, falling back to isolated scans",
			"target", target, "error", err)
		return false, nil
	}
	if !ok || fact.IsGoModOnly() {
		// A shallow walk holds no zip for the target, so there is nothing to root
		// the analysis at. A go.mod-only record likewise carries no source. Either
		// way the isolated path is the honest answer here.
		uc.logger.Info("target-rooted scan: target module has no source in the blob store, falling back to isolated scans",
			"target", target)
		return false, nil
	}

	zipIdentity, hasZip, err := fetchports.ZipIdentity(fact)
	if err != nil || !hasZip {
		uc.logger.Info("target-rooted scan: the target's fact record names no module zip, falling back to isolated scans",
			"target", target)
		return false, nil
	}
	blob, err := uc.moduleScanner.blobs.Get(ctx, zipIdentity)
	if err != nil {
		uc.logger.Warn("target-rooted scan: could not retrieve the target's module content, falling back to isolated scans",
			"target", target, "error", err)
		return false, nil
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
		return false, nil
	}
	// A scan that extracted its own advisory database counted it. Rebind the
	// local snapshot — not the caller's, which the run row already names — so
	// every record built below states the database this analysis consulted.
	counted, cerr := snapshotCountingAdvisories(*snapshot, result.AdvisoryCount)
	if cerr != nil {
		return false, cerr
	}
	snapshot = &counted

	if result.Status == domain.StatusUnscannable || result.Status == domain.StatusScanFailed {
		uc.logger.Warn("target-rooted scan could not analyse the target, falling back to isolated scans",
			"target", target, "status", result.Status, "reason", result.UnscannableReason, "error_detail", result.ErrorDetail)
		rec, perr := uc.recordTargetFrameGap(ctx, root, result, params, snapshot)
		if perr != nil {
			return false, perr
		}
		frameGaps[target] = rec
		return false, nil
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
		findings, err := uc.mergeCoordinateFindings(ctx, coord, findings, coord != target, *snapshot)
		if err != nil {
			// A coordinate whose advisory set could not be read has not been
			// checked. Recording it Clean would be a false negative, so it carries
			// the fault instead.
			uc.logger.Error("target-rooted scan: advisory match by coordinate failed", "coordinate", coord, "error", err)
			rec, perr := uc.persistProjectRecord(ctx, root, coord, nil, domain.StatusScanFailed, "", "", err.Error(), domain.AnalysisSurfaceFetched, result.Toolchain, params, snapshot)
			if perr != nil {
				return false, perr
			}
			out[coord] = moduleResult{coord: coord, record: rec}
			continue
		}

		// The findings decide the word, not their count: every match may name an
		// advisory that has since been retracted, and that is not an Affected verdict.
		status := domain.DetermineRecordOverallStatus(
			domain.CoverageAnalysed, domain.DetermineFindingsAxis(findings),
		)
		rec, perr := uc.persistProjectRecord(ctx, root, coord, findings, status, "", "", "", domain.AnalysisSurfaceFetched, result.Toolchain, params, snapshot)
		if perr != nil {
			return false, perr
		}
		out[coord] = moduleResult{coord: coord, record: rec}
	}
	uc.logger.Info("target-rooted scan derived verdicts for the walk", "target", target, "modules", len(allCoords))
	return true, nil
}

// recordTargetFrameGap persists the run's own statement that it could not root
// an analysis at its target, and returns it for the caller to count.
//
// The record is written in the run's frame — target-rooted at the target — and
// that is the whole point of writing it. Before it existed the failure was
// logged and nothing else: the run row kept no trace, the isolated fallback
// supplied a record for the target from a different frame, and the tally counted
// that as the run's coverage. On a warm store the fallback did not even scan —
// it served a cached isolated record written by an unrelated walk — so a run
// that performed no analysis at all reported Complete coverage and a Clean
// verdict, which is the shape of an un-run scan being indistinguishable from a
// passing one.
//
// The reason code is the scanner's own when it classified one, and
// target-load-failed when it did not. A ScanFailed result is the unclassified
// case: the toolchain refused before any pattern the classifier recognises could
// be matched, which is exactly the load failure the code names.
func (uc *ScanWalkUseCase) recordTargetFrameGap(
	ctx context.Context,
	root coordinate.ModuleCoordinate,
	result domain.ProjectScanResult,
	params ScanWalkParams,
	snapshot *domain.DatabaseSnapshot,
) (domain.VulnerabilityRecord, error) {
	reason := result.UnscanReason
	if reason == "" {
		reason = domain.UnscanReasonTargetLoadFailed
	}
	note := result.UnscannableReason
	if note == "" {
		note = "the analysis could not be rooted at this module: the toolchain did not load its packages"
	}
	// No findings. The analysis never ran, so there is nothing it could have
	// found, and an empty findings list here states absence of evidence rather
	// than evidence of absence — the coverage axis, which this record sets to
	// Unscannable, is what carries that distinction.
	rec, err := uc.persistProjectRecord(
		ctx, root, root, nil, domain.StatusUnscannable,
		reason, note, result.ErrorDetail,
		domain.AnalysisSurfaceFetched, result.Toolchain, params, snapshot,
	)
	if err != nil {
		return domain.VulnerabilityRecord{}, err
	}
	return rec, nil
}
