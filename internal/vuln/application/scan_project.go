package application

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
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
// shared tally/status/run-persist path downstream is unchanged. A record the
// store would not accept is returned as an error, because the tally downstream
// reads out as the run's set of stored verdicts.
func (uc *ScanWalkUseCase) scanProjectRooted(
	ctx context.Context,
	walk walkdomain.WalkRecord,
	allCoords []coordinate.ModuleCoordinate,
	params ScanWalkParams,
	snapshot *domain.DatabaseSnapshot,
	vulnDBDir string,
	closure ports.VendoredClosure,
	out map[coordinate.ModuleCoordinate]moduleResult,
) error {
	root := walk.Target

	// The surface this run asked for. The scanner reports back the one it could
	// actually use, which is what every record names; this stands in only when
	// the scan failed before reporting anything, so a fault is still filed under
	// the regime the run was operating in rather than under a blank field.
	requested := domain.AnalysisSurfaceFetched
	if closure.Vendored {
		requested = domain.AnalysisSurfaceVendored
	}

	result, err := uc.moduleScanner.scanner.ScanProject(ctx, ports.ProjectScanRequest{
		ProjectDir: params.ProjectDir,
		Snapshot:   *snapshot,
		DBDir:      vulnDBDir,
		Vendored:   closure.Vendored,
	})
	if err != nil {
		uc.logger.Error("project-rooted scan failed", "root", root, "error", err)
		return uc.fillProjectFault(ctx, root, allCoords, params, snapshot, closure, requested, out, domain.StatusScanFailed, "", "", err.Error())
	}
	// A scan that extracted its own advisory database counted it. Rebind the
	// local snapshot — not the caller's, which the run row already names — so
	// every record built below states the database this analysis consulted.
	counted, cerr := snapshotCountingAdvisories(*snapshot, result.AdvisoryCount)
	if cerr != nil {
		return cerr
	}
	snapshot = &counted

	surface := result.AnalysisSurface
	if surface == "" {
		surface = requested
	}
	if result.Status == domain.StatusUnscannable || result.Status == domain.StatusScanFailed {
		// A genuine fault — no go.mod, OOM, a real build break — surfaces
		// honestly across the build rather than as a false clean.
		uc.logger.Warn("project-rooted scan could not analyse the project",
			"root", root, "status", result.Status, "analysis_surface", string(surface))
		return uc.fillProjectFault(ctx, root, allCoords, params, snapshot, closure, surface, out, result.Status, result.UnscanReason, result.UnscannableReason, result.ErrorDetail)
	}

	for _, coord := range allCoords {
		// A module the vendored tree does not hold contributed nothing to the
		// analysed build, and the honest record says so. The alternative — fetch
		// this one module from the store and scan it in isolation to fill the gap —
		// would answer a question about bytes the project does not compile, under a
		// verdict a reader would take for the build's. That substitution is the
		// defect the vendored surface exists to close, so the gap is recorded
		// instead.
		if reason, absent := absentFromVendor(surface, closure, coord, root); absent {
			rec, perr := uc.persistProjectRecord(ctx, root, coord, nil, domain.StatusUnscannable,
				domain.UnscanReasonAbsentFromVendor, reason, "", surface, params, snapshot)
			if perr != nil {
				return perr
			}
			out[coord] = moduleResult{coord: coord, record: rec}
			continue
		}

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
		findings, err := uc.mergeCoordinateFindings(ctx, coord, findings, true, *snapshot)
		if err != nil {
			// A coordinate whose advisory set could not be read has not been
			// checked. Reporting it Clean would be the exact false negative this
			// path is being fixed for, so it carries the fault instead.
			uc.logger.Error("project-rooted scan: advisory match by coordinate failed", "coordinate", coord, "error", err)
			rec, perr := uc.persistProjectRecord(ctx, root, coord, nil, domain.StatusScanFailed, "", "", err.Error(), surface, params, snapshot)
			if perr != nil {
				return perr
			}
			out[coord] = moduleResult{coord: coord, record: rec}
			continue
		}

		// The findings decide the word, not their count: every match may name an
		// advisory that has since been retracted, and that is not an Affected verdict.
		status := domain.DetermineRecordOverallStatus(
			domain.CoverageAnalysed, domain.DetermineFindingsAxis(findings),
		)
		rec, perr := uc.persistProjectRecord(ctx, root, coord, findings, status, "", "", "", surface, params, snapshot)
		if perr != nil {
			return perr
		}
		out[coord] = moduleResult{coord: coord, record: rec}
	}
	return nil
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
// An advisory both sources report is merged FIELD BY FIELD, per the authority
// table on domain.MergeCoordinateMatches. The analysis keeps the call path, the
// symbols and the reachability answer that whole-build analysis alone can
// establish, and the match contributes the advisory's affected range, which the
// analysis route never sets. Taking the analysis finding whole instead — which
// is what this did — meant one advisory was stored in two shapes depending on
// which route reached it, in fields that are sealed and content-hashed.
//
// A coordinate match the analysis did not report is handled per
// reachabilityAnswerable. When true — the analysis examined this module at its
// real version from real entry points, as it does for
// every dependency — its silence about a symbol is an answer, so the match is
// added as not-reachable with high confidence. When false, the analysis could not
// have reported this advisory at all, so reachability was not computed and the
// match is added with a nil Reachable rather than a fabricated verdict. The only
// module where it is false is the analysis's own main module: a main module has
// no version, so version-range OSV matching never fires on it and its silence is
// structural inability, not a reachability answer. Findings are never dropped in
// either direction.
//
// snapshot is the advisory database this run is judged against, and it is the
// database the match is made in. It is passed rather than left to the adapter
// because the derived-from-silence verdict below is only sound while the two
// routes read one database, and nothing else enforces that.
func (uc *ScanWalkUseCase) mergeCoordinateFindings(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	reported []domain.VulnerabilityFinding,
	reachabilityAnswerable bool,
	snapshot domain.DatabaseSnapshot,
) ([]domain.VulnerabilityFinding, error) {
	matched, err := uc.moduleScanner.database.LookupFindings(ctx, coord, snapshot)
	if err != nil {
		return nil, fmt.Errorf("coordinate advisory match for %s: %w", coord, err)
	}
	analysed := len(reported)
	merged, added := domain.MergeCoordinateMatches(reported, matched, func(f *domain.VulnerabilityFinding) {
		if !reachabilityAnswerable {
			return
		}
		// The derivation is stated even though this answer has no route, and
		// having none is the point: it is govulncheck's SILENCE about the
		// module, not a path it traced. The instrument and its fidelity are
		// what make that silence an answer — the analysis examined this module
		// at its real version from real entry points — so an answer that did
		// not name them would be indistinguishable from one no analyser
		// produced at all.
		//
		// THE SILENCE IS ONLY EVIDENCE ABOUT AN ADVISORY THE ANALYSER WAS
		// GIVEN. An advisory absent from the database govulncheck read is one
		// it could not have reported whatever the code does, so its silence
		// says nothing and a not-reachable derived from it is manufactured.
		// That premise used to rest on nothing: the analysis was handed the
		// pinned snapshot while the match above read the live service, so on
		// any host whose snapshot had fallen behind, every advisory published
		// since arrived here and was stamped not-reachable at high confidence.
		// It now rests on the snapshot parameter — one database, named by the
		// record, read by both routes — which is why that parameter exists.
		//
		// It reaches only an advisory the analysis never reported. Where the
		// analysis did report one, its own reachability answer stands and this
		// derived-from-silence verdict must never displace it.
		f.Reachable = &domain.ReachabilityResult{
			IsReachable: false,
			Confidence:  domain.ConfidenceHigh,
			DerivedBy: domain.ReachabilityDerivation{
				Analyser: domain.AnalyserGovulncheck,
				Fidelity: string(domain.ScanModeSource),
			},
		}
	})
	if added > 0 {
		uc.logger.Info("project-rooted scan: advisories matched by coordinate the build analysis did not reach",
			"coordinate", coord, "matched", added, "reported_by_analysis", analysed)
	}
	return merged, nil
}

// projectFindingsFor returns the findings a project scan attributed to coord.
// The synthetic stdlib node is resolved to the version-less {stdlib, ""} key the
// grouped parse collapses every toolchain-tagged stdlib frame onto. Otherwise an
// exact coordinate match wins; a path-only match is the fallback for the rare
// case where govulncheck reports a version string that differs cosmetically from
// the walk node's (a pruned build carries one version per path, so this cannot
// mis-attribute between two versions of the same module).
func projectFindingsFor(byModule map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding, coord coordinate.ModuleCoordinate) []domain.VulnerabilityFinding {
	if coord.Path() == domain.StdlibModulePath {
		return byModule[coordinate.NewStdlibCoordinate()]
	}
	if fs, ok := byModule[coord]; ok {
		return fs
	}
	for k, fs := range byModule {
		if k.Path() != domain.StdlibModulePath && k.Path() == coord.Path() {
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
//
// The gap is only visible if the rows are there, so a write the store refused is
// returned as an error rather than skipped.
//
// A module the vendored tree does not hold keeps its own, more specific reason
// even here. The whole-project fault says the build did not analyse; absence
// from vendor/ says why this particular module could not have been in it, and
// collapsing the two would hide a structural gap behind a transient one.
func (uc *ScanWalkUseCase) fillProjectFault(
	ctx context.Context,
	root coordinate.ModuleCoordinate,
	allCoords []coordinate.ModuleCoordinate,
	params ScanWalkParams,
	snapshot *domain.DatabaseSnapshot,
	closure ports.VendoredClosure,
	surface domain.AnalysisSurface,
	out map[coordinate.ModuleCoordinate]moduleResult,
	status domain.VulnerabilityStatus,
	unscanReason domain.UnscanReason,
	unscannableReason, errorDetail string,
) error {
	for _, coord := range allCoords {
		coordStatus, coordUnscan, coordReason, coordDetail := status, unscanReason, unscannableReason, errorDetail
		if reason, absent := absentFromVendor(surface, closure, coord, root); absent {
			coordStatus, coordUnscan, coordReason, coordDetail = domain.StatusUnscannable, domain.UnscanReasonAbsentFromVendor, reason, ""
		}
		rec, err := uc.persistProjectRecord(ctx, root, coord, nil, coordStatus, coordUnscan, coordReason, coordDetail, surface, params, snapshot)
		if err != nil {
			return err
		}
		out[coord] = moduleResult{coord: coord, record: rec}
	}
	return nil
}

// absentFromVendor reports whether coord is a module a vendored analysis could
// not have measured, and the prose reason naming the absence.
//
// It answers only for the vendored surface. On the fetched surface vendor/ is
// not the source of anything, so its contents say nothing about coverage.
//
// The project's own main module is exempt: it is the working tree the analysis
// is rooted at, and no project vendors itself. So is the synthetic standard
// library, which the toolchain provides and `go mod vendor` never writes.
//
// A coordinate is resolved through the tree's replacement mapping first, and
// that step is not an optimisation. `go mod vendor` writes a replaced module's
// files under the ORIGINAL module path and names the replacement only on the
// modules.txt comment line, while the walk's build list keys on the REPLACEMENT
// coordinate — so the two names never meet, and a replacement coordinate looked
// up directly is absent from both Listed and Present no matter how completely
// the tree holds it. Without the mapping every replaced dependency is dropped
// from the analysis under a reason that positively asserts `go mod vendor`
// pruned it, which is a false statement about a module sitting in the tree.
//
// The two real absences are distinguished in the prose because they are
// different facts about the project. A module modules.txt lists but the tree has
// no files for is an incomplete vendor tree — a real inconsistency, the same one
// the vendor verifier reports. A module in the walk's build list that modules.txt
// does not mention at all was pruned by `go mod vendor` as contributing no
// imported package, which is a coverage gap of the analysis rather than a fault
// in the project.
func absentFromVendor(
	surface domain.AnalysisSurface,
	closure ports.VendoredClosure,
	coord, root coordinate.ModuleCoordinate,
) (string, bool) {
	if surface != domain.AnalysisSurfaceVendored || !closure.Vendored {
		return "", false
	}
	path := coord.Path()
	if path == domain.StdlibModulePath || path == root.Path() {
		return "", false
	}
	if original, replaced := closure.ReplacedBy[path]; replaced {
		path = original
	}
	if closure.Present[path] {
		return "", false
	}
	if _, listed := closure.Listed[path]; listed {
		return "vendor/modules.txt lists this module but the vendored tree holds no files for it, " +
			"so nothing of it was in the analysed build", true
	}
	return "the module is in the walk's build list but vendor/modules.txt does not list it, " +
		"so `go mod vendor` pruned it and nothing of it was in the analysed build", true
}

// effectiveProjectDir settles which working tree, if any, this run analyses.
//
// A caller that supplied one (--gomod, --tool, --project, the local driver)
// always wins: it named the tree it means, and the walk's recollection of an
// older one must not override it. Otherwise — the `vuln-scan <walk-id>` spelling
// — the walk's own record of where it was taken from is consulted, so a walk of
// a project is scanned rooted at that project's build no matter which command
// asked. Without this, one walk answered two ways depending on how the operator
// spelled the command: the direct form re-derived every dependency in isolation,
// which leaves the standard library metadata-only and reports a self-inflicted
// version-not-in-project-build gap for any module whose isolated build re-selects
// a version the project never chose — while the project's build was in hand the
// whole time. It is also the slower of the two, by one govulncheck per module.
//
// Whether the tree is vendored decides which SOURCE the project-rooted scan
// reads, not whether it happens. --no-vendor and an unwired closure reader both
// leave the run on the fetched surface, which the scanner selects for itself and
// every record then names; neither is a reason to abandon the project's build as
// the frame.
//
// The recorded directory is provenance, never an oracle. A checkout that has
// moved or been deleted cannot be analysed, so the run degrades to scanning each
// module in isolation and says so against the directory itself — a moved
// checkout must not make a stored walk unscannable, and must not be silently
// replaced by some other tree either.
func (uc *ScanWalkUseCase) effectiveProjectDir(params ScanWalkParams, walk walkdomain.WalkRecord) string {
	dir, adopted, err := projectDirForRun(params.ProjectDir, walk)
	switch {
	case err != nil:
		uc.logger.Warn("vuln-scan: the directory this walk was taken from is no longer readable, so this run cannot be rooted at the project's build; scanning each module in isolation instead, which leaves the standard library and any module the isolated build re-resolves unanalysed",
			"walk_id", params.WalkID, "project_dir", walk.ProjectDir, "error", err)
	case adopted:
		uc.logger.Info("vuln-scan: rooting this run at the project the walk was taken from",
			"walk_id", params.WalkID, "project_dir", dir)
	}
	return dir
}

// projectDirForRun resolves which working tree a run of this walk is about,
// without narrating it. It is the shared half of effectiveProjectDir, split out
// because the reuse decision asks the same question and must get the same
// answer: a stored run may only be served for the directory a fresh scan of the
// same walk would have analysed, and that is decided here rather than twice.
//
// adopted reports that the answer came from the walk's own record rather than
// from the caller. err reports a recorded directory that is no longer readable —
// there is then no tree to analyse and no tree to compare against, which is a
// degradation both callers already handle and neither may convert into a
// verdict.
func projectDirForRun(requested string, walk walkdomain.WalkRecord) (dir string, adopted bool, err error) {
	if requested != "" {
		return requested, false, nil
	}
	if walk.ProjectDir == "" {
		// A walk of a published coordinate, or one taken before walks recorded
		// their root. Neither has a project tree to reach; nothing to say.
		return "", false, nil
	}
	if _, serr := os.Stat(walk.ProjectDir); serr != nil {
		return "", false, fmt.Errorf("reading the project directory %q this walk was taken from: %w", walk.ProjectDir, serr)
	}
	return walk.ProjectDir, true, nil
}

// resolveVendoredClosure asks the project's working tree whether it is vendored
// and, if so, which modules its tree holds.
//
// A read failure is not fatal and is not silent: the scan continues on the
// fetched surface, which is a real analysis, and the record every module
// carries says "fetched" — so the run never claims to have measured the
// vendored bytes on the strength of a read that did not happen.
func (uc *ScanWalkUseCase) resolveVendoredClosure(ctx context.Context, params ScanWalkParams) ports.VendoredClosure {
	if uc.vendoredClosure == nil || params.ProjectDir == "" {
		return ports.VendoredClosure{}
	}
	if params.NoVendor {
		uc.logger.Info("vuln-scan: --no-vendor set, analysing the fetched artefacts even if the project is vendored",
			"project_dir", params.ProjectDir)
		return ports.VendoredClosure{}
	}
	closure, err := uc.vendoredClosure.VendoredClosure(ctx, filepath.Join(params.ProjectDir, "go.mod"))
	if err != nil {
		uc.logger.Warn("vuln-scan: could not read the project's vendored closure, analysing the fetched artefacts instead",
			"project_dir", params.ProjectDir, "error", err)
		return ports.VendoredClosure{}
	}
	if closure.Vendored {
		uc.logger.Info("vuln-scan: project is vendored, analysing the source it compiles",
			"project_dir", params.ProjectDir, "modules_listed", len(closure.Listed), "modules_present", len(closure.Present))
	}
	return closure
}

// persistProjectRecord builds, hashes and persists one live project-rooted
// vulnerability record. Record identity (Ecosystem, timestamps, pipeline) is
// stamped here exactly as the module scanner stamps an isolated record, so the
// downstream tally, run persistence and queries treat both paths uniformly.
//
// A record that could not be sealed or written is returned with an error, the
// same rule the isolated module scanner and persistSealed apply. This site used
// to log the failure and hand the in-memory record back: the caller then wrote
// it into the results map, the tally counted it towards analysed and clean, and
// the summary described as measured a module whose verdict was never stored.
func (uc *ScanWalkUseCase) persistProjectRecord(
	ctx context.Context,
	root coordinate.ModuleCoordinate,
	coord coordinate.ModuleCoordinate,
	findings []domain.VulnerabilityFinding,
	status domain.VulnerabilityStatus,
	unscanReason domain.UnscanReason,
	unscannableReason, errorDetail string,
	surface domain.AnalysisSurface,
	params ScanWalkParams,
	snapshot *domain.DatabaseSnapshot,
) (domain.VulnerabilityRecord, error) {
	if surface == "" {
		// Every record names a surface. A path that reached here without one
		// resolved from fetched artefacts — that is the only other regime — so it
		// is stated rather than left blank, which a reader would have to read as
		// a record predating the field.
		surface = domain.AnalysisSurfaceFetched
	}
	// No ArtefactIdentity. A project-rooted verdict is derived from one
	// govulncheck run over the TARGET's build, not from this dependency's own
	// bytes: the stage never opened the dependency's artefact, so it cannot name
	// which measurement of it produced this row. Stamping the coordinate's latest
	// fetch identity here would be exactly the link-by-convention this field
	// exists to replace — a claim about bytes nothing in this path read.
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
		// The frame this record was produced in, naming the target it was rooted
		// at. Every record on this path comes from one analysis rooted at that
		// target, reaching each dependency through the target's import graph at the
		// versions the build selects — so it answers "is this advisory reachable in
		// what THIS target ships", which neither an isolated scan of the same
		// coordinate nor an analysis rooted at a different target can.
		//
		// The root is part of the frame rather than a note beside it. All three
		// collided on (coordinate, pipeline, snapshot) before, and whichever ran
		// last silently answered for every question; naming the root is what keeps
		// one consumer's reachability finding from being displaced by another's.
		Rooting: domain.TargetRootedAt(root),
		// Which copy of the source this verdict was reached from. A project's
		// vendored tree and the artefacts kanonarion fetched can differ, so a
		// verdict that did not name its surface could not be checked against the
		// build it claims to describe.
		AnalysisSurface: surface,
	}
	domain.SortFindings(rec.Findings)
	// govulncheck produced these reachability answers and knows nothing of the
	// walk; the frame it was rooted at is stamped on each of them here, so a
	// finding carries its own derivation wherever it is copied to.
	domain.StampReachabilityRooting(&rec)
	sealed, herr := domain.VulnerabilityRecordHasher{}.SetContentHash(rec)
	if herr != nil {
		// An unsealed record is one the store refuses, so there is nothing to
		// persist: raise the failure rather than following it with a write that
		// cannot succeed.
		return rec, fmt.Errorf("hashing target-rooted vulnerability record for %s: %w", coord, herr)
	}
	rec = sealed
	if perr := uc.vulnStore.PutVulnerabilityRecord(ctx, rec); perr != nil {
		return rec, fmt.Errorf("persisting target-rooted vulnerability record for %s: %w", coord, perr)
	}
	return rec, nil
}
