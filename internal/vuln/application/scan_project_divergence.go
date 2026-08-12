package application

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// divergenceMaxNamed is how many module disagreements a reason line names before
// it starts counting instead. A build list can move by hundreds of modules at
// once (a `go get -u`), and a reason repeated on every record in the walk would
// bury the statement it exists to make.
const divergenceMaxNamed = 3

// projectBuildDivergence reports the modules whose version the project directory
// no longer agrees with the walk on, as "path walked -> required".
//
// It is the agreement test the project-rooted path owes before it attributes a
// govulncheck analysis to a walk's coordinates. The analysis reads the directory
// AS IT IS NOW; the record is filed against the versions the walk pinned. Those
// are the same build only while the tree still requires what the walk resolved,
// and nothing established that. When they differ, an analysis that reports
// nothing about a module reports nothing about the version in the record, and
// storing that silence as "not reachable" is a false negative on the question
// this tool exists to answer.
//
// WHAT MATCHES MEANS, and why it is the manifest rather than a re-resolution.
// The comparison is over the modules BOTH the walk and the manifest name, at the
// version each states — walkdomain.RequireDisagreement, the same comparator the
// read path's default frame choice uses. A module the manifest requires and the
// walk does not carry is not a disagreement (that is a narrower walk of the same
// tree, not a moved one), and a module the walk carries that the manifest does
// not require is not compared. In a pruned module (go >= 1.17) the second class
// is exactly the modules contributing no imported package: measured on this
// repository, 20 of 20 modules whose code the build imports are named by a
// require line, against 213 build-list modules that are not. No analysis of the
// tree reaches the code of an uncompared module, so its version cannot change a
// reachability answer either way.
//
// The alternative — re-resolving the directory through the go command, as the
// walk engine does — compares the same modules and adds a second of wall time
// plus two subprocesses to a command that today runs none, and fails outright on
// a vendored project, whose build list the toolchain will not compute from
// vendor/. This costs one file read.
//
// A directory that cannot be compared at all — no go.mod, an unparseable one, or
// one that requires no module the walk resolved — returns no divergence and says
// why. That is the same degradation the missing-directory case takes: the run
// proceeds and states what it could not check, rather than converting an
// unreadable file into a verdict about the build.
func (uc *ScanWalkUseCase) projectBuildDivergence(walk walkdomain.WalkRecord, projectDir string) []string {
	if projectDir == "" || !walk.Target.IsLocal() {
		return nil
	}
	gomodPath := filepath.Join(projectDir, "go.mod")
	data, err := os.ReadFile(filepath.Clean(gomodPath)) // #nosec G304 — the path is the project directory this run was pointed at
	if err != nil {
		uc.logger.Warn("vuln-scan: could not read the project's manifest, so this run could not check that the directory still builds the versions the walk pinned",
			"walk_id", walk.ID, "project_dir", projectDir, "error", err)
		return nil
	}
	f, err := modfile.Parse(gomodPath, data, nil)
	if err != nil {
		uc.logger.Warn("vuln-scan: could not parse the project's manifest, so this run could not check that the directory still builds the versions the walk pinned",
			"walk_id", walk.ID, "project_dir", projectDir, "error", err)
		return nil
	}
	required := make(map[string]string, len(f.Require))
	for _, r := range f.Require {
		if r == nil {
			continue
		}
		required[r.Mod.Path] = r.Mod.Version
	}
	disagreements, err := walkdomain.RequireDisagreement(required, walk)
	if err != nil {
		uc.logger.Warn("vuln-scan: the project's manifest could not be compared against the walk, so this run could not check that the directory still builds the versions the walk pinned",
			"walk_id", walk.ID, "project_dir", projectDir, "error", err)
		return nil
	}
	if len(disagreements) == 0 {
		uc.logger.Info("vuln-scan: the project directory still requires the module versions this walk resolved",
			"walk_id", walk.ID, "project_dir", projectDir, "compared", len(required))
		return nil
	}
	return disagreements
}

// divergenceStatement is the sentence every record of a diverged run carries: it
// names both version sets on the modules that moved, and says what the run
// therefore did not establish.
//
// Both versions are in each entry ("path walked -> required"), because naming
// only the one the walk pinned would leave a reader unable to tell an upgrade
// from a downgrade, and naming only the current one would lose the version the
// record is filed against.
func divergenceStatement(projectDir string, disagreements []string) string {
	named := disagreements
	tail := ""
	if len(named) > divergenceMaxNamed {
		tail = fmt.Sprintf(", and %d more", len(named)-divergenceMaxNamed)
		named = named[:divergenceMaxNamed]
	}
	return fmt.Sprintf(
		"the project directory %s no longer requires the module versions this walk resolved (%s%s), "+
			"so an analysis of that directory would be evidence about a different build; "+
			"advisories were matched by coordinate against the versions the walk pinned and reachability was not established",
		projectDir, strings.Join(named, ", "), tail)
}

// scanProjectDiverged records a coordinate-only verdict for every module in a
// walk whose project directory has moved on from it.
//
// It is a degradation, not a refusal. The operator asked whether this walk's
// build carries a known vulnerability, and half of that answer is still
// available and still true: the advisory match is against the versions the WALK
// pinned, which is what the record is keyed on, and losing it would take away
// the "you are pinned to a vulnerable version" signal because a directory
// elsewhere on the host had changed. The half that is not available is
// reachability, and that half is recorded as absent rather than fabricated —
// every finding carries a nil Reachable, and the coverage axis says Unscannable
// with the divergence as its reason, so no reader can mistake the run for an
// analysed one that came back clean.
//
// It is the same shape as the directory that no longer EXISTS, which warns and
// reports a coverage gap rather than failing the run, and the opposite of a
// re-scan's frame refusal: a scan is asked "scan this walk", and answering with
// what can still be measured is a narrower answer to the question asked.
func (uc *ScanWalkUseCase) scanProjectDiverged(
	ctx context.Context,
	walk walkdomain.WalkRecord,
	allCoords []coordinate.ModuleCoordinate,
	params ScanWalkParams,
	snapshot *domain.DatabaseSnapshot,
	closure ports.VendoredClosure,
	disagreements []string,
	out map[coordinate.ModuleCoordinate]moduleResult,
) error {
	root := walk.Target
	surface := domain.AnalysisSurfaceFetched
	if closure.Vendored {
		surface = domain.AnalysisSurfaceVendored
	}
	reason := divergenceStatement(params.ProjectDir, disagreements)

	for _, coord := range allCoords {
		// reachabilityAnswerable is false: no analysis of this walk's build ran,
		// so every matched advisory is added with a nil Reachable. That parameter
		// already exists for the one other case where the analysis could not have
		// reported an advisory at all, and it means the same thing here.
		findings, err := uc.mergeCoordinateFindings(ctx, coord, nil, false)
		if err != nil {
			uc.logger.Error("diverged project scan: advisory match by coordinate failed", "coordinate", coord, "error", err)
			rec, perr := uc.persistProjectRecord(ctx, root, coord, nil, domain.StatusScanFailed, "", "", err.Error(), surface, params, snapshot)
			if perr != nil {
				return perr
			}
			out[coord] = moduleResult{coord: coord, record: rec}
			continue
		}
		rec, perr := uc.persistProjectRecord(ctx, root, coord, findings,
			domain.StatusUnscannable, domain.UnscanReasonProjectBuildDiverged, reason, "", surface, params, snapshot)
		if perr != nil {
			return perr
		}
		out[coord] = moduleResult{coord: coord, record: rec}
	}
	return nil
}
