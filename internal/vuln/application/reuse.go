package application

import (
	"context"
	"fmt"
	"strings"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// ReusableRun returns a stored scan run that already answers the question a new
// Scan of walkID would ask, if one exists.
//
// The question a scan answers is fixed by three things: WHICH dependency set was
// analysed (the walk), WHICH advisories it was judged against (the snapshot),
// and WHICH pipeline derived the verdicts. When all three match a completed
// stored run, re-running govulncheck can only reproduce that run's own findings
// at the cost of the whole analysis — on a large project the dominant cost of
// the command.
//
// It deliberately does NOT live inside Scan. Scan measures; that is its whole
// contract, and RescanWalkUseCase depends on it. Whether a measurement is wanted
// at all is the caller's decision, which is where --force already is.
//
// Three conditions, each of which refuses rather than approximates:
//
//   - The run's coverage must be complete. A partial or failed run left part of
//     the build list unanalysed; serving it would freeze a gap the operator is
//     entitled to have another attempt at, and would report coverage this
//     invocation never established.
//   - The pipeline version must match. A corrected scanner takes effect on its
//     own, exactly as the walk cache's pipeline check makes a corrected resolver
//     take effect, rather than every caller having to know to pass a flag.
//   - The snapshot must name the same advisory database: same source, same
//     generation, same seal. A new advisory generation is a new question, and the
//     run that predates it did not answer it.
//
// The advisory database is the whole of what --fresh refreshes, and it is the
// third condition here. A caller that has just refreshed asks this question
// afterwards: a refresh that brought in a new generation fails the snapshot
// check and the walk is re-scanned, and a refresh that found the stored database
// still current passes it and the stored run answers — which is the same run
// that answered before, against the same database, and it is still the answer.
// A fourth condition guards the subject rather than the question: the walk must
// still be in the store. Reuse serves a stored run as named evidence — the
// derivation output names the run and the walk it analysed — and a run whose
// walk has been purged cannot support that claim: the findings survive, the
// statement of what was scanned does not. Every caller reaches this having just
// resolved the walk, so in practice the check never fires; it is here so the
// guarantee belongs to this method rather than to the habits of its callers.
//
// A fifth guards the frame: the project directory the run would be about must
// still require the module versions the walk resolved. A stored run of a project
// walk is an analysis of that directory, and the answer to "does this build
// carry a known vulnerability" must not depend on whether a stored run happens
// to be servable. So the agreement test lives HERE, in the decision that owns
// whether a stored run may be served, and not beside the caller's short-circuit:
// a copy at the call site is how the guard came to cover the measuring path and
// not the serving one. Refusing hands the walk to Scan, whose diverged branch
// matches advisories by coordinate and records no reachability without running
// an analysis — the same answer, reached the same way, at no extra cost.
func (uc *ScanWalkUseCase) ReusableRun(ctx context.Context, walkID, projectDir string) (domain.WalkScanRun, bool, error) {
	walk, err := uc.walkStore.GetWalk(ctx, walkID)
	if err != nil {
		// A walk that cannot be loaded is not a walk this run can name as the
		// subject of the evidence it serves, whether it is absent or unreadable.
		// Refusing costs a re-scan; serving would present findings whose inputs
		// this store can no longer state.
		uc.logger.Debug("scan reuse: walk unresolvable, will scan", "walk_id", walkID, "error", err)
		return domain.WalkScanRun{}, false, nil
	}

	// The project directory the run is about, resolved exactly as a scan of this
	// walk would resolve it, and then compared against the walk. A stored run of
	// a project walk is a statement about the directory AS IT WAS; serving it
	// after the directory has moved presents an analysis of a build that no
	// longer exists as the current answer, and in the direction where the tree
	// has moved ONTO a vulnerable version it presents it as a clean one. The
	// comparison is the same one the scan itself makes — projectBuildDivergence,
	// over walkdomain.RequireDisagreement — so a diverged directory reaches the
	// same metadata-only degradation whether or not a stored run happens to be
	// servable.
	dir, _, derr := projectDirForRun(projectDir, walk)
	if derr != nil {
		// The recorded directory is gone. There is nothing to compare and nothing
		// to analyse, which is the degradation the scan already takes; it is not a
		// reason to refuse the stored run.
		uc.logger.Debug("scan reuse: the directory this walk was taken from is no longer readable, so this run could not check that it still builds the versions the walk pinned",
			"walk_id", walkID, "project_dir", walk.ProjectDir, "error", derr)
	} else if disagreements := uc.projectBuildDivergence(walk, dir); len(disagreements) > 0 {
		// Info, not Warn: the fault itself is stated by the run this refusal hands
		// the walk to, on stderr and in the result, and saying it twice at
		// warning level would read as two faults.
		uc.logger.Info("vuln-scan: the project directory no longer requires the module versions this walk resolved, so the stored run for it is not served; re-deriving, which will match advisories by coordinate and record no reachability",
			"walk_id", walkID, "project_dir", dir, "disagreements", strings.Join(disagreements, ", "))
		return domain.WalkScanRun{}, false, nil
	}

	// The snapshot a scan started now would use: the pinned-or-stored snapshot,
	// at the cost of a store read and never a fetch.
	snapshot, err := uc.resolveSnapshot(ctx, nil, false, walkID)
	if err != nil {
		// A snapshot that cannot be resolved is not evidence that no reusable run
		// exists. Report no reuse and let Scan surface the same failure with its
		// own diagnostics rather than failing the command from the cache path.
		uc.logger.Debug("scan reuse: snapshot unresolved, will scan", "walk_id", walkID, "error", err)
		return domain.WalkScanRun{}, false, nil
	}

	runs, err := uc.vulnStore.ListWalkScanRuns(ctx, walkID)
	if err != nil {
		return domain.WalkScanRun{}, false, fmt.Errorf("listing scan runs for walk %q: %w", walkID, err)
	}

	// Runs arrive most recent first; the first that qualifies is the answer.
	for _, run := range runs {
		if run.CoverageStatus != domain.CoverageComplete {
			continue
		}
		if run.PipelineVersion != uc.pipelineVersion {
			continue
		}
		if !sameAdvisoryDatabase(run.Snapshot, *snapshot) {
			continue
		}
		return run, true, nil
	}
	return domain.WalkScanRun{}, false, nil
}

// sameAdvisoryDatabase reports whether two snapshots name the same advisory
// database: the same source, the same generation of it, and the same bytes.
//
// It deliberately does not use DatabaseSnapshot.Equal, which also compares the
// retrieval time. Retrieval time is when THIS machine downloaded the database,
// not which database it is: a snapshot fetched by --fresh carries nanosecond
// precision in memory while the store round-trips it at second precision, so
// comparing it makes a run unequal to the very snapshot it was judged against
// and reuse never fires again after a fresh fetch. Two downloads of one
// generation with one seal are one advisory database.
//
// The seal is compared, both-empty included. A run whose snapshot was never
// sealed cannot be shown to have been judged against these bytes, so it is only
// reusable against another unsealed reading of the same generation.
func sameAdvisoryDatabase(a, b domain.DatabaseSnapshot) bool {
	return a.Source() == b.Source() &&
		a.Version() == b.Version() &&
		a.ContentHash() == b.ContentHash()
}
