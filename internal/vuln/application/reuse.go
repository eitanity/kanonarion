package application

import (
	"context"
	"fmt"

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
// at all is the caller's decision, which is where --fresh and --force already
// are.
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
// fresh short-circuits the whole lookup: --fresh is the operator asking for a
// live advisory snapshot, and serving a stored run against it would be the
// opposite of what was asked.
func (uc *ScanWalkUseCase) ReusableRun(ctx context.Context, walkID string, fresh bool) (domain.WalkScanRun, bool, error) {
	if fresh {
		return domain.WalkScanRun{}, false, nil
	}

	// The snapshot a scan started now would use. Passing fresh=false is not a
	// second guess at the flag: --fresh already returned above, so this is the
	// pinned-or-cached snapshot and the call costs a store read, never a fetch.
	snapshot, err := uc.resolveSnapshot(ctx, nil, false)
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
