package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// toolchainVersionOf returns the toolchain version a walk record states it was
// built under.
//
// The walk holds two toolchain versions and they are not interchangeable. The
// build environment's GoVersion is `go env GOVERSION` — the toolchain that
// actually compiled the project — while the synthetic stdlib node's version is
// pinned to the go.mod directive whenever --stdlib-from-gomod was passed, which
// is a declared minimum and not what ran. The judgment is about the toolchain
// that built the walk, so it reads the build environment and never the node.
func toolchainVersionOf(rec walkdomain.WalkRecord) string { return rec.Graph.BuildEnv.GoVersion }

// judgeWalkToolchain derives the toolchain judgment for a walk against the
// snapshot the run was judged on. A failure to read the snapshot is reported as
// an unjudged judgment rather than failing the command: the toolchain axis is
// evidence beside the module evidence, and losing it must not cost the report.
func judgeWalkToolchain(ctx context.Context, ctr *Container, rec walkdomain.WalkRecord, snapshot vulndomain.DatabaseSnapshot) vulndomain.ToolchainJudgment {
	version := toolchainVersionOf(rec)
	if ctr.ScanWalk == nil {
		return vulndomain.ToolchainJudgment{
			Version:  version,
			Snapshot: snapshot,
			Status:   vulndomain.ToolchainUnjudged,
			Reason:   "this run has no advisory database to judge the toolchain against",
		}
	}
	judgment, err := ctr.ScanWalk.JudgeToolchain(ctx, snapshot, version)
	if err != nil {
		return vulndomain.ToolchainJudgment{
			Version:  version,
			Snapshot: snapshot,
			Status:   vulndomain.ToolchainUnjudged,
			Reason:   err.Error(),
		}
	}
	return judgment
}

// reportToolchainAxis derives the toolchain judgment for a scan run and writes
// it. It is the vuln-scan entry point, where the walk record is not already in
// hand: the run names the walk it judged and the snapshot it judged against, and
// both are read locally.
//
// A walk that cannot be loaded is reported as an unjudged toolchain, naming that
// as the reason. The scan's own result is unaffected either way — this axis is
// beside it, not part of it.
func reportToolchainAxis(ctx context.Context, ctr *Container, run vulndomain.WalkScanRun, w io.Writer) error {
	rec, err := ctr.QueryWalks.GetWalk(ctx, run.WalkID)
	if err != nil {
		return writeToolchainJudgment(w, vulndomain.ToolchainJudgment{
			Snapshot: run.Snapshot,
			Status:   vulndomain.ToolchainUnjudged,
			Reason:   fmt.Sprintf("the walk it was built by could not be loaded (%v)", err),
		})
	}
	return writeToolchainJudgment(w, judgeWalkToolchain(ctx, ctr, rec, storedSnapshotFor(ctx, ctr, run)))
}

// storedSnapshotFor returns the advisory snapshot a report should judge the
// toolchain against: the one the scan run named when there is a run, and
// otherwise the latest snapshot the store holds. Both are store reads.
//
// The zero snapshot is a valid answer — a store that holds no advisory database
// cannot judge a toolchain — and the judgment says so in those words.
func storedSnapshotFor(ctx context.Context, ctr *Container, run vulndomain.WalkScanRun) vulndomain.DatabaseSnapshot {
	if !run.Snapshot.IsZero() {
		return run.Snapshot
	}
	if ctr.VulnStore == nil {
		// A container assembled without an advisory store holds no snapshot to
		// judge against, which the zero value already states in those words.
		return vulndomain.DatabaseSnapshot{}
	}
	snapshot, ok, err := ctr.VulnStore.GetLatestDatabaseSnapshot(ctx)
	if err != nil || !ok {
		return vulndomain.DatabaseSnapshot{}
	}
	return snapshot
}

// writeToolchainJudgment states the toolchain axis in one block.
//
// It is written on the same channel as the run's other whole-run statements and
// never onto the data channel, for the reason the judgment exists at all: the
// toolchain is not a dependency of the artefact. It is not a row, it is not
// counted in the affected/clean roll-ups, and a reader tallying module findings
// must get the same numbers whether or not this judgment was made.
//
// Every outcome names its basis — the version judged and the snapshot it was
// judged against — because a bare "clear" is a claim with nothing behind it, and
// the unjudged case is printed rather than omitted for the same reason: a
// silently missing line reads as a clear.
func writeToolchainJudgment(w io.Writer, j vulndomain.ToolchainJudgment) error {
	if _, err := fmt.Fprintf(w, "toolchain:\n  %s\n", strings.Join(toolchainLines(j), "\n  ")); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

// toolchainLines renders the judgment's body, one statement per line.
func toolchainLines(j vulndomain.ToolchainJudgment) []string {
	snapshot := fmt.Sprintf("%s@%s", j.Snapshot.Source(), j.Snapshot.Version())
	version := j.Version
	if version == "" {
		version = "(unrecorded)"
	}

	switch j.Status {
	case vulndomain.ToolchainUnjudged:
		return []string{fmt.Sprintf("%s was not judged against the advisory database's toolchain key: %s", version, j.Reason)}

	case vulndomain.ToolchainAffected:
		lines := []string{fmt.Sprintf("%s is covered by %s in %s: %s",
			version, pluralAdvisories(len(j.Covering)), snapshot, toolchainAdvisoryList(j.Covering, j.Version))}
		if len(j.WithdrawnCovering) > 0 {
			lines = append(lines, fmt.Sprintf("also covered by %s since withdrawn: %s",
				pluralAdvisories(len(j.WithdrawnCovering)), toolchainAdvisoryList(j.WithdrawnCovering, j.Version)))
		}
		return append(lines, toolchainAxisNote)

	case vulndomain.ToolchainWithdrawn:
		return []string{
			fmt.Sprintf("%s is covered only by %s in %s that %s since been withdrawn: %s",
				version, pluralAdvisories(len(j.WithdrawnCovering)), snapshot,
				pluralHas(len(j.WithdrawnCovering)), toolchainAdvisoryList(j.WithdrawnCovering, j.Version)),
			toolchainAxisNote,
		}

	default:
		return []string{fmt.Sprintf("%s: none of the %d toolchain advisories in %s covers it",
			version, j.Judged, snapshot)}
	}
}

// toolchainAxisNote is printed whenever an advisory matched, because that is
// when a reader is most likely to go looking for it in the counts below and
// conclude the counts are wrong.
const toolchainAxisNote = "this is the build toolchain, not a dependency of the artefact: it is reported as its own axis and is counted in no module roll-up"

// toolchainAdvisoryList renders matched advisories as "id (fixed in x)" pairs.
// The fix named is the one for the branch this toolchain is on, not the
// advisory's lowest: an advisory backported to two release lines has two fixes,
// and only one of them is a move forward.
func toolchainAdvisoryList(advs []vulndomain.ToolchainAdvisory, version string) string {
	parts := make([]string, 0, len(advs))
	for _, a := range advs {
		if fixed := a.FixedFor(version); fixed != "" {
			parts = append(parts, fmt.Sprintf("%s (fixed in %s)", a.ID, fixed))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s (no fixed version)", a.ID))
	}
	return strings.Join(parts, ", ")
}

func pluralAdvisories(n int) string {
	if n == 1 {
		return "1 advisory"
	}
	return fmt.Sprintf("%d advisories", n)
}

func pluralHas(n int) string {
	if n == 1 {
		return "has"
	}
	return "have"
}
