package cli

import (
	"context"
	"fmt"
	"io"
	"os"
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

// ---- the build a stored walk was resolved in ----

// walkBuildJSON is the build a walk was resolved in, on the machine surface.
//
// The field names are the ones the walk record already publishes at
// .graph.build_env and the ones the SBOM generator already emits as CycloneDX
// properties, so one fact keeps one spelling across every surface. The object is
// deliberately not called "toolchain": that key is taken on the vulnerability
// record surface, where it names the toolchain that produced the RECORD, and one
// key must not carry two meanings.
//
// Every field is emitted, empty included. An empty value is the statement that
// the walk recorded no build environment, and it is a different statement from
// the key being absent, which would say this producer does not publish the fact
// at all.
type walkBuildJSON struct {
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	GoVersion string `json:"go_version"`
}

// walkBuildOf projects a walk's recorded build environment.
//
// It reads rec.Graph.BuildEnv and nothing else, for the reason
// toolchainVersionOf records: the synthetic stdlib node's version is the go.mod
// directive whenever --stdlib-from-gomod was passed, and a second reader taking
// the value from there would disagree with the judgment vuln-scan and audit
// already render.
func walkBuildOf(rec walkdomain.WalkRecord) walkBuildJSON {
	env := rec.Graph.BuildEnv
	return walkBuildJSON{GOOS: env.GOOS, GOARCH: env.GOARCH, GoVersion: env.GoVersion}
}

// walkBuildToolchainUnrecorded is what a walk that recorded no toolchain says.
// It never degrades to the reader's own: a walk rooted at a published
// coordinate resolves no toolchain and never will, and answering with this
// host's would attribute a standard library to a build that never named one.
const walkBuildToolchainUnrecorded = "a toolchain that is not recorded"

// readerWalkToolchain is the toolchain `go env GOVERSION` resolves to today in
// the directory the walk was taken from, or "" when there is nothing to ask.
//
// The comparison this feeds is walk-recorded against THAT PROJECT's toolchain
// now — never against the reader's working directory. GOTOOLCHAIN honours each
// project's own go.mod, so keying on the reader's directory would tell an
// operator standing in a different project that their walk had diverged when
// nothing about it had changed.
//
// A walk with no recorded toolchain is not probed at all: there is nothing to
// compare it with, and the probe is a subprocess.
func readerWalkToolchain(ctx context.Context, rec walkdomain.WalkRecord) string {
	if toolchainVersionOf(rec) == "" || rec.ProjectDir == "" {
		return ""
	}
	if _, err := os.Stat(rec.ProjectDir); err != nil {
		return ""
	}
	return currentWalkBuildEnv(ctx, "", rec.ProjectDir, nil).toolchain
}

// storedWalkFor loads the walk a report is about to describe, best-effort.
//
// Best-effort is the contract, not a shortcut. This is the build disclosure
// beside an answer the store has already produced, and a walk that has been
// deleted, or a reader assembled without a walk store, must not cost the report
// the answer it came for. The second return says whether there is a walk to
// describe at all, so a caller states "not recorded" rather than rendering the
// zero record as though it were a walk that recorded nothing.
func storedWalkFor(ctx context.Context, walks QueryWalksUseCase, walkID string, present bool) (walkdomain.WalkRecord, bool) {
	if walks == nil || walkID == "" || !present {
		return walkdomain.WalkRecord{}, false
	}
	rec, err := walks.GetWalk(ctx, walkID)
	if err != nil {
		return walkdomain.WalkRecord{}, false
	}
	return rec, true
}

// walkBuildLines states the build a walk was resolved in, and — where the
// project it was resolved in no longer resolves that toolchain — says so.
//
// The platform half comes from the walk's own frame, so this line cannot
// disagree with the frame every other surface renders: a module-rooted walk
// reads "not-platform-scoped" rather than being reported as a project walk that
// lost its platform.
func walkBuildLines(rec walkdomain.WalkRecord, readerToolchain string) []string {
	frame := rec.Graph.Frame().String()
	version := toolchainVersionOf(rec)
	if version == "" {
		return []string{frame + " under " + walkBuildToolchainUnrecorded}
	}
	lines := []string{frame + " under " + version}
	switch {
	case readerToolchain == "":
		lines = append(lines, "the project it was resolved in is not present here, so "+version+
			" could not be compared with what that project resolves today")
	case readerToolchain != version:
		lines = append(lines, "that project resolves "+readerToolchain+" today: this answer describes "+version+
			"'s standard library, not the one a build taken there now would use")
	}
	return lines
}

// writeWalkBuild states the build block for a walk a command was asked for by
// name, plus any notes the caller owes beside it.
//
// It is one block on one channel for the same reason writeToolchainJudgment is:
// a fact rendered twice is a fact two surfaces come to disagree about, and a
// reader who learns the wording from one command has to recognise it from the
// next.
func writeWalkBuild(w io.Writer, rec walkdomain.WalkRecord, readerToolchain string, notes ...string) error {
	lines := append(walkBuildLines(rec, readerToolchain), notes...)
	if _, err := fmt.Fprintf(w, "build:\n  %s\n", strings.Join(lines, "\n  ")); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

// rescanRecordedBuildNote is the statement a re-scan owes ahead of the run.
//
// Re-evaluating a recorded build against fresh advisories is exactly what a
// re-scan is for, and re-resolving the toolchain would change the subject rather
// than refresh the answer. The trap is that a re-scan is what an operator
// reaches for when they want a DATED statement, and nothing in the output said
// which standard library the dated statement was about.
const rescanRecordedBuildNote = "a re-scan re-evaluates that recorded build against fresh advisories; " +
	"it does not re-resolve the toolchain, so this run answers for the build above and not for the one a walk taken now would record"

// writeRescanBuildPreflight states the build a re-scan is about to re-evaluate,
// before the most expensive run the CLI offers starts.
//
// A walk the store cannot produce writes nothing: the re-scan is about to fail
// on the same id and say so in its own words, and a second complaint ahead of it
// buys the reader nothing.
func writeRescanBuildPreflight(ctx context.Context, w io.Writer, walks QueryWalksUseCase, walkID string) error {
	rec, ok := storedWalkFor(ctx, walks, walkID, true)
	if !ok {
		return nil
	}
	return writeWalkBuild(w, rec, readerWalkToolchain(ctx, rec), rescanRecordedBuildNote)
}
