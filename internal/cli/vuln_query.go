package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"

	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/spf13/cobra"
)

// vulnPipelineVersion is the vuln scan pipeline version the read-side query
// commands pin to. It mirrors the version the container scans under so a query
// resolves the records the scanner wrote — keeping reader and writer on a
// single source of truth instead of duplicating the literal at each call site.
const vulnPipelineVersion = vulnapp.PipelineVersion

func newVulnShowCmd(stdout, stderr io.Writer) *cobra.Command {
	var walkID string
	var gomod string
	var history bool

	cmd := &cobra.Command{
		Use:   "vuln-show <module>@<version>",
		Short: "Show the vulnerability record for a module",
		Long: `Show the vulnerability record for a module.

A stored record answers "what did this advisory do in THIS build", so the
answer depends on which build you mean. Name it with --walk-id, or with
--gomod to use the newest project walk for that go.mod (defaults to
./go.mod). The answer is then drawn from records measured in that build's
frame only, and a notice states which build it was restricted to.

With neither flag, vuln-show composes across the whole store. On a store
holding scans of a single project that is the same answer; on a store
holding two, vuln-show refuses and names the frames it found, because the
newest scan of a shared dependency belongs to whichever project was scanned
last.

Use --history to list every stored scan record for the module across all
walks, snapshots and pipeline generations, newest first — including the
frame each was measured in. This shows when a finding first appeared or was
absent because the vulnerability database snapshot predated it.

--history is the one read that spans pipeline generations. The others serve
only records this build's scan logic would still produce, and refuse when
the store holds a coordinate at superseded generations alone; a history is
what was recorded rather than what holds now, so it lists those records and
marks them superseded.`,
		Example: `  kanonarion vuln-show github.com/gin-gonic/gin@v1.6.2
  kanonarion vuln-show github.com/gin-gonic/gin@v1.6.2 --json
  kanonarion vuln-show github.com/gin-gonic/gin@v1.6.2 --history
  kanonarion vuln-show github.com/gin-gonic/gin@v1.6.2 --history --json
  kanonarion vuln-show github.com/gin-gonic/gin@v1.6.2 --gomod ./go.mod
  kanonarion vuln-show github.com/gin-gonic/gin@v1.6.2 --walk-id 01KQDBVW092ER1HNXZ60X27CMD
  kanonarion vuln-show github.com/gin-gonic/gin@v1.6.2 --walk-id 01KQDBVW092ER1HNXZ60X27CMD --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runVulnShow(cmd.Context(), args[0], walkID, gomod, cmd.Flags().Changed("gomod"), jsonOut, history,
				ctr.QueryVuln, ctr.QueryScanRuns, ctr.QueryWalks, ctr.QueryCallGraph, stdout)
		},
	}

	cmd.Flags().BoolVar(&history, "history", false, "list all scan records across walks and snapshots")
	cmd.Flags().StringVar(&walkID, "walk-id", "", "answer in the frame of this walk's scans")
	cmd.Flags().StringVar(&gomod, "gomod", "",
		"answer in the frame of the latest project walk for this go.mod; takes a path, e.g. --gomod "+defaultGoModPath)

	return cmd
}

func runVulnShow(
	ctx context.Context,
	arg, walkID, gomod string,
	gomodSet, jsonOut, history bool,
	uc QueryVulnUseCase,
	runs QueryScanRunsUseCase,
	walks QueryWalksUseCase,
	graphs QueryCallGraphUseCase,
	stdout io.Writer,
) error {
	coord, err := parseCoordinate(arg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", arg, err)
	}

	if history {
		return runVulnShowHistory(ctx, coord, jsonOut, uc, graphs, stdout)
	}

	anchor, anchored, err := resolveVulnFrameAnchor(ctx, walks, walkID, gomod, gomodSet)
	if err != nil {
		return err
	}

	var rec vuldomain.VulnerabilityRecord
	var isolated vuldomain.VulnerabilityRecord
	var hasIsolated bool
	if !anchored {
		// Every generation is read rather than the store's composed "latest",
		// because "show me this module's record" is a question a consumer asks
		// about a module they depend on, and the frame-blind ladder answers it in
		// whichever frame happens to rank first. The rung that decides is
		// call-graph completeness, and an isolated scan wins it by construction:
		// it built the module alone, so it records BUILT_WITH_BODIES, while a
		// consumer-rooted govulncheck analysis records no completeness at all.
		// vuln-show therefore headlined an isolated "not reachable" while
		// reachability, over the same store, served the consumer's route to the
		// vulnerable symbol. Same read as reachability uses, so the two agree.
		recs, err := uc.ListRecordsForModule(ctx, coord, vulnPipelineVersion)
		if err != nil {
			return fmt.Errorf("getting vulnerability record: %w", err)
		}
		// More than one consumer frame and no flag naming one: the question has
		// several true answers and no way to tell which was asked.
		if frames := consumerFrames(recs, coord); len(frames) > 1 {
			return ambiguousFrameRefusal("kanonarion vuln-show "+coord.String(), coord, frames)
		}
		r, aside, has, ok := selectConsumerRecord(recs, coord)
		if !ok {
			// The read above keys on the pipeline version, so an empty result may
			// be a coordinate this build has superseded rather than one nobody has
			// scanned. Asked before the miss is reported, because the two absences
			// carry opposite instructions.
			if err := supersededVulnRefusal(ctx, uc, coord); err != nil {
				return err
			}
			// No walk was named, so there is no "newer than what you passed" to
			// compute — but a succeeded walk of this module may already exist,
			// and naming it turns the placeholder <walk-id> into a command the
			// operator can run. The primary line keeps its placeholder shape.
			msg := fmt.Sprintf("no vulnerability record for %s — run: kanonarion vuln-scan <walk-id>", coord)
			if note := latestSucceededWalkNote(ctx, walks, coord, time.Time{}); note != "" {
				msg += "\n" + note
			}
			return &exitError{code: ExitNotFound, msg: msg}
		}
		rec, isolated, hasIsolated = r, aside, has
	} else {
		// The candidates leave the store unranked and the frame decides here. The
		// walk's membership index keys on (coordinate, pipeline, snapshot) and
		// carries no frame, so the candidate set for a project walk also contains
		// the isolated scans and every other project's target-rooted records of
		// the same generation — which is how a walk-pinned read used to answer
		// from a different walk without saying so.
		candidates, err := uc.ListRecordsForModuleInWalk(ctx, coord, vulnPipelineVersion, anchor.walkID)
		if err != nil {
			return fmt.Errorf("getting vulnerability record: %w", err)
		}
		if len(candidates) == 0 {
			return explainWalkRecordAbsence(ctx, runs, walks, coord, anchor.walkID)
		}
		r, aside, has, ok, serr := selectAnchoredRecord(candidates, coord, anchor, "kanonarion vuln-show "+coord.String())
		if serr != nil {
			return serr
		}
		if !ok {
			return frameRecordAbsence(coord, anchor, candidates)
		}
		rec, isolated, hasIsolated = r, aside, has
	}

	if jsonOut {
		// The JSON body stays record-shaped: that shape is this command's published
		// contract, and wrapping it to carry the aside would break every consumer
		// parsing it. The served record is the consumer-frame one either way, so
		// --json agrees with reachability --json on the verdict; the declined
		// isolated answer is reported on the text surface and by
		// 'reachability --json', whose result type has a field for it.
		//
		// The findings are rendered through vulnRecordJSON so each carries the rung
		// behind its reachability answer. The text surface has printed that rung
		// beside every negative for some time; --json did not, which left the one
		// consumer that cannot read it out of prose — a machine — with the negative
		// and no statement of what was searched to reach it.
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(toVulnRecordJSON(rec, newRecordRootFunc(ctx, graphs))); err != nil {
			return fmt.Errorf("encoding vulnerability record: %w", err)
		}
		return nil
	}

	writeFrameAnchorNotice(stdout, anchor, anchored)
	if anchored {
		// The record's own Walk line is provenance for the scan that wrote it, and
		// one build's walks share their records, so it routinely names an earlier
		// walk in the same frame. Beside a pin that reads as a substitution — the
		// failure this path was rebuilt to stop — so the difference is stated
		// rather than left for the reader to infer.
		_, _ = fmt.Fprintln(stdout,
			"        the Walk line below names the scan that wrote the served record, which may be an earlier walk in the same frame")
	}
	printVulnRecord(stdout, rec, newRouteRootFunc(ctx, graphs, rec))
	printDeclinedIsolatedFrame(stdout, isolated, hasIsolated)
	return nil
}

// frameRecordAbsence refuses a pinned read the walk's own frame cannot answer,
// naming the frames its candidates were measured in instead.
//
// The alternative — serving whichever candidate ranks first — is the substitution
// this path exists to stop: the walk's membership brings in records measured in
// other frames, so "the pin found nothing" and "the pin found something else"
// are one step apart, and only one of them is an answer to the question asked.
func frameRecordAbsence(coord coordinate.ModuleCoordinate, anchor vulnFrameAnchor, candidates []vuldomain.VulnerabilityRecord) error {
	if len(candidates) == 0 {
		return &exitError{code: ExitNotFound, msg: fmt.Sprintf(
			"walk %s holds no vulnerability record for %s — the walk may not contain the module, or may not have been scanned; run: kanonarion vuln-scan %s",
			anchor.walkID, coord, anchor.walkID)}
	}
	frame := "that walk's own frame"
	if anchor.rooting.IsRecorded() {
		frame = fmt.Sprintf("that walk's own frame (%s)", anchor.rooting)
	}
	msg := fmt.Sprintf("walk %s scanned %s, but holds no record for it in %s",
		anchor.walkID, coord, frame)
	if frames := framesPresent(candidates); len(frames) > 0 {
		msg += "\nthe records it did cover were measured in:"
		for _, f := range frames {
			label := f.String()
			if !f.IsRecorded() {
				label = "(frame not recorded)"
			}
			msg += "\n  " + label
		}
	}
	msg += fmt.Sprintf("\nre-run: kanonarion vuln-scan %s", anchor.walkID)
	return &exitError{code: ExitNotFound, msg: msg}
}

// printDeclinedIsolatedFrame prints what the isolated-frame record says about
// each advisory it saw, under the served record and visibly subordinate to it.
//
// It is the record-shaped counterpart of printIsolatedAside, which reports the
// same thing for a single queried advisory. Both exist for the same reason: the
// two frames disagreeing is itself information, and a reader who has seen the
// isolated verdict on another surface is owed the reason it is not the headline.
func printDeclinedIsolatedFrame(stdout io.Writer, rec vuldomain.VulnerabilityRecord, has bool) {
	if !has {
		return
	}
	var lines []string
	for _, f := range rec.Findings {
		if aside := isolatedAsideFor(rec, true, f.ID); aside != nil {
			lines = append(lines, fmt.Sprintf("    %s: %s [confidence: %s, soundness: %s, by: %s]",
				f.ID, aside.Verdict, aside.Confidence, aside.Soundness, aside.Method))
		}
	}
	if len(lines) == 0 {
		// An isolated record exists but says nothing about reachability, so there
		// is no second answer to report. Announcing the frame alone would imply a
		// disagreement that was never measured.
		return
	}
	_, _ = fmt.Fprintf(stdout,
		"  Isolated frame (a different question — the module built alone, not the build that consumes it), scanned %s:\n",
		rec.ScannedAt.UTC().Format(time.RFC3339))
	for _, l := range lines {
		_, _ = fmt.Fprintln(stdout, l)
	}
}

// explainWalkRecordAbsence says why the named walk has no readable record for
// coord, using only what that walk's own scan runs recorded.
//
// The obvious shortcut — ask for the coordinate's latest record across all
// walks and report its status — answers with a fact about some other walk. When
// walk W never scanned the module and walk V's scan of it failed, that shortcut
// reports W as having failed, quotes V's error detail, and tells the operator to
// re-run W, where the failure will not reproduce. Every clause is wrong about
// the walk the user named.
func explainWalkRecordAbsence(
	ctx context.Context,
	runs QueryScanRunsUseCase,
	walks QueryWalksUseCase,
	coord coordinate.ModuleCoordinate,
	walkID string,
) error {
	scanRuns, err := runs.ListRunsForWalk(ctx, walkID)
	if err != nil {
		return fmt.Errorf("no vulnerability record for %s in walk %s, and its scan runs could not be read: %w", coord, walkID, err)
	}
	if len(scanRuns) == 0 {
		// The remedy names the walk the operator passed — that walk stays the
		// subject. But scanning a resolution that a fresher walk has already
		// superseded produces a second scan surface for an outdated build list,
		// so a newer succeeded walk of the same root is worth one line.
		msg := fmt.Sprintf("no vulnerability scan run for walk %s — run: kanonarion vuln-scan %s", walkID, walkID)
		if note := newerWalkNote(ctx, walks, walkID); note != "" {
			msg += "\n" + note
		}
		return &exitError{code: ExitNotFound, msg: msg}
	}

	// The newest run that covered this module is the one whose generation
	// explains why the read missed.
	var covering *vuldomain.WalkScanRun
	for i := range scanRuns {
		if _, ok := scanRuns[i].PerModuleResults[coord]; !ok {
			continue
		}
		if covering == nil || scanRuns[i].CompletedAt.After(covering.CompletedAt) {
			covering = &scanRuns[i]
		}
	}
	if covering == nil {
		return &exitError{code: ExitNotFound, msg: fmt.Sprintf(
			"walk %s has %d vulnerability scan run(s), none covering %s — the walk does not contain this module",
			walkID, len(scanRuns), coord)}
	}
	if covering.PipelineVersion != vulnPipelineVersion {
		return &exitError{code: ExitNotFound, msg: fmt.Sprintf(
			"walk %s scanned %s under pipeline version %s, and this build reads pipeline version %s — re-run: kanonarion vuln-scan %s",
			walkID, coord, covering.PipelineVersion, vulnPipelineVersion, walkID)}
	}
	// The run claims this module and the generations agree, so a record should
	// have been readable. Say so rather than reporting a plain absence, which
	// would read as "not affected".
	return &exitError{code: ExitNotFound, msg: fmt.Sprintf(
		"walk %s scan run %s records %s at pipeline version %s, but no record was readable — the store may be inconsistent; re-run: kanonarion vuln-scan %s",
		walkID, covering.ID, coord, vulnPipelineVersion, walkID)}
}

// newerWalkNote reports, as one appendable line, whether a succeeded walk of
// the same root coordinate as walkID exists that is newer than walkID itself.
//
// It is advisory: every failure to answer — the named walk cannot be read, the
// listing fails, nothing newer exists — yields the empty string, because this
// decorates a refusal that is already correct. A note that cannot be computed
// must not turn a good diagnostic into an error about the diagnostic.
func newerWalkNote(ctx context.Context, walks QueryWalksUseCase, walkID string) string {
	if walks == nil {
		return ""
	}
	named, err := walks.GetWalk(ctx, walkID)
	if err != nil {
		return ""
	}
	return latestSucceededWalkNote(ctx, walks, named.Target, named.StartedAt)
}

// latestSucceededWalkNote returns the note for the most recent succeeded walk
// of root that started after notBefore, or "" when there is none. A zero
// notBefore imposes no lower bound.
func latestSucceededWalkNote(
	ctx context.Context,
	walks QueryWalksUseCase,
	root coordinate.ModuleCoordinate,
	notBefore time.Time,
) string {
	if walks == nil {
		return ""
	}
	succeeded := walkdomain.WalkSucceeded
	target := root
	// No LatestOnly: it groups by (target, scope), so a Target filter can still
	// return one row per scope. The plain listing is ordered started_at DESC, so
	// Limit 1 is exactly "the newest succeeded walk of this root".
	summaries, err := walks.ListWalks(ctx, walkports.WalkFilter{
		Target:        &target,
		OverallStatus: &succeeded,
		Limit:         1,
	})
	if err != nil || len(summaries) == 0 {
		return ""
	}
	newest := summaries[0]
	if !notBefore.IsZero() && !newest.StartedAt.After(notBefore) {
		return ""
	}
	// The frame is inside the one sentence, not on a line of its own: the note is
	// concatenated onto an error string. A newer walk of another platform is
	// still worth naming, and the reader has to be able to see that it is one.
	return fmt.Sprintf("note: a newer walk of %s exists (%s, frame %s, %s); consider scanning that instead",
		root, newest.ID, newest.BuildFrame(), walkAge(newest.StartedAt))
}

// walkAge renders how long ago t was, coarsely — the note exists to say
// "fresher than the one you named", and a minute-accurate duration would imply
// a precision the advice does not need.
func walkAge(t time.Time) string {
	d := cliSince(t)
	switch {
	case d < time.Minute:
		return "seconds ago"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// runVulnShowHistory lists what the store has ever recorded about a coordinate.
//
// It reads across generations deliberately, and it is the only vulnerability
// read that does. The point-in-time reads key on the pipeline version and refuse
// when the store holds the coordinate only at superseded ones, which is right: a
// verdict served today must be one this build's logic would reach. A history is
// a different question — it asks what was recorded, not what holds now — and the
// keyed read answered it by making the history vanish at the bump that produced
// it, which is the one moment the reader most needs to see the earlier rows.
//
// The rows a superseded generation wrote are marked, in vuln-by-id's words: they
// reach a reader here and nowhere else, and an unmarked one would be quoted as
// the current answer.
func runVulnShowHistory(ctx context.Context, coord coordinate.ModuleCoordinate, jsonOut bool, uc QueryVulnUseCase, graphs QueryCallGraphUseCase, stdout io.Writer) error {
	recs, err := uc.ListRecordsForModuleAllGenerations(ctx, coord)
	if err != nil {
		return fmt.Errorf("listing vulnerability history: %w", err)
	}
	if len(recs) == 0 {
		// Nothing at any generation, so there is no supersession to report and
		// this is the genuine absence it reads as. The superseded branch the keyed
		// reads carry is unreachable from here by construction — the read above
		// sees every generation the census would have counted.
		return &exitError{code: ExitNotFound, msg: fmt.Sprintf("no vulnerability records for %s — run 'kanonarion vuln-scan' first", coord)}
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(toVulnRecordsJSON(recs, newRecordRootFunc(ctx, graphs))); err != nil {
			return fmt.Errorf("encoding vulnerability history: %w", err)
		}
		return nil
	}

	_, _ = fmt.Fprintf(stdout, "%s@%s — %d scan record(s)\n\n", coord.Path(), coord.Version(), len(recs))
	for _, rec := range recs {
		findingIDs := make([]string, 0, len(rec.Findings))
		for _, f := range rec.Findings {
			findingIDs = append(findingIDs, f.ID)
		}
		findingSummary := "no findings"
		if len(findingIDs) > 0 {
			findingSummary = strings.Join(findingIDs, "  ")
		}
		// The frame is on every line because two generations for one coordinate
		// and snapshot may be answers to two different questions rather than a
		// revision of one, and the dates alone cannot say which.
		_, _ = fmt.Fprintf(stdout, "  %s  walk=%-26s  snap=%-24s  frame=%-13s  %-26s  %-8s  %s\n",
			rec.ScannedAt.UTC().Format(time.RFC3339),
			rec.WalkID,
			rec.DatabaseSnapshot.Version(),
			vuldomain.RecordRooting(rec),
			vulnGenerationLabel(rec),
			rec.OverallStatus,
			findingSummary,
		)
	}
	if note := supersededHistoryNote(recs); note != "" {
		_, _ = fmt.Fprint(stdout, note)
	}
	return nil
}

// vulnGenerationLabel names the generation one row was written under, marking it
// when this build serves nothing from that generation anywhere else.
func vulnGenerationLabel(rec vuldomain.VulnerabilityRecord) string {
	if rec.PipelineVersion != vulnPipelineVersion {
		return "pipeline=" + rec.PipelineVersion + " [superseded]"
	}
	return "pipeline=" + rec.PipelineVersion
}

// supersededVulnRowCount counts the rows of a listing that a generation this
// build no longer serves produced.
func supersededVulnRowCount(records []vuldomain.VulnerabilityRecord) int {
	n := 0
	for _, rec := range records {
		if rec.PipelineVersion != vulnPipelineVersion {
			n++
		}
	}
	return n
}

// supersededHistoryNote states, once under a history listing, how much of it
// this build would not serve as an answer.
//
// It is supersededByIDNote's statement for a different listing, and it stops
// short of that one's second sentence: the rows here are a coordinate's whole
// history, so most of them are not "the newest evidence the store holds" and
// saying so would be false. What both notes must carry is the same: how many
// rows, out of how many, and which pipeline this build reads.
func supersededHistoryNote(records []vuldomain.VulnerabilityRecord) string {
	n := supersededVulnRowCount(records)
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(
		"\nnotice: %d of %d record(s) were produced by superseded scan logic (this build reads pipeline %s).\n"+
			"        They are the history this coordinate has, and they are not what a current scan would\n"+
			"        answer — the point-in-time reads serve none of them. Re-scan to add a current record:\n"+
			"          kanonarion vuln-scan --module %s --reachability\n",
		n, len(records), vulnPipelineVersion, coordOf(records))
}

// coordOf names the coordinate a single-coordinate listing is about, taken from
// the rows themselves so the remedy line cannot name a different module from the
// one the rows describe.
func coordOf(records []vuldomain.VulnerabilityRecord) string {
	if len(records) == 0 {
		return ""
	}
	return records[0].Coordinate.String()
}

func newVulnByIDCmd(stdout, stderr io.Writer) *cobra.Command {
	var walkID string

	cmd := &cobra.Command{
		Use:   "vuln-by-id <finding-id>",
		Short: "Find all modules affected by a specific vulnerability ID",
		Long: `Find all modules affected by a specific vulnerability ID.

With no --walk-id, the answer spans the entire store: every module version,
pipeline version and database snapshot generation ever scanned — including a
module version that was patched out of your build several scans ago. Pass
--walk-id to restrict the answer to the modules one walk's scans covered,
which is what "which of my modules is hit by this CVE" usually means.`,
		Example: `  kanonarion vuln-by-id GO-2023-1234
  kanonarion vuln-by-id CVE-2023-12345 --json
  kanonarion vuln-by-id GO-2023-1234 --walk-id 01KQDBVW092ER1HNXZ60X27CMD`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runVulnByID(cmd.Context(), args[0], walkID, jsonOut, ctr.QueryVuln, ctr.QueryCallGraph, stdout)
		},
	}

	cmd.Flags().StringVar(&walkID, "walk-id", "", "restrict results to modules scanned under this walk (optional; defaults to every stored scan)")

	return cmd
}

func runVulnByID(ctx context.Context, findingID, walkID string, jsonOut bool, uc QueryVulnUseCase, graphs QueryCallGraphUseCase, stdout io.Writer) error {
	// Wrapped with the command name rather than a second description of the
	// operation: the use case already says "listing vulnerability records by
	// finding ID", and repeating that here tells the reader nothing new.
	records, err := uc.ListRecordsByFindingID(ctx, findingID, walkID)
	if err != nil {
		return fmt.Errorf("vuln-by-id: %w", err)
	}
	if jsonOut {
		// emit a JSON array ("[]" when empty), never plain text. Every finding
		// carries its derived reachability rung: this command's text surface prints
		// no verdict at all, so --json is the only place a consumer reads one, and
		// an unqualified negative here is the whole failure mode.
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(toVulnRecordsJSON(records, newRecordRootFunc(ctx, graphs))); err != nil {
			return fmt.Errorf("encoding vulnerability records: %w", err)
		}
		return nil
	}

	// A restricted list looks exactly like an unrestricted one, so without this
	// the reader has no way to tell that rows were withheld — and "no modules
	// affected" is the most consequential sentence this command can print.
	if walkID != "" {
		_, _ = fmt.Fprintf(stdout, "notice: results restricted to the modules scanned under walk %q\n", walkID)
	}

	if len(records) == 0 {
		if walkID != "" {
			_, _ = fmt.Fprintf(stdout, "no modules in walk %s affected by %s\n", walkID, findingID)
			return nil
		}
		_, _ = fmt.Fprintf(stdout, "no modules affected by %s\n", findingID)
		return nil
	}

	// Each row is one module version's current verdict, and a verdict is only
	// meaningful with the scan it came from: a Clean from a database snapshot
	// that predates the advisory says something very different from a Clean
	// scanned yesterday. Printing the generation is what lets a reader tell a
	// stale answer from a fresh one.
	// Two dates, because they answer different questions. vuln-db is the
	// generation of the advisory database the verdict was reached against — a
	// Clean from a database that predates the advisory is not evidence of
	// anything. scanned is when this tool last looked.
	// The generation is on every row because this read spans them by design —
	// that is its documented contract — and a row from a generation this build
	// will not serve anywhere else is not a row a reader may quote as the current
	// answer. Serving them silently while vuln-show denied they existed was one
	// inconsistency with two halves; the rows stay, and now they say what they
	// are. --json needs no such marking: it emits the record, pipeline_version
	// and all.
	for _, rec := range records {
		generation := "pipeline=" + rec.PipelineVersion
		if rec.PipelineVersion != vulnPipelineVersion {
			generation += " [superseded]"
		}
		_, _ = fmt.Fprintf(stdout, "%-60s %-12s vuln-db=%-24s scanned=%-20s %s\n",
			rec.Coordinate.Path()+"@"+rec.Coordinate.Version(),
			rec.OverallStatus,
			rec.DatabaseSnapshot.Version(),
			rec.ScannedAt.UTC().Format(time.RFC3339),
			generation)
	}
	if note := supersededByIDNote(records); note != "" {
		_, _ = fmt.Fprint(stdout, note)
	}
	return nil
}

// supersededByIDNote states, once under the listing, that some of the rows above
// come from generations this build serves nowhere else — so a reader who takes
// one to vuln-show and is told the record is superseded has already been told
// why, here.
//
// Silent when every row is current, which is the ordinary case and where a
// standing caveat would only teach the reader to skip it.
func supersededByIDNote(records []vuldomain.VulnerabilityRecord) string {
	n := supersededVulnRowCount(records)
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(
		"\nnotice: %d of %d row(s) were produced by superseded scan logic (this build reads pipeline %s).\n"+
			"        They are the newest evidence the store holds for those coordinates, and they are not\n"+
			"        what a current scan would answer. Re-scan a coordinate to replace one.\n",
		n, len(records), vulnPipelineVersion)
}
