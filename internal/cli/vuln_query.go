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
	var history bool

	cmd := &cobra.Command{
		Use:   "vuln-show <module>@<version>",
		Short: "Show the vulnerability record for a module",
		Long: `Show the vulnerability record for a module.

When --walk-id is omitted, vuln-show returns the most recent scan for the
module across all walks. Pass --walk-id to pin to a specific walk.

Use --history to list every stored scan record for the module across all
walks and snapshots, newest first. This shows when a finding first appeared
or was absent because the vulnerability database snapshot predated it.`,
		Example: `  kanonarion vuln-show github.com/gin-gonic/gin@v1.6.2
  kanonarion vuln-show github.com/gin-gonic/gin@v1.6.2 --json
  kanonarion vuln-show github.com/gin-gonic/gin@v1.6.2 --history
  kanonarion vuln-show github.com/gin-gonic/gin@v1.6.2 --history --json
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
			return runVulnShow(cmd.Context(), args[0], walkID, jsonOut, history, ctr.QueryVuln, ctr.QueryScanRuns, ctr.QueryWalks, ctr.QueryCallGraph, stdout)
		},
	}

	cmd.Flags().BoolVar(&history, "history", false, "list all scan records across walks and snapshots")
	cmd.Flags().StringVar(&walkID, "walk-id", "", "walk ID the scan was performed under (optional; defaults to most recent scan)")

	return cmd
}

func runVulnShow(
	ctx context.Context,
	arg, walkID string,
	jsonOut, history bool,
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
		return runVulnShowHistory(ctx, coord, jsonOut, uc, stdout)
	}

	var rec vuldomain.VulnerabilityRecord
	var isolated vuldomain.VulnerabilityRecord
	var hasIsolated bool
	if walkID == "" {
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
		r, aside, has, ok := selectConsumerRecord(recs, coord)
		if !ok {
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
		r, ok, err := uc.GetLatestRecordForWalk(ctx, coord, vulnPipelineVersion, walkID)
		if err != nil {
			return fmt.Errorf("getting vulnerability record: %w", err)
		}
		if !ok {
			return explainWalkRecordAbsence(ctx, runs, walks, coord, walkID)
		}
		rec = r
	}

	if jsonOut {
		// The JSON body stays a bare VulnerabilityRecord: that shape is this
		// command's published contract, and wrapping it to carry the aside would
		// break every consumer parsing it. The served record is the consumer-frame
		// one either way, so --json now agrees with reachability --json on the
		// verdict; the declined isolated answer is reported on the text surface and
		// by 'reachability --json', whose result type has a field for it.
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rec); err != nil {
			return fmt.Errorf("encoding vulnerability record: %w", err)
		}
		return nil
	}

	printVulnRecord(stdout, rec, newRouteRootFunc(ctx, graphs, rec))
	printDeclinedIsolatedFrame(stdout, isolated, hasIsolated)
	return nil
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
			lines = append(lines, fmt.Sprintf("    %s: %s [confidence: %s, by: %s]",
				f.ID, aside.Verdict, aside.Confidence, aside.Method))
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
	return fmt.Sprintf("note: a newer walk of %s exists (%s, %s); consider scanning that instead",
		root, newest.ID, walkAge(newest.StartedAt))
}

// walkAge renders how long ago t was, coarsely — the note exists to say
// "fresher than the one you named", and a minute-accurate duration would imply
// a precision the advice does not need.
func walkAge(t time.Time) string {
	d := time.Since(t)
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

func runVulnShowHistory(ctx context.Context, coord coordinate.ModuleCoordinate, jsonOut bool, uc QueryVulnUseCase, stdout io.Writer) error {
	recs, err := uc.ListRecordsForModule(ctx, coord, vulnPipelineVersion)
	if err != nil {
		return fmt.Errorf("listing vulnerability history: %w", err)
	}
	if len(recs) == 0 {
		return &exitError{code: ExitNotFound, msg: fmt.Sprintf("no vulnerability records for %s — run 'kanonarion vuln-scan' first", coord)}
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(recs); err != nil {
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
		_, _ = fmt.Fprintf(stdout, "  %s  walk=%-26s  snap=%-24s  frame=%-13s  %-8s  %s\n",
			rec.ScannedAt.UTC().Format(time.RFC3339),
			rec.WalkID,
			rec.DatabaseSnapshot.Version(),
			vuldomain.RecordRooting(rec),
			rec.OverallStatus,
			findingSummary,
		)
	}
	return nil
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
			return runVulnByID(cmd.Context(), args[0], walkID, jsonOut, ctr.QueryVuln, stdout)
		},
	}

	cmd.Flags().StringVar(&walkID, "walk-id", "", "restrict results to modules scanned under this walk (optional; defaults to every stored scan)")

	return cmd
}

func runVulnByID(ctx context.Context, findingID, walkID string, jsonOut bool, uc QueryVulnUseCase, stdout io.Writer) error {
	// Wrapped with the command name rather than a second description of the
	// operation: the use case already says "listing vulnerability records by
	// finding ID", and repeating that here tells the reader nothing new.
	records, err := uc.ListRecordsByFindingID(ctx, findingID, walkID)
	if err != nil {
		return fmt.Errorf("vuln-by-id: %w", err)
	}
	if jsonOut {
		// emit a JSON array ("[]" when empty), never plain text.
		if records == nil {
			records = []vuldomain.VulnerabilityRecord{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(records); err != nil {
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
	for _, rec := range records {
		_, _ = fmt.Fprintf(stdout, "%-60s %-12s vuln-db=%-24s scanned=%s\n",
			rec.Coordinate.Path()+"@"+rec.Coordinate.Version(),
			rec.OverallStatus,
			rec.DatabaseSnapshot.Version(),
			rec.ScannedAt.UTC().Format(time.RFC3339))
	}
	return nil
}
