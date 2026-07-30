package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/spf13/cobra"
)

func newVulnCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vuln <module>@<version>",
		Short: "Show the vulnerability record for a module",
		Example: `  kanonarion vuln github.com/gin-gonic/gin@v1.6.2
  kanonarion vuln github.com/gin-gonic/gin@v1.6.2 --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runVuln(cmd.Context(), args[0], jsonOut, ctr.QueryVuln, ctr.QueryScanRuns, stdout)
		},
	}

	return cmd
}

func runVuln(ctx context.Context, arg string, jsonOut bool, uc QueryVulnUseCase, runs QueryScanRunsUseCase, stdout io.Writer) error {
	// runs is unused on this path — it only explains a walk-scoped miss, and
	// this command names no walk — but it is threaded rather than nil so the
	// two entry points cannot drift into different behaviour.
	return runVulnShow(ctx, arg, "", jsonOut, false, uc, runs, stdout)
}

// printVulnRecord renders a single VulnerabilityRecord in human-readable form;
// shared between `vuln`, `vuln-show`, and any future text presenter.
func printVulnRecord(stdout io.Writer, rec vuldomain.VulnerabilityRecord) {
	coverage, _ := vuldomain.RecordAxes(rec)
	label := string(rec.OverallStatus)
	// Whether the summary word needs a coverage caveat beside it is a coverage
	// question. Gating on the word instead left the cause off exactly the records
	// that most need it: a metadata-only record that matched an advisory reads
	// Affected, so its "version-not-in-toolchain" went unprinted.
	if coverage == vuldomain.CoverageUnscannable && rec.UnscanReason != "" {
		label = fmt.Sprintf("%s (%s)", rec.OverallStatus, rec.UnscanReason)
	}
	_, _ = fmt.Fprintf(stdout, "%s@%s — %s\n", rec.Coordinate.Path(), rec.Coordinate.Version(), label)
	_, _ = fmt.Fprintf(stdout, "  Walk:            %s\n", rec.WalkID)
	// The analysis frame is printed on every record, including "not recorded".
	// A reachability finding means something different in each: isolated answers
	// "is this advisory reachable in the module examined alone", target-rooted
	// answers "is it reachable in the build we ship". Leaving it off would let a
	// reader take one for the other, which is exactly what happened while the two
	// shared a row.
	_, _ = fmt.Fprintf(stdout, "  Analysis frame:  %s\n", vuldomain.RecordRooting(rec))
	// First and last validated are stated as distinct facts: when the verdict was
	// first established versus the run that last re-confirmed it. The reader, not
	// kanonarion, judges whether that is acceptably fresh.
	if !rec.FirstScannedAt.IsZero() {
		_, _ = fmt.Fprintf(stdout, "  First validated: %s\n", rec.FirstScannedAt.UTC().Format(time.RFC3339))
	}
	_, _ = fmt.Fprintf(stdout, "  Last validated:  %s\n", rec.ScannedAt.UTC().Format(time.RFC3339))
	_, _ = fmt.Fprintf(stdout, "  Snapshot:        %s@%s\n", rec.DatabaseSnapshot.Source(), rec.DatabaseSnapshot.Version())
	if !rec.DatabaseSnapshot.RetrievedAt().IsZero() {
		_, _ = fmt.Fprintf(stdout, "  Snapshot age:    retrieved %s (%d day(s) old at validation)\n",
			rec.DatabaseSnapshot.RetrievedAt().UTC().Format(time.RFC3339),
			vuldomain.SnapshotAgeDays(rec.ScannedAt, rec.DatabaseSnapshot.RetrievedAt()))
	}
	// The coverage caveat is printed from the coverage axis, and printing it does
	// not end the record: a coverage gap and an advisory match are independent
	// facts, and a record carrying both owes both lines. Returning after the reason
	// — which routing on the collapsed word did — would have dropped the findings
	// of every metadata-only record the moment this switch started catching them.
	switch coverage {
	case vuldomain.CoverageFailedScan:
		reason := rec.ErrorDetail
		if reason == "" {
			reason = "unknown reason"
		}
		_, _ = fmt.Fprintf(stdout, "  Reason:   %s\n", reason)
	case vuldomain.CoverageUnscannable:
		reason := rec.UnscannableReason
		if reason == "" {
			reason = "unknown reason"
		}
		_, _ = fmt.Fprintf(stdout, "  Reason:   %s\n", reason)
	case vuldomain.CoverageAnalysed:
		// Analysed: no caveat owed, the findings below are the whole answer.
	}
	if len(rec.Findings) == 0 {
		// "No findings" is a claim only an analysed module can make. On a coverage
		// gap the reason line above is the answer, and printing "No findings" beside
		// it would read as an all-clear for a module nothing was ever looked at in.
		if coverage == vuldomain.CoverageAnalysed {
			_, _ = fmt.Fprintln(stdout, "  No findings.")
		}
		return
	}
	printFindingLines(stdout, rec)
}

// reachabilityLabel renders the one-word reachability tag beside a finding.
//
// It has three outcomes, not two. A finding whose answer was never determined at
// symbol level — because the advisory names no symbol for this module path, or
// because the analysis could not decide — is not a negative: labelling it "not
// reachable" reports a search that was never run, and the operator acts on the
// negative by not upgrading. notReachable lets each caller keep its own wording
// for the genuine negative, which differs in how much of the instrument it names.
func reachabilityLabel(f vuldomain.VulnerabilityFinding, notReachable string) string {
	if f.Reachable == nil {
		// A reachability question that was asked and could not be answered is not
		// the same as one nobody asked, and the blank label rendered them alike. The
		// note printed under the finding carries the reason; this is what stops the
		// entry reading as a finding reachability was simply not run for.
		if f.ReachabilityAttemptFailed() {
			return " [reachability requested but not computed]"
		}
		return ""
	}
	if f.Reachable.IsReachable {
		return " [reachable]"
	}
	if f.AdvisoryNamesNoSymbols {
		return " [affected at package level; symbol-level reachability not determined]"
	}
	if f.Reachable.Confidence == vuldomain.ConfidenceUnknown {
		return " [reachability not determined]"
	}
	return notReachable
}

func printFindingLines(stdout io.Writer, rec vuldomain.VulnerabilityRecord) {
	for _, f := range rec.Findings {
		aliases := ""
		if len(f.Aliases) > 0 {
			aliases = " (" + strings.Join(f.Aliases, ", ") + ")"
		}
		_, _ = fmt.Fprintf(stdout, "  %s%s%s: %s\n", f.ID, aliases, reachabilityLabel(f, " [not reachable]"), f.Summary)
		// The retraction is printed as its own line, ahead of the range and the fix,
		// because it changes what the rest of the entry means: an affected range and
		// a fixed version for a retracted advisory describe a report that was
		// withdrawn, and acting on the fix line would be acting on nothing. Upstream
		// signals this only by prefixing the summary with "WITHDRAWN: ", which is
		// prose a reader may or may not notice and no consumer could route on.
		if f.IsWithdrawn() {
			_, _ = fmt.Fprintf(stdout, "      WITHDRAWN: advisory retracted upstream %s — not a finding against this module\n",
				f.WithdrawnAt.UTC().Format(time.RFC3339))
		}
		if f.AffectedRange != "" {
			_, _ = fmt.Fprintf(stdout, "      affected: %s\n", f.AffectedRange)
		}
		// FixDisplay renders "no fix available" explicitly rather than leaving the
		// remediation question blank — a finding exists to answer "will a bump fix
		// it?", and absence of a fix is an answer, not missing data.
		_, _ = fmt.Fprintf(stdout, "      fix:      %s\n", f.FixDisplay())
		if len(f.AffectedSymbols) > 0 {
			_, _ = fmt.Fprintf(stdout, "      symbols:  %s\n", strings.Join(f.AffectedSymbols, ", "))
		}
		// Printed where the symbols would have been, because the empty symbol list
		// is the thing being explained: a reader must not take it for a symbol list
		// that failed to load, nor read the absent route as "nothing calls it".
		if f.AdvisoryNamesNoSymbols {
			_, _ = fmt.Fprintln(stdout, "      symbols:  none named by the advisory for this module path — affected at package level, symbol-level reachability not determinable")
		}
		// A reachability answer never prints without saying what produced it. The
		// same advisory in the same module is reachable in one build and not in
		// the next, so an unlabelled answer reads as a property of the module and
		// is a property of one analysis of one build.
		if f.Reachable != nil {
			_, _ = fmt.Fprintf(stdout, "      derived:  %s\n", f.Reachable.DerivedBy)
		}
		// The route is what answers "which of my dependencies reaches this". It is
		// printed entry point first, and says so when its hops carry no versions,
		// because an unversioned route cannot be checked against another build.
		if f.Reachable != nil && len(f.Reachable.Routes) > 0 {
			route := f.Reachable.Routes[0]
			caveat := ""
			if !route.IsVersioned() {
				caveat = " (hops carry no module version)"
			}
			_, _ = fmt.Fprintf(stdout, "      route:    entry point first%s\n", caveat)
			for _, hop := range route {
				_, _ = fmt.Fprintf(stdout, "        %s\n", hop)
			}
			if extra := len(f.Reachable.Routes) - 1; extra > 0 {
				_, _ = fmt.Fprintf(stdout, "        (%d further route(s) recorded)\n", extra)
			}
		}
		if f.ReachabilityNote != "" {
			_, _ = fmt.Fprintf(stdout, "      reachability: %s\n", f.ReachabilityNote)
		}
	}
}
