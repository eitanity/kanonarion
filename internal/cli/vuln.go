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
	// First and last validated are stated as distinct facts: when the verdict was
	// first established versus the run that last re-confirmed it. The reader, not
	// kanonarion, judges whether that is acceptably fresh.
	if !rec.FirstScannedAt.IsZero() {
		_, _ = fmt.Fprintf(stdout, "  First validated: %s\n", rec.FirstScannedAt.UTC().Format(time.RFC3339))
	}
	_, _ = fmt.Fprintf(stdout, "  Last validated:  %s\n", rec.ScannedAt.UTC().Format(time.RFC3339))
	_, _ = fmt.Fprintf(stdout, "  Snapshot:        %s@%s\n", rec.DatabaseSnapshot.Source, rec.DatabaseSnapshot.Version)
	if !rec.DatabaseSnapshot.RetrievedAt.IsZero() {
		_, _ = fmt.Fprintf(stdout, "  Snapshot age:    retrieved %s (%d day(s) old at validation)\n",
			rec.DatabaseSnapshot.RetrievedAt.UTC().Format(time.RFC3339),
			vuldomain.SnapshotAgeDays(rec.ScannedAt, rec.DatabaseSnapshot.RetrievedAt))
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
	for _, f := range rec.Findings {
		aliases := ""
		if len(f.Aliases) > 0 {
			aliases = " (" + strings.Join(f.Aliases, ", ") + ")"
		}
		reachability := ""
		if f.Reachable != nil {
			if f.Reachable.IsReachable {
				reachability = " [reachable]"
			} else {
				reachability = " [not reachable]"
			}
		}
		_, _ = fmt.Fprintf(stdout, "  %s%s%s: %s\n", f.ID, aliases, reachability, f.Summary)
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
		if f.ReachabilityNote != "" {
			_, _ = fmt.Fprintf(stdout, "      reachability: %s\n", f.ReachabilityNote)
		}
	}
}
