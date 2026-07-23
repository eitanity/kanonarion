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
			return runVuln(cmd.Context(), args[0], jsonOut, ctr.QueryVuln, stdout)
		},
	}

	return cmd
}

func runVuln(ctx context.Context, arg string, jsonOut bool, uc QueryVulnUseCase, stdout io.Writer) error {
	return runVulnShow(ctx, arg, "", jsonOut, false, uc, stdout)
}

// printVulnRecord renders a single VulnerabilityRecord in human-readable form;
// shared between `vuln`, `vuln-show`, and any future text presenter.
func printVulnRecord(stdout io.Writer, rec vuldomain.VulnerabilityRecord) {
	label := string(rec.OverallStatus)
	if rec.OverallStatus == vuldomain.StatusUnscannable && rec.UnscanReason != "" {
		label = fmt.Sprintf("%s (%s)", rec.OverallStatus, rec.UnscanReason)
	}
	_, _ = fmt.Fprintf(stdout, "%s@%s — %s\n", rec.Coordinate.Path, rec.Coordinate.Version, label)
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
	switch rec.OverallStatus {
	case vuldomain.StatusScanFailed:
		reason := rec.ErrorDetail
		if reason == "" {
			reason = "unknown reason"
		}
		_, _ = fmt.Fprintf(stdout, "  Reason:   %s\n", reason)
		return
	case vuldomain.StatusUnscannable:
		reason := rec.UnscannableReason
		if reason == "" {
			reason = "unknown reason"
		}
		_, _ = fmt.Fprintf(stdout, "  Reason:   %s\n", reason)
		return
	}
	if len(rec.Findings) == 0 {
		_, _ = fmt.Fprintln(stdout, "  No findings.")
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
