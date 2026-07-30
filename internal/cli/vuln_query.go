package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

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
			return runVulnShow(cmd.Context(), args[0], walkID, jsonOut, history, ctr.QueryVuln, ctr.QueryScanRuns, stdout)
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
	if walkID == "" {
		r, ok, err := uc.GetLatestRecord(ctx, coord, vulnPipelineVersion)
		if err != nil {
			return fmt.Errorf("getting vulnerability record: %w", err)
		}
		if !ok {
			return fmt.Errorf("no vulnerability record for %s — run: kanonarion vuln-scan <walk-id>", coord)
		}
		rec = r
	} else {
		r, ok, err := uc.GetLatestRecordForWalk(ctx, coord, vulnPipelineVersion, walkID)
		if err != nil {
			return fmt.Errorf("getting vulnerability record: %w", err)
		}
		if !ok {
			return explainWalkRecordAbsence(ctx, runs, coord, walkID)
		}
		rec = r
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rec); err != nil {
			return fmt.Errorf("encoding vulnerability record: %w", err)
		}
		return nil
	}

	printVulnRecord(stdout, rec)
	return nil
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
	coord coordinate.ModuleCoordinate,
	walkID string,
) error {
	scanRuns, err := runs.ListRunsForWalk(ctx, walkID)
	if err != nil {
		return fmt.Errorf("no vulnerability record for %s in walk %s, and its scan runs could not be read: %w", coord, walkID, err)
	}
	if len(scanRuns) == 0 {
		return fmt.Errorf("no vulnerability scan run for walk %s — run: kanonarion vuln-scan %s", walkID, walkID)
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
		return fmt.Errorf("walk %s has %d vulnerability scan run(s), none covering %s — the walk does not contain this module",
			walkID, len(scanRuns), coord)
	}
	if covering.PipelineVersion != vulnPipelineVersion {
		return fmt.Errorf("walk %s scanned %s under pipeline version %s, and this build reads pipeline version %s — re-run: kanonarion vuln-scan %s",
			walkID, coord, covering.PipelineVersion, vulnPipelineVersion, walkID)
	}
	// The run claims this module and the generations agree, so a record should
	// have been readable. Say so rather than reporting a plain absence, which
	// would read as "not affected".
	return fmt.Errorf("walk %s scan run %s records %s at pipeline version %s, but no record was readable — the store may be inconsistent; re-run: kanonarion vuln-scan %s",
		walkID, covering.ID, coord, vulnPipelineVersion, walkID)
}

func runVulnShowHistory(ctx context.Context, coord coordinate.ModuleCoordinate, jsonOut bool, uc QueryVulnUseCase, stdout io.Writer) error {
	recs, err := uc.ListRecordsForModule(ctx, coord, vulnPipelineVersion)
	if err != nil {
		return fmt.Errorf("listing vulnerability history: %w", err)
	}
	if len(recs) == 0 {
		return fmt.Errorf("no vulnerability records for %s — run 'kanonarion vuln-scan' first", coord)
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
