package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/spf13/cobra"
)

func newVulnScanListCmd(stdout, stderr io.Writer) *cobra.Command {
	var limit int

	cmd := &cobra.Command{
		Use:   "vuln-scan-list [walk-id]",
		Short: "List walk scan runs",
		Example: `  kanonarion vuln-scan-list
  kanonarion vuln-scan-list 01KQDBVW092ER1HNXZ60X27CMD`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var walkID string
			if len(args) == 1 {
				walkID = args[0]
			}
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runScanList(cmd.Context(), walkID, limit, ctr.QueryScanRuns, stdout)
		},
	}

	cmd.Flags().IntVar(&limit, "limit", 20, "maximum number of results to return (0 = unlimited)")

	return cmd
}

func runScanList(ctx context.Context, walkID string, limit int, uc QueryScanRunsUseCase, stdout io.Writer) error {
	var (
		runs []vuldomain.WalkScanRun
		err  error
	)
	if walkID == "" {
		runs, err = uc.ListAllRuns(ctx)
	} else {
		runs, err = uc.ListRunsForWalk(ctx, walkID)
	}
	if err != nil {
		return fmt.Errorf("listing scan runs: %w", err)
	}
	if limit > 0 && len(runs) > limit {
		runs = runs[:limit]
	}
	if jsonOut {
		type entry struct {
			ID          string `json:"id"`
			WalkID      string `json:"walk_id"`
			Status      string `json:"status"`
			CompletedAt string `json:"completed_at"`
		}
		out := make([]entry, 0, len(runs))
		for _, r := range runs {
			out = append(out, entry{r.ID, r.WalkID, string(r.OverallStatus), isoTime(r.CompletedAt)})
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}
	if len(runs) == 0 {
		_, _ = fmt.Fprintln(stdout, "no scan runs found")
		return nil
	}
	for _, r := range runs {
		_, _ = fmt.Fprintf(stdout, "%-26s  walk=%-26s  status=%-12s  %s\n",
			r.ID, r.WalkID, string(r.OverallStatus), r.CompletedAt.UTC().Format("2006-01-02T15:04:05Z"))
	}
	return nil
}

func newVulnScanShowCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vuln-scan-show <run-id>",
		Short: "Show details of a walk scan run",
		Example: `  kanonarion vuln-scan-show 01KQDBVW092ER1HNXZ60X27CMD
  kanonarion vuln-scan-show 01KQDBVW092ER1HNXZ60X27CMD --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runScanShow(cmd.Context(), args[0], jsonOut, ctr.QueryScanRuns, ctr.QueryVuln, stdout)
		},
	}

	return cmd
}

type scanAffectedModule struct {
	Coordinate string                           `json:"coordinate"`
	Status     string                           `json:"status"`
	Findings   []vuldomain.VulnerabilityFinding `json:"findings,omitempty"`
}

type scanShowJSON struct {
	ID               string                                 `json:"id"`
	WalkID           string                                 `json:"walk_id"`
	Snapshot         vuldomain.DatabaseSnapshot             `json:"snapshot"`
	PerModuleResults map[coordinate.ModuleCoordinate]string `json:"per_module_results"`
	StartedAt        time.Time                              `json:"started_at"`
	CompletedAt      time.Time                              `json:"completed_at"`
	OverallStatus    vuldomain.WalkScanStatus               `json:"overall_status"`
	PipelineVersion  string                                 `json:"pipeline_version"`
	Operator         string                                 `json:"operator"`
	ContentHash      string                                 `json:"content_hash"`
	AffectedModules  []scanAffectedModule                   `json:"affected_modules,omitempty"`
}

func runScanShow(ctx context.Context, runID string, jsonOut bool, ucRuns QueryScanRunsUseCase, ucVuln QueryVulnUseCase, stdout io.Writer) error {
	run, found, err := ucRuns.GetRun(ctx, runID)
	if err != nil {
		return fmt.Errorf("getting scan run: %w", err)
	}
	if !found {
		return fmt.Errorf("scan run not found: %s", runID)
	}

	affected, unscannable := buildScanAffectedModules(ctx, run, ucVuln)

	if jsonOut {
		out := scanShowJSON{
			ID:               run.ID,
			WalkID:           run.WalkID,
			Snapshot:         run.Snapshot,
			PerModuleResults: run.PerModuleResults,
			StartedAt:        run.StartedAt,
			CompletedAt:      run.CompletedAt,
			OverallStatus:    run.OverallStatus,
			PipelineVersion:  run.PipelineVersion,
			Operator:         run.Operator,
			ContentHash:      run.ContentHash,
			AffectedModules:  affected,
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return fmt.Errorf("encoding scan run: %w", err)
		}
		return nil
	}

	_, _ = fmt.Fprintf(stdout, "ID:          %s\n", run.ID)
	_, _ = fmt.Fprintf(stdout, "Walk ID:     %s\n", run.WalkID)
	_, _ = fmt.Fprintf(stdout, "Status:      %s\n", run.OverallStatus)
	_, _ = fmt.Fprintf(stdout, "Operator:    %s\n", run.Operator)
	_, _ = fmt.Fprintf(stdout, "Started:     %s\n", run.StartedAt.UTC().Format(time.RFC3339))
	_, _ = fmt.Fprintf(stdout, "Completed:   %s\n", run.CompletedAt.UTC().Format(time.RFC3339))
	_, _ = fmt.Fprintf(stdout, "Snapshot:    %s@%s\n", run.Snapshot.Source, run.Snapshot.Version)
	_, _ = fmt.Fprintf(stdout, "Modules:     %d\n", len(run.PerModuleResults))
	// One line per reason rather than one for the out-of-toolchain set alone, so
	// a Partial run is explained whichever reason produced it and no Unscannable
	// module is absent from the detail view.
	for _, section := range unscannable.sections() {
		line := fmt.Sprintf("%s: %d", section.display.heading, len(section.coords))
		if section.display.hint != "" {
			line += " — " + section.display.hint
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", line)
	}
	if len(affected) > 0 {
		_, _ = fmt.Fprintf(stdout, "\nAffected modules (%d):\n", len(affected))
		for _, m := range affected {
			findingIDs := make([]string, 0, len(m.Findings))
			for _, f := range m.Findings {
				findingIDs = append(findingIDs, f.ID)
			}
			_, _ = fmt.Fprintf(stdout, "  %s  %s\n", m.Coordinate, strings.Join(findingIDs, "  "))
		}
	}
	return nil
}

// buildScanAffectedModules looks up VulnerabilityRecords for each module in
// the scan run and returns entries where findings were present.
// It also returns, as a second value, every Unscannable module collected by
// reason, so the detail view carries the same categories the scan output does.
// Previously only the out-of-toolchain reason was collected and every other
// Unscannable record was dropped from the query output entirely.
func buildScanAffectedModules(ctx context.Context, run vuldomain.WalkScanRun, uc QueryVulnUseCase) ([]scanAffectedModule, *unscannableRollup) {
	coords := make([]coordinate.ModuleCoordinate, 0, len(run.PerModuleResults))
	for coord := range run.PerModuleResults {
		coords = append(coords, coord)
	}
	sort.Slice(coords, func(i, j int) bool {
		if coords[i].Path != coords[j].Path {
			return coords[i].Path < coords[j].Path
		}
		return coords[i].Version < coords[j].Version
	})

	out := []scanAffectedModule(nil)
	unscannable := newUnscannableRollup()
	for _, coord := range coords {
		rec, found, err := uc.GetRecord(ctx, coord, vulnPipelineVersion, run.Snapshot)
		if err != nil || !found {
			continue
		}
		if rec.OverallStatus == vuldomain.StatusUnscannable {
			unscannable.add(rec.UnscanReason, coord.String(), rec.UnscannableReason)
			continue
		}
		if rec.OverallStatus != vuldomain.StatusAffected {
			continue
		}
		out = append(out, scanAffectedModule{
			Coordinate: coord.String(),
			Status:     string(rec.OverallStatus),
			Findings:   rec.Findings,
		})
	}
	return out, unscannable
}

// newVulnScanHistoryCmd returns the vuln-scan-history command.
func newVulnScanHistoryCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vuln-scan-history <walk-id>",
		Short: "List every scan run for a walk in chronological order",
		Example: `  kanonarion vuln-scan-history 01KQDBVW092ER1HNXZ60X27CMD
  kanonarion vuln-scan-history 01KQDBVW092ER1HNXZ60X27CMD --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runScanHistory(cmd.Context(), args[0], jsonOut, ctr.QueryScanRuns, stdout)
		},
	}

	return cmd
}

func runScanHistory(ctx context.Context, walkID string, jsonOut bool, uc QueryScanRunsUseCase, stdout io.Writer) error {
	runs, err := uc.ListRunsForWalk(ctx, walkID)
	if err != nil {
		return fmt.Errorf("listing scan runs: %w", err)
	}
	// The empty case is answered on the caller's own channel: under --json an
	// empty array, never a human sentence that fails to parse. Only the text
	// path gets the prose.
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if runs == nil {
			runs = []vuldomain.WalkScanRun{}
		}
		if err := enc.Encode(runs); err != nil {
			return fmt.Errorf("encoding scan runs: %w", err)
		}
		return nil
	}

	if len(runs) == 0 {
		_, _ = fmt.Fprintf(stdout, "no scan runs found for walk %s\n", walkID)
		return nil
	}

	_, _ = fmt.Fprintf(stdout, "%-26s  %-12s  %-30s  %s\n", "RUN ID", "STATUS", "SNAPSHOT", "COMPLETED")
	for _, r := range runs {
		snap := r.Snapshot.Source + "@" + r.Snapshot.Version
		_, _ = fmt.Fprintf(stdout, "%-26s  %-12s  %-30s  %s\n",
			r.ID,
			string(r.OverallStatus),
			snap,
			r.CompletedAt.UTC().Format("2006-01-02T15:04:05Z"),
		)
	}
	return nil
}

// newVulnScanDiffCmd returns the vuln-scan-diff command.
func newVulnScanDiffCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vuln-scan-diff <run-id-a> <run-id-b>",
		Short: "Compare two scan runs of the same walk",
		Long: `vuln-scan-diff compares two WalkScanRuns of the same walk and reports:
  - findings present only in B (newly known vulnerabilities)
  - findings present only in A (resolved / no longer known)
  - findings present in both with changed reachability`,
		Example: `  kanonarion vuln-scan-diff vscan-01ABC vscan-01DEF
  kanonarion vuln-scan-diff vscan-01ABC vscan-01DEF --json`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runScanDiff(cmd.Context(), args[0], args[1], jsonOut, ctr.DiffScanRuns, stdout)
		},
	}

	return cmd
}

func runScanDiff(ctx context.Context, runIDA, runIDB string, jsonOut bool, ucDiff DiffScanRunsUseCase, stdout io.Writer) error {
	diff, err := ucDiff.Diff(ctx, runIDA, runIDB)
	if err != nil {
		return fmt.Errorf("computing scan diff: %w", err)
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(diff); err != nil {
			return fmt.Errorf("encoding scan diff: %w", err)
		}
		return nil
	}

	_, _ = fmt.Fprintf(stdout, "Diff: %s → %s\n", runIDA, runIDB)
	_, _ = fmt.Fprintf(stdout, "Walk: %s\n\n", diff.RunA.WalkID)

	if len(diff.NewFindings) == 0 && len(diff.ResolvedFindings) == 0 && len(diff.ReachabilityChanges) == 0 && len(diff.UnresolvedFindings) == 0 {
		_, _ = fmt.Fprintln(stdout, "No differences.")
		return nil
	}

	if len(diff.NewFindings) > 0 {
		_, _ = fmt.Fprintf(stdout, "NEW findings (%d):\n", len(diff.NewFindings))
		for _, d := range diff.NewFindings {
			_, _ = fmt.Fprintf(stdout, "  + %s  %s@%s  %s\n", d.Finding.ID, d.Coordinate.Path, d.Coordinate.Version, d.Finding.Summary)
		}
		_, _ = fmt.Fprintln(stdout)
	}

	if len(diff.ResolvedFindings) > 0 {
		_, _ = fmt.Fprintf(stdout, "RESOLVED findings (%d):\n", len(diff.ResolvedFindings))
		for _, d := range diff.ResolvedFindings {
			_, _ = fmt.Fprintf(stdout, "  - %s  %s@%s  %s\n", d.Finding.ID, d.Coordinate.Path, d.Coordinate.Version, d.Finding.Summary)
		}
		_, _ = fmt.Fprintln(stdout)
	}

	if len(diff.ReachabilityChanges) > 0 {
		_, _ = fmt.Fprintf(stdout, "REACHABILITY changes (%d):\n", len(diff.ReachabilityChanges))
		for _, c := range diff.ReachabilityChanges {
			was := "not reachable"
			if c.WasReachable {
				was = "reachable"
			}
			now := "not reachable"
			if c.IsReachable {
				now = "reachable"
			}
			_, _ = fmt.Fprintf(stdout, "  ~ %s  %s@%s  %s → %s\n", c.Finding.ID, c.Coordinate.Path, c.Coordinate.Version, was, now)
		}
		_, _ = fmt.Fprintln(stdout)
	}

	if len(diff.UnresolvedFindings) > 0 {
		_, _ = fmt.Fprintf(stdout, "UNRESOLVED (%d) — completeness parity mismatch, verdict withheld:\n", len(diff.UnresolvedFindings))
		for _, u := range diff.UnresolvedFindings {
			_, _ = fmt.Fprintf(stdout, "  ? %s  %s@%s  would-be %s but %s\n",
				u.Finding.ID, u.Coordinate.Path, u.Coordinate.Version, u.Kind, u.Reason)
		}
	}

	return nil
}
