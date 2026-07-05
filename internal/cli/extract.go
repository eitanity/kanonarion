package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	extractapp "github.com/eitanity/kanonarion/internal/extract/application"
	domain "github.com/eitanity/kanonarion/internal/extract/domain"
	"github.com/eitanity/kanonarion/internal/extract/ports"
	"github.com/spf13/cobra"
)

type extractFlags struct {
	goBinary string
	stages   []string
	force    bool
	workers  int
}

func NewExtractCmd(stdout, stderr io.Writer) *cobra.Command {
	var f extractFlags
	cmd := &cobra.Command{
		Use:   "extract [walk-id]",
		Short: "Run extraction stages for all modules in a walk",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExtract(cmd.Context(), args[0], f, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&f.goBinary, "go-binary", "", "path to 'go' binary if not in PATH")
	cmd.Flags().StringSliceVar(&f.stages, "stages", []string{"license", "interface", "example"}, "Comma-separated list of stages to run (callgraph is excluded by default: it loads each module's full transitive dependency closure into SSA and OOMs on large walks; pass explicitly when needed)")
	cmd.Flags().BoolVar(&f.force, "force", false, "re-extract even if cached")
	cmd.Flags().IntVar(&f.workers, "workers", 0, "parallel module extraction workers (0 = number of CPUs; reduce to limit memory use)")

	cmd.AddCommand(newExtractShowCmd(stdout, stderr))
	cmd.AddCommand(newExtractListCmd(stdout, stderr))

	return cmd
}

func runExtract(ctx context.Context, walkID string, f extractFlags, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)

	ctr, cleanup, err := NewContainer(storeRoot, "", f.goBinary, false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	// Status preamble must go to stderr so that stdout is a clean data
	// channel — under --json, callers pipe stdout straight into jq and a
	// preamble line breaks parsing.
	_, _ = fmt.Fprintf(stderr, "Starting extraction for walk %s...\n", walkID)
	run, err := ctr.Extract.Execute(ctx, extractapp.ExtractRequest{
		WalkID:  walkID,
		Stages:  f.stages,
		Force:   f.force,
		Workers: f.workers,
	})
	if err != nil {
		return fmt.Errorf("extraction execution failed: %w", err)
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(run); err != nil {
			return fmt.Errorf("failed to encode JSON output: %w", err)
		}
		return nil
	}

	_, _ = fmt.Fprintf(stdout, "Extraction run %s completed with status: %s\n", run.ID, run.OverallStatus)
	_, _ = fmt.Fprintf(stdout, "Modules processed: %d\n", len(run.PerModuleResults))

	printExtractionFailures(stdout, run)

	return nil
}

// printExtractionFailures prints a breakdown of failed stages when the run is
// partial or failed. It is a no-op when every stage succeeded.
func printExtractionFailures(w io.Writer, run domain.ExtractionRun) {
	type stageFailure struct {
		module string
		stage  string
		errMsg string
	}
	var failures []stageFailure
	for coord, modResult := range run.PerModuleResults {
		for stageName, stageResult := range modResult.Stages {
			if stageResult.Status == domain.StageFailed {
				failures = append(failures, stageFailure{
					module: coord.String(),
					stage:  stageName,
					errMsg: stageResult.Error,
				})
			}
		}
	}
	if len(failures) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "Failed stages (%d):\n", len(failures))
	slices.SortFunc(failures, func(a, b stageFailure) int {
		if a.module != b.module {
			return strings.Compare(a.module, b.module)
		}
		return strings.Compare(a.stage, b.stage)
	})
	for _, f := range failures {
		if f.errMsg != "" {
			_, _ = fmt.Fprintf(w, "  %s  stage=%s  error=%s\n", f.module, f.stage, f.errMsg)
		} else {
			_, _ = fmt.Fprintf(w, "  %s  stage=%s\n", f.module, f.stage)
		}
	}
}

func newExtractShowCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show [run-id]",
		Short: "Show details of an extraction run",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()

			run, err := ctr.QueryExtract.GetExtractionRun(cmd.Context(), args[0])
			if err != nil {
				return fmt.Errorf("failed to get extraction run: %w", err)
			}

			if jsonOut {
				enc := json.NewEncoder(stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(run); err != nil {
					return fmt.Errorf("failed to encode JSON output: %w", err)
				}
				return nil
			}

			_, _ = fmt.Fprintf(stdout, "Run ID:         %s\n", run.ID)
			_, _ = fmt.Fprintf(stdout, "Walk ID:        %s\n", run.WalkID)
			_, _ = fmt.Fprintf(stdout, "Status:         %s\n", run.OverallStatus)
			_, _ = fmt.Fprintf(stdout, "Started:        %s\n", run.StartedAt.Format(time.RFC3339))
			_, _ = fmt.Fprintf(stdout, "Completed:      %s\n", run.CompletedAt.Format(time.RFC3339))
			_, _ = fmt.Fprintf(stdout, "Stages:         %s\n", strings.Join(run.RequestedStages, ", "))
			_, _ = fmt.Fprintf(stdout, "Module Results: %d\n", len(run.PerModuleResults))

			printExtractionFailures(stdout, run)

			return nil
		},
	}
	return cmd
}

func newExtractListCmd(stdout, stderr io.Writer) *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List extraction runs",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()

			runs, err := ctr.QueryExtract.ListExtractionRuns(cmd.Context(), ports.ExtractionRunFilter{Limit: limit})
			if err != nil {
				return fmt.Errorf("failed to list extraction runs: %w", err)
			}

			if jsonOut {
				type runJSON struct {
					ID            string                     `json:"id"`
					WalkID        string                     `json:"walk_id"`
					Status        domain.ExtractionRunStatus `json:"status"`
					ModuleCount   int                        `json:"module_count"`
					StartedAt     time.Time                  `json:"started_at"`
					CompletedAt   time.Time                  `json:"completed_at"`
				}
				out := make([]runJSON, len(runs))
				for i, r := range runs {
					out[i] = runJSON{
						ID:          r.ID,
						WalkID:      r.WalkID,
						Status:      r.OverallStatus,
						ModuleCount: r.ModuleCount,
						StartedAt:   r.StartedAt,
						CompletedAt: r.CompletedAt,
					}
				}
				enc := json.NewEncoder(stdout)
				enc.SetIndent("", "  ")
				if encErr := enc.Encode(out); encErr != nil {
					return fmt.Errorf("encoding JSON: %w", encErr)
				}
				return nil
			}

			_, _ = fmt.Fprintf(stdout, "%-26s %-26s %-10s %-12s %s\n", "RUN ID", "WALK ID", "STATUS", "MODULES", "STARTED")
			for _, r := range runs {
				_, _ = fmt.Fprintf(stdout, "%-26s %-26s %-10s %-12d %s\n",
					r.ID, r.WalkID, r.OverallStatus, r.ModuleCount, r.StartedAt.Format(time.RFC3339))
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 20, "maximum number of runs to return (0 = unlimited)")
	return cmd
}
