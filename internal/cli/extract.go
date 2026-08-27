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
	goBinary   string
	stages     []string
	force      bool
	workers    int
	noProgress bool
}

func NewExtractCmd(stdout, stderr io.Writer) *cobra.Command {
	var f extractFlags
	cmd := &cobra.Command{
		Use:         "extract [walk-id]",
		Annotations: map[string]string{annotationStoreIntent: StoreIntentCreate},
		Short:       "Run extraction stages for all modules in a walk",
		Args:        cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExtract(cmd.Context(), args[0], f, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&f.goBinary, "go-binary", "", "path to 'go' binary if not in PATH")
	cmd.Flags().StringSliceVar(&f.stages, "stages", []string{"license", "interface", "example"}, "Comma-separated list of stages to run (callgraph is excluded by default: it loads each module's full transitive dependency closure into SSA, and running that over a whole walk in --workers concurrent subprocesses is what exhausts memory — one module on its own is a bounded cost, see 'kanonarion callgraph --help'; pass explicitly when needed)")
	cmd.Flags().BoolVar(&f.force, "force", false, "re-extract even if cached")
	cmd.Flags().IntVar(&f.workers, "workers", 0, "parallel module extraction workers (0 = number of CPUs; each concurrent callgraph subprocess holds its own module's SSA closure, so the run's peak is roughly this many times the largest module's peak — reduce to limit memory use)")
	registerNoProgressFlag(cmd, &f.noProgress)

	cmd.AddCommand(newExtractShowCmd(stdout, stderr))
	cmd.AddCommand(newExtractListCmd(stdout, stderr))

	return cmd
}

func runExtract(ctx context.Context, walkID string, f extractFlags, stdout, stderr io.Writer) error {
	run, err := extractWalk(ctx, walkID, f, stderr)
	if err != nil {
		return err
	}
	return renderExtraction(run, jsonOut, stdout)
}

// renderExtraction writes the run and reports the exit it earns. One exit for
// both formats: the JSON document said partial while the process said success.
func renderExtraction(run domain.ExtractionRun, asJSON bool, stdout io.Writer) error {
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(run); err != nil {
			return fmt.Errorf("failed to encode JSON output: %w", err)
		}
		return extractionExit(run)
	}

	_, _ = fmt.Fprintf(stdout, "Extraction run %s completed with status: %s\n", run.ID, run.OverallStatus)
	_, _ = fmt.Fprintf(stdout, "Modules processed: %d\n", len(run.PerModuleResults))

	printExtractionFailures(stdout, run)

	return extractionExit(run)
}

// extractWalk runs the requested stages and hands back the run it recorded.
// Split from the rendering because a partial run returns no error, so a caller
// that needs its failures must read the record rather than a returned error.
func extractWalk(ctx context.Context, walkID string, f extractFlags, stderr io.Writer) (domain.ExtractionRun, error) {
	logger := buildLogger(logLevel, stderr)

	ctr, cleanup, err := NewContainer(storeRoot, "", f.goBinary, false, activeConfig, logger)
	if err != nil {
		return domain.ExtractionRun{}, fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	// Status preamble must go to stderr so that stdout is a clean data
	// channel — under --json, callers pipe stdout straight into jq and a
	// preamble line breaks parsing.
	_, _ = fmt.Fprintf(stderr, "Starting extraction for walk %s...\n", walkID)
	run, err := ctr.Extract.Execute(ctx, extractapp.ExtractRequest{
		WalkID:   walkID,
		Stages:   f.stages,
		Force:    f.force,
		Workers:  f.workers,
		Progress: newExtractProgressReporter(stderr, f.noProgress, activeConfig, logLevel),
	})
	if err != nil {
		return domain.ExtractionRun{}, fmt.Errorf("extraction execution failed: %w", err)
	}
	return run, nil
}

// extractionExit maps the recorded run status onto the process exit code. A
// partial run is exit 1's definition — completed, known-incomplete — and the
// exit code is the only part of this output a CI step reads. Only Succeeded is
// enumerated as clean, so a status added later cannot default into one.
func extractionExit(run domain.ExtractionRun) error {
	switch run.OverallStatus {
	case domain.ExtractionRunSucceeded:
		return nil
	case domain.ExtractionRunFailed:
		return &exitError{code: ExitFailed, msg: fmt.Sprintf(
			"extraction failed: run %s produced no usable stage", run.ID)}
	case domain.ExtractionRunCancelled:
		return &exitError{code: ExitCancelled, msg: fmt.Sprintf(
			"extraction cancelled: run %s did not reach every module", run.ID)}
	default:
		return &exitError{code: ExitPartial, msg: fmt.Sprintf(
			"extraction %s: %d stage(s) failed; run %s records which modules and stages",
			run.OverallStatus, len(extractionFailures(run)), run.ID)}
	}
}

// extractStageFailure is one module/stage pair an extraction run recorded as
// failed — what "N stages failed" is a count of.
type extractStageFailure struct {
	Module string `json:"module"`
	Stage  string `json:"stage"`
	Error  string `json:"error,omitempty"`
}

// extractionFailures lists the run's failed stages, ordered so two readings of
// one run agree.
func extractionFailures(run domain.ExtractionRun) []extractStageFailure {
	failures := []extractStageFailure{}
	for coord, modResult := range run.PerModuleResults {
		for stageName, stageResult := range modResult.Stages {
			if stageResult.Status == domain.StageFailed {
				failures = append(failures, extractStageFailure{
					Module: coord.String(),
					Stage:  stageName,
					Error:  stageResult.Error,
				})
			}
		}
	}
	slices.SortFunc(failures, func(a, b extractStageFailure) int {
		if a.Module != b.Module {
			return strings.Compare(a.Module, b.Module)
		}
		return strings.Compare(a.Stage, b.Stage)
	})
	return failures
}

// printExtractionFailures prints a breakdown of failed stages when the run is
// partial or failed. It is a no-op when every stage succeeded.
func printExtractionFailures(w io.Writer, run domain.ExtractionRun) {
	failures := extractionFailures(run)
	if len(failures) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "Failed stages (%d):\n", len(failures))
	for _, f := range failures {
		if f.Error != "" {
			_, _ = fmt.Fprintf(w, "  %s  stage=%s  error=%s\n", f.Module, f.Stage, f.Error)
		} else {
			_, _ = fmt.Fprintf(w, "  %s  stage=%s\n", f.Module, f.Stage)
		}
	}
}

func newExtractShowCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:         "show [run-id]",
		Annotations: map[string]string{annotationStoreIntent: StoreIntentRead},
		Short:       "Show details of an extraction run",
		Args:        cobra.ExactArgs(1),
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
	var limit, offset int
	cmd := &cobra.Command{
		Use:         "list",
		Annotations: map[string]string{annotationStoreIntent: StoreIntentRead},
		Short:       "List extraction runs",
		RunE: func(cmd *cobra.Command, _ []string) error {
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runExtractList(cmd.Context(), limit, offset, ctr.QueryExtract, stdout, stderr)
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 20, "maximum number of runs to return (0 = unlimited)")
	cmd.Flags().IntVar(&offset, "offset", 0, "skip this many runs")
	return cmd
}

// runExtractList renders the extraction-run listing. Split from the command so
// the row cap it applies is exercisable without a live store.
func runExtractList(ctx context.Context, limit, offset int, uc QueryExtractionUseCase, stdout, stderr io.Writer) error {
	// One row more than will be printed, so the extra row answers whether the
	// limit bit without a second read.
	runs, err := uc.ListExtractionRuns(ctx, ports.ExtractionRunFilter{Limit: truncationFetchLimit(limit), Offset: offset})
	if err != nil {
		return fmt.Errorf("failed to list extraction runs: %w", err)
	}
	runs, truncated := truncateList(runs, limit)
	trunc := listTruncation{limit: limit, subject: "extraction runs", truncated: truncated, offset: offset}

	if jsonOut {
		type runJSON struct {
			ID          string                     `json:"id"`
			WalkID      string                     `json:"walk_id"`
			Status      domain.ExtractionRunStatus `json:"status"`
			ModuleCount int                        `json:"module_count"`
			StartedAt   time.Time                  `json:"started_at"`
			CompletedAt time.Time                  `json:"completed_at"`
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
		if len(out) == 0 {
			scope, serr := extractListZeroScope(ctx, offset, uc)
			if serr != nil {
				return serr
			}
			return writeListZeroNoticeJSON(stderr, scope)
		}
		return writeListTruncationJSON(stderr, trunc)
	}

	// The notice replaces the header rather than following it: a table with no
	// rows under it is not a short answer, it is no answer at all.
	if len(runs) == 0 {
		scope, serr := extractListZeroScope(ctx, offset, uc)
		if serr != nil {
			return serr
		}
		return writeListZeroNotice(stdout, scope)
	}

	_, _ = fmt.Fprintf(stdout, "%-26s %-26s %-10s %-12s %s\n", "RUN ID", "WALK ID", "STATUS", "MODULES", "STARTED")
	for _, r := range runs {
		_, _ = fmt.Fprintf(stdout, "%-26s %-26s %-10s %-12d %s\n",
			r.ID, r.WalkID, r.OverallStatus, r.ModuleCount, r.StartedAt.Format(time.RFC3339))
	}
	return writeListTruncationNotice(stdout, trunc)
}

// extractListZeroScope lifts the paging and re-asks the store, so a zero says
// whether the store holds no extraction run at all or the page starts past the
// last one. This listing takes no filter, so the filter cause cannot arise and
// the notice never claims it did. Reached only when the listing came back empty.
func extractListZeroScope(ctx context.Context, offset int, uc QueryExtractionUseCase) (listZeroScope, error) {
	all, err := uc.ListExtractionRuns(ctx, ports.ExtractionRunFilter{})
	if err != nil {
		return listZeroScope{}, fmt.Errorf("counting extraction runs for the zero-result notice: %w", err)
	}
	scope := listZeroScope{
		subject:    "extraction run",
		considered: len(all),
		produce:    "kanonarion extract <walk-id>",
		listAll:    "kanonarion extract list",
	}
	// An empty corpus is not something a page can start past, so a zero over it
	// keeps the store-empty statement and its produce-a-record remedy.
	if len(all) > 0 && offset > 0 && offset >= len(all) {
		scope.pagedPast = fmt.Sprintf("--offset %d starts past the last one", offset)
	}
	return scope, nil
}
