package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	dirapp "github.com/eitanity/kanonarion/internal/directive/application"
	dirdomain "github.com/eitanity/kanonarion/internal/directive/domain"
	"github.com/spf13/cobra"
)

// directiveDeltaJSON is the JSON-friendly projection of a directive that
// appears in a diff (Added / Removed). It reuses directiveResult so the diff
// JSON shape is consistent with `directives` output.
type directiveDeltaJSON struct {
	Directive directiveResult `json:"directive"`
}

type reclassificationJSON struct {
	Before directiveResult `json:"before"`
	After  directiveResult `json:"after"`
}

type directivesDiffJSON struct {
	Project      string                 `json:"project"`
	ScanA        string                 `json:"scan_a"`
	ScanB        string                 `json:"scan_b"`
	Added        []directiveDeltaJSON   `json:"added"`
	Removed      []directiveDeltaJSON   `json:"removed"`
	Reclassified []reclassificationJSON `json:"reclassified"`
}

func directiveToResult(d dirdomain.Directive) directiveResult {
	return directiveResult{
		Kind:               string(d.Kind),
		Source:             d.Source,
		Line:               d.Line,
		OldPath:            d.OldPath,
		OldVersion:         d.OldVersion,
		NewPath:            d.NewPath,
		NewVersion:         d.NewVersion,
		LocalPath:          d.LocalPath,
		Applied:            d.Applied,
		Classification:     d.Class.String(),
		ReachabilityTarget: d.ReachabilityTarget,
		PolicyOutcome:      d.PolicyOutcome,
		PolicyBlocking:     d.PolicyBlocking,
	}
}

func toDirectivesDiffJSON(diff dirdomain.DirectiveDiff) directivesDiffJSON {
	out := directivesDiffJSON{
		Project:      diff.ScanB.ProjectModulePath,
		ScanA:        diff.ScanA.ID,
		ScanB:        diff.ScanB.ID,
		Added:        make([]directiveDeltaJSON, 0, len(diff.Added)),
		Removed:      make([]directiveDeltaJSON, 0, len(diff.Removed)),
		Reclassified: make([]reclassificationJSON, 0, len(diff.Reclassified)),
	}
	for _, d := range diff.Added {
		out.Added = append(out.Added, directiveDeltaJSON{Directive: directiveToResult(d)})
	}
	for _, d := range diff.Removed {
		out.Removed = append(out.Removed, directiveDeltaJSON{Directive: directiveToResult(d)})
	}
	for _, r := range diff.Reclassified {
		out.Reclassified = append(out.Reclassified, reclassificationJSON{
			Before: directiveToResult(r.Before),
			After:  directiveToResult(r.After),
		})
	}
	return out
}

func newDirectivesListCmd(stdout, stderr io.Writer) *cobra.Command {
	var (
		project   string
		gomodPath string
		limit     int
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List recent directive scans for a project",
		Long: `list prints the directive scan history for a project, newest first.

The project module path is inferred from ./go.mod (or --gomod) when --project
is omitted, so running 'kanonarion directives list' inside a Go module's root
works without any flags.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDirectivesList(cmd.Context(), project, gomodPath, limit, stdout, stderr)
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "project module path (default: inferred from go.mod)")
	cmd.Flags().StringVar(&gomodPath, "gomod", "", "path to go.mod used to infer --project (default: ./go.mod)")
	cmd.Flags().IntVar(&limit, "limit", 20, "maximum number of scans to list (0 = unlimited)")
	return cmd
}

func runDirectivesList(ctx context.Context, project, gomodPath string, limit int, stdout, stderr io.Writer) error {
	if project == "" {
		resolved, err := resolveGoModPath(gomodPath)
		if err != nil {
			return fmt.Errorf("inferring --project: %w (pass --project explicitly to override)", err)
		}
		mod, err := projectModulePathFromGoMod(resolved)
		if err != nil {
			return fmt.Errorf("inferring --project: %w (pass --project explicitly to override)", err)
		}
		project = mod
	}

	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	return directivesListWith(ctx, ctr, project, limit, stdout)
}

// directivesListWith holds the directives-list logic over an injected
// Container: it lists scans for a project, reports an empty set explicitly, and
// renders JSON or a table. Split from runDirectivesList so listing and render
// selection are testable without a live store.
func directivesListWith(ctx context.Context, ctr *Container, project string, limit int, stdout io.Writer) error {
	scans, err := ctr.QueryDirectives.ListScans(ctx, project, limit)
	if err != nil {
		return fmt.Errorf("listing directive scans: %w", err)
	}
	if jsonOut {
		type scanJSON struct {
			ID              string    `json:"id"`
			Project         string    `json:"project"`
			CompletedAt     time.Time `json:"completed_at"`
			DirectiveCount  int       `json:"directive_count"`
			ContentHash     string    `json:"content_hash"`
			PipelineVersion string    `json:"pipeline_version"`
		}
		out := make([]scanJSON, len(scans))
		for i, s := range scans {
			out[i] = scanJSON{
				ID:              s.ID,
				Project:         s.ProjectModulePath,
				CompletedAt:     s.CompletedAt,
				DirectiveCount:  len(s.Directives),
				ContentHash:     s.ContentHash,
				PipelineVersion: s.PipelineVersion,
			}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return fmt.Errorf("encoding scans: %w", err)
		}
		return nil
	}

	if len(scans) == 0 {
		_, _ = fmt.Fprintf(stdout, "no directive scans for %s\n", project)
		return nil
	}

	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "SCAN ID\tCOMPLETED\tDIRECTIVES\tCONTENT HASH"); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	for _, s := range scans {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n",
			s.ID, s.CompletedAt.UTC().Format(time.RFC3339), len(s.Directives), s.ContentHash); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flushing output: %w", err)
	}
	return nil
}

func newDirectivesShowCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <scan-id>",
		Short: "Show a specific directive scan by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDirectivesShow(cmd.Context(), args[0], stdout, stderr)
		},
	}
	return cmd
}

func runDirectivesShow(ctx context.Context, scanID string, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	return directivesShowWith(ctx, ctr, scanID, stdout)
}

// directivesShowWith holds the directives-show logic over an injected
// Container: a missing scan is surfaced as ExitNotFound (never an empty
// success), otherwise the scan is rendered. Split from runDirectivesShow so the
// not-found contract is testable without a live store.
func directivesShowWith(ctx context.Context, ctr *Container, scanID string, stdout io.Writer) error {
	rec, found, err := ctr.QueryDirectives.GetScan(ctx, scanID)
	if err != nil {
		return fmt.Errorf("loading directive scan: %w", err)
	}
	if !found {
		return &exitError{code: ExitNotFound, msg: fmt.Sprintf("directive scan not found: %s", scanID)}
	}
	section := toDirectivesSection(rec)

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(section); err != nil {
			return fmt.Errorf("encoding scan: %w", err)
		}
		return nil
	}
	_, _ = fmt.Fprintf(stdout, "Scan:       %s\n", rec.ID)
	_, _ = fmt.Fprintf(stdout, "Project:    %s\n", rec.ProjectModulePath)
	_, _ = fmt.Fprintf(stdout, "Completed:  %s\n", rec.CompletedAt.UTC().Format(time.RFC3339))
	_, _ = fmt.Fprintf(stdout, "Directives: %d\n\n", len(rec.Directives))
	return printDirectivesTable(stdout, section)
}

func newDirectivesDiffCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff <scan-id-a> <scan-id-b>",
		Short: "Compare two directive scans of the same project",
		Long: `diff compares two directive scans of the same project and reports
directives added, removed, or reclassified between the two scans. Mirrors
vuln-scan-diff. scan-id-a is the baseline (older); scan-id-b is the newer
scan.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDirectivesDiff(cmd.Context(), args[0], args[1], stdout, stderr)
		},
	}
	return cmd
}

func runDirectivesDiff(ctx context.Context, scanA, scanB string, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	return directivesDiffWith(ctx, ctr, scanA, scanB, stdout)
}

// directivesDiffWith holds the directives-diff logic over an injected
// Container: a missing scan on either side is surfaced as ExitNotFound, then
// changes are rendered (JSON or text). Split from runDirectivesDiff so the
// not-found contract and render selection are testable without a live store.
func directivesDiffWith(ctx context.Context, ctr *Container, scanA, scanB string, stdout io.Writer) error {
	diff, err := ctr.DiffDirectives.Diff(ctx, scanA, scanB)
	if err != nil {
		var notFound *dirapp.ErrScanNotFound
		if errors.As(err, &notFound) {
			return &exitError{code: ExitNotFound, msg: notFound.Error()}
		}
		return fmt.Errorf("diffing directive scans: %w", err)
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(toDirectivesDiffJSON(diff)); err != nil {
			return fmt.Errorf("encoding diff: %w", err)
		}
		return nil
	}

	_, _ = fmt.Fprintf(stdout, "Diff:    %s → %s\n", diff.ScanA.ID, diff.ScanB.ID)
	_, _ = fmt.Fprintf(stdout, "Project: %s\n\n", diff.ScanB.ProjectModulePath)
	if !diff.HasChanges() {
		_, _ = fmt.Fprintln(stdout, "No directive changes.")
		return nil
	}

	if len(diff.Added) > 0 {
		_, _ = fmt.Fprintf(stdout, "ADDED (%d):\n", len(diff.Added))
		for _, d := range diff.Added {
			_, _ = fmt.Fprintf(stdout, "  + %s %s  (%s, policy=%s)\n",
				d.Kind, directiveLeftHandSide(d), d.Class.String(), d.PolicyOutcome)
		}
		_, _ = fmt.Fprintln(stdout)
	}
	if len(diff.Removed) > 0 {
		_, _ = fmt.Fprintf(stdout, "REMOVED (%d):\n", len(diff.Removed))
		for _, d := range diff.Removed {
			_, _ = fmt.Fprintf(stdout, "  - %s %s  (was %s)\n",
				d.Kind, directiveLeftHandSide(d), d.Class.String())
		}
		_, _ = fmt.Fprintln(stdout)
	}
	if len(diff.Reclassified) > 0 {
		_, _ = fmt.Fprintf(stdout, "RECLASSIFIED (%d):\n", len(diff.Reclassified))
		for _, r := range diff.Reclassified {
			_, _ = fmt.Fprintf(stdout, "  ~ %s %s  %s/%s → %s/%s\n",
				r.After.Kind, directiveLeftHandSide(r.After),
				r.Before.Class.String(), r.Before.PolicyOutcome,
				r.After.Class.String(), r.After.PolicyOutcome)
		}
	}
	return nil
}

func directiveLeftHandSide(d dirdomain.Directive) string {
	if d.OldVersion != "" {
		return d.OldPath + "@" + d.OldVersion
	}
	return d.OldPath
}
