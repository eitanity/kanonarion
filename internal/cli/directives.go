package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	dirdomain "github.com/eitanity/kanonarion/internal/directive/domain"
	"github.com/spf13/cobra"
)

// directiveResult is the machine-readable shape of one classified directive.
// An agentic consumer must be able to reason about whether a replacement is
// approved, so classification and policy verdict are first-class fields.
type directiveResult struct {
	Kind               string `json:"kind"`
	Source             string `json:"source"`
	Line               int    `json:"line"`
	OldPath            string `json:"old_path"`
	OldVersion         string `json:"old_version,omitempty"`
	NewPath            string `json:"new_path,omitempty"`
	NewVersion         string `json:"new_version,omitempty"`
	LocalPath          string `json:"local_path,omitempty"`
	Applied            bool   `json:"applied"`
	Classification     string `json:"classification"`
	ReachabilityTarget string `json:"reachability_target,omitempty"`
	PolicyOutcome      string `json:"policy_outcome"`
	PolicyBlocking     bool   `json:"policy_blocking"`
}

// directivesSection is the top-level `directives` JSON section. It is
// deterministic: directives are domain-sorted and no wall-clock field is
// emitted, so identical inputs yield identical bytes.
type directivesSection struct {
	SchemaVersion   string            `json:"schema_version"`
	Ecosystem       string            `json:"ecosystem"`
	PipelineVersion string            `json:"pipeline_version"`
	Project         string            `json:"project"`
	ContentHash     string            `json:"content_hash"`
	Directives      []directiveResult `json:"directives"`
}

// toDirectivesSection projects a domain record into the JSON section. Shared
// by the `directives` command and the `inspect` aggregate.
func toDirectivesSection(rec dirdomain.Record) directivesSection {
	out := directivesSection{
		SchemaVersion:   rec.SchemaVersion,
		Ecosystem:       rec.Ecosystem,
		PipelineVersion: rec.PipelineVersion,
		Project:         rec.ProjectModulePath,
		ContentHash:     rec.ContentHash,
		Directives:      make([]directiveResult, 0, len(rec.Directives)),
	}
	for _, d := range rec.Directives {
		out.Directives = append(out.Directives, directiveResult{
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
		})
	}
	return out
}

func newDirectivesCmd(stdout, stderr io.Writer) *cobra.Command {
	var gomodPath string
	cmd := &cobra.Command{
		Use:   "directives",
		Short: "Detect, classify and policy-check go.mod/go.work replace & exclude directives",
		Long: `directives enumerates every replace and exclude directive in the
project's go.mod (and adjacent go.work), classifies each by security risk,
evaluates it against the directive_policy governance block, and records an
audit fact per directive.

replace and exclude change dependency resolution WITHOUT changing the import
graph, so they are invisible to anyone reading import statements. A local-path
replace has no remote checksum to verify; an exclude can force resolution off
a CVE-patched version. The default policy flags local-path replace, so this
command exits non-zero (20) when a directive's policy outcome is "warn".`,
		Example: `  kanonarion directives
  kanonarion directives --gomod ./go.mod --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDirectives(cmd.Context(), gomodPath, stdout, stderr)
		},
	}
	cmd.Flags().StringVar(&gomodPath, "gomod", "", "path to go.mod file (default: ./go.mod)")
	cmd.AddCommand(
		newDirectivesListCmd(stdout, stderr),
		newDirectivesShowCmd(stdout, stderr),
		newDirectivesDiffCmd(stdout, stderr),
	)
	return cmd
}

func runDirectives(ctx context.Context, gomodFlag string, stdout, stderr io.Writer) error {
	gomodPath, err := resolveGoModPath(gomodFlag)
	if err != nil {
		return err
	}
	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	rec, err := ctr.ExtractDirectives.Extract(ctx, gomodPath, activeConfig.DirectivePolicy)
	if err != nil {
		return fmt.Errorf("scanning directives: %w", err)
	}
	section := toDirectivesSection(rec)

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(section); err != nil {
			return fmt.Errorf("encoding directives: %w", err)
		}
		return directivesBlockingErr(section)
	}
	if err := printDirectivesTable(stdout, section); err != nil {
		return err
	}
	return directivesBlockingErr(section)
}

func printDirectivesTable(stdout io.Writer, s directivesSection) error {
	if len(s.Directives) == 0 {
		if _, err := fmt.Fprintf(stdout, "no replace/exclude directives in %s\n", s.Project); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "KIND\tSOURCE:LINE\tOLD\tTARGET\tAPPLIED\tCLASS\tPOLICY"); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	for _, d := range s.Directives {
		target := d.NewPath
		if d.LocalPath != "" {
			target = d.LocalPath
		}
		if d.NewVersion != "" {
			target += "@" + d.NewVersion
		}
		old := d.OldPath
		if d.OldVersion != "" {
			old += "@" + d.OldVersion
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s:%d\t%s\t%s\t%t\t%s\t%s\n",
			d.Kind, d.Source, d.Line, old, target, d.Applied,
			d.Classification, d.PolicyOutcome); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flushing output: %w", err)
	}
	return nil
}

// directivesBlockingErr returns a non-zero ExitConfig error when any directive
// resolves to a blocking ("warn") policy outcome — e.g. a local-path replace
// under the default policy.
func directivesBlockingErr(s directivesSection) error {
	var blocked []string
	for _, d := range s.Directives {
		if d.PolicyBlocking {
			blocked = append(blocked, fmt.Sprintf("%s %s (%s)", d.Kind, d.OldPath, d.Classification))
		}
	}
	if len(blocked) == 0 {
		return nil
	}
	return &exitError{code: ExitConfig, msg: fmt.Sprintf(
		"directive policy: %d directive(s) violate policy: %v", len(blocked), blocked)}
}
