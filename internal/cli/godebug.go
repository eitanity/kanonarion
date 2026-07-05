package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	gddomain "github.com/eitanity/kanonarion/internal/godebug/domain"
	"github.com/spf13/cobra"
)

// godebugResult is the machine-readable shape of one classified //go:debug
// setting. An agentic consumer must be able to reason about whether a
// runtime-behaviour knob is approved, so the taxonomy tier and policy verdict
// are first-class fields.
type godebugResult struct {
	Setting        string `json:"setting"`
	Value          string `json:"value,omitempty"`
	Source         string `json:"source"`
	Line           int    `json:"line"`
	Module         string `json:"module,omitempty"`
	Applied        bool   `json:"applied"`
	Classification string `json:"classification"`
	PolicyOutcome  string `json:"policy_outcome"`
	PolicyBlocking bool   `json:"policy_blocking"`
}

// godebugSection is the top-level `godebug` JSON section. It is deterministic:
// settings are domain-sorted and no wall-clock field is emitted, so identical
// inputs yield identical bytes. taxonomy_version records which
// risk-taxonomy revision classified the scan.
type godebugSection struct {
	SchemaVersion   string          `json:"schema_version"`
	Ecosystem       string          `json:"ecosystem"`
	PipelineVersion string          `json:"pipeline_version"`
	TaxonomyVersion string          `json:"taxonomy_version"`
	Project         string          `json:"project"`
	ContentHash     string          `json:"content_hash"`
	Settings        []godebugResult `json:"settings"`
}

// toGoDebugSection projects a domain record into the JSON section. Shared by
// the `godebug` command and the `inspect` aggregate.
func toGoDebugSection(rec gddomain.Record) godebugSection {
	out := godebugSection{
		SchemaVersion:   rec.SchemaVersion,
		Ecosystem:       rec.Ecosystem,
		PipelineVersion: rec.PipelineVersion,
		TaxonomyVersion: rec.TaxonomyVersion,
		Project:         rec.ProjectModulePath,
		ContentHash:     rec.ContentHash,
		Settings:        make([]godebugResult, 0, len(rec.Settings)),
	}
	for _, s := range rec.Settings {
		out.Settings = append(out.Settings, godebugResult{
			Setting:        s.Name,
			Value:          s.Value,
			Source:         s.Source,
			Line:           s.Line,
			Module:         s.Module,
			Applied:        s.Applied,
			Classification: s.Tier.String(),
			PolicyOutcome:  s.PolicyOutcome,
			PolicyBlocking: s.PolicyBlocking,
		})
	}
	return out
}

func newGoDebugCmd(stdout, stderr io.Writer) *cobra.Command {
	var gomodPath string
	cmd := &cobra.Command{
		Use:   "godebug",
		Short: "Detect, classify and policy-check GODEBUG / //go:debug settings",
		Long: `godebug enumerates every //go:debug setting baked into the project's
main package (and any vendored dependency main packages), classifies each
against a versioned risk taxonomy (red / amber / green), evaluates it against
the godebug_policy governance block, and records an audit fact per setting.

//go:debug directives (Go 1.21+) change runtime security behaviour invisibly
to dependency-graph analysis — some disable TLS verification, weaken crypto
defaults, or revert deprecated protocol behaviour. A setting in a dependency
does NOT take effect in the current build: it is recorded "applied": false,
never silently dropped. The default policy flags red (security-weakening)
settings, so this command exits non-zero (20) when an applied setting's
policy outcome is "warn".`,
		Example: `  kanonarion godebug
  kanonarion godebug --gomod ./go.mod --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGoDebug(cmd.Context(), gomodPath, stdout, stderr)
		},
	}
	cmd.Flags().StringVar(&gomodPath, "gomod", "", "path to go.mod file (default: ./go.mod)")
	return cmd
}

func runGoDebug(ctx context.Context, gomodFlag string, stdout, stderr io.Writer) error {
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

	rec, err := ctr.ExtractGoDebug.Extract(ctx, gomodPath, activeConfig.GoDebugPolicy)
	if err != nil {
		return fmt.Errorf("scanning godebug settings: %w", err)
	}
	section := toGoDebugSection(rec)

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(section); err != nil {
			return fmt.Errorf("encoding godebug: %w", err)
		}
		return godebugBlockingErr(section)
	}
	if err := printGoDebugTable(stdout, section); err != nil {
		return err
	}
	return godebugBlockingErr(section)
}

func printGoDebugTable(stdout io.Writer, s godebugSection) error {
	if len(s.Settings) == 0 {
		if _, err := fmt.Fprintf(stdout, "no //go:debug settings in %s\n", s.Project); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "SETTING\tVALUE\tSOURCE:LINE\tMODULE\tAPPLIED\tCLASS\tPOLICY"); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	for _, d := range s.Settings {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s:%d\t%s\t%t\t%s\t%s\n",
			d.Setting, d.Value, d.Source, d.Line, d.Module, d.Applied,
			d.Classification, d.PolicyOutcome); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flushing output: %w", err)
	}
	return nil
}

// godebugBlockingErr returns a non-zero ExitConfig error when any *applied*
// setting resolves to a blocking ("warn") policy outcome — e.g. a red-tier
// setting in the main package under the default policy. Not-applied settings
// are surfaced but never gate the build (they do not affect the binary).
func godebugBlockingErr(s godebugSection) error {
	var blocked []string
	for _, d := range s.Settings {
		if d.PolicyBlocking {
			blocked = append(blocked, fmt.Sprintf("%s=%s (%s)", d.Setting, d.Value, d.Classification))
		}
	}
	if len(blocked) == 0 {
		return nil
	}
	return &exitError{code: ExitConfig, msg: fmt.Sprintf(
		"godebug policy: %d setting(s) violate policy: %v", len(blocked), blocked)}
}
