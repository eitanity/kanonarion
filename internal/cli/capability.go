package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	capapp "github.com/eitanity/kanonarion/internal/capability/application"
	capdomain "github.com/eitanity/kanonarion/internal/capability/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func newCapabilityCmd(stdout, stderr io.Writer) *cobra.Command {
	var against string

	cmd := &cobra.Command{
		Use:   "capability <module>@<version>",
		Short: "Report the sensitive capabilities a module's reachable code can use",
		Long: `capability derives, from a module's stored call graph, which sensitive
capabilities (NETWORK, FILES, EXEC, REFLECT, UNSAFE_POINTER, …) its reachable
code can exercise. Each capability is reported with an example witnessing path
and that path's weakest edge confidence, so a capability confirmed by a resolved
direct call is distinguishable from one reached only through interface fanout.

With --against, it diffs the capability set of two versions (update-validity):
did the bump add NETWORK/EXEC/UNSAFE? The diff is only valid when both versions
were analysed at equal completeness.

It reads stored call graphs; run 'kanonarion callgraph <module>@<version>' first.`,
		Example: `  kanonarion capability github.com/spf13/cobra@v1.8.1
  kanonarion capability github.com/spf13/cobra@v1.8.1 --json
  kanonarion capability github.com/spf13/cobra@v1.8.0 --against github.com/spf13/cobra@v1.8.1`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()

			uc := capapp.NewAnalyseCapabilitiesUseCase(ctr.QueryCallGraph)
			if against != "" {
				return runCapabilityDiff(cmd.Context(), args[0], against, uc, jsonOut, stdout)
			}
			return runCapability(cmd.Context(), args[0], uc, jsonOut, stdout)
		},
	}

	cmd.Flags().StringVar(&against, "against", "", "second <module>@<version> to diff the capability set against")
	return cmd
}

// capabilityAnalyser is the behaviour runCapability/runCapabilityDiff need,
// extracted so the commands are unit-testable with a fake.
type capabilityAnalyser interface {
	Analyse(ctx context.Context, coord fetchdomain.ModuleCoordinate, pipelineVersion string) (capdomain.CapabilityReport, error)
	Diff(ctx context.Context, from, to fetchdomain.ModuleCoordinate, pipelineVersion string) (capdomain.CapabilityReport, capdomain.CapabilityReport, capdomain.CapabilityDiff, error)
}

func runCapability(ctx context.Context, arg string, uc capabilityAnalyser, jsonOut bool, stdout io.Writer) error {
	coord, err := parseCoordinate(arg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", arg, err)
	}
	report, err := uc.Analyse(ctx, coord, cgapp.PipelineVersion)
	if err != nil {
		return fmt.Errorf("analysing capabilities: %w", err)
	}
	if jsonOut {
		return encodeJSON(stdout, capabilityReportToJSON(coord, report))
	}
	return printCapabilityReport(stdout, coord, report)
}

func runCapabilityDiff(ctx context.Context, fromArg, toArg string, uc capabilityAnalyser, jsonOut bool, stdout io.Writer) error {
	from, err := parseCoordinate(fromArg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", fromArg, err)
	}
	to, err := parseCoordinate(toArg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", toArg, err)
	}
	fromReport, toReport, diff, err := uc.Diff(ctx, from, to, cgapp.PipelineVersion)
	if err != nil {
		return fmt.Errorf("diffing capabilities: %w", err)
	}
	if jsonOut {
		return encodeJSON(stdout, capabilityDiffToJSON(from, to, fromReport, toReport, diff))
	}
	return printCapabilityDiff(stdout, from, to, diff)
}

func encodeJSON(stdout io.Writer, v any) error {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return nil
}

// -- JSON shapes --

type capabilityFindingJSON struct {
	Capability        string   `json:"capability"`
	WeakestConfidence string   `json:"weakest_confidence"`
	SinkPackage       string   `json:"sink_package"`
	SinkSymbol        string   `json:"sink_symbol"`
	Path              []string `json:"path"`
}

type capabilityReportJSON struct {
	Module       string                  `json:"module"`
	Version      string                  `json:"version"`
	Partial      bool                    `json:"partial"`
	Caveat       string                  `json:"caveat,omitempty"`
	Capabilities []string                `json:"capabilities"`
	Findings     []capabilityFindingJSON `json:"findings"`
}

type capabilityDiffJSON struct {
	From     capabilityReportJSON `json:"from"`
	To       capabilityReportJSON `json:"to"`
	ParityOK bool                 `json:"parity_ok"`
	Caveat   string               `json:"caveat,omitempty"`
	Added    []string             `json:"added"`
	Removed  []string             `json:"removed"`
	Common   []string             `json:"common"`
}

func capabilityReportToJSON(coord fetchdomain.ModuleCoordinate, r capdomain.CapabilityReport) capabilityReportJSON {
	findings := make([]capabilityFindingJSON, 0, len(r.Findings))
	for _, f := range r.Findings {
		findings = append(findings, capabilityFindingJSON{
			Capability:        string(f.Capability),
			WeakestConfidence: string(f.WeakestConfidence),
			SinkPackage:       f.SinkPackage,
			SinkSymbol:        f.SinkSymbol,
			Path:              f.Path,
		})
	}
	return capabilityReportJSON{
		Module:       coord.Path,
		Version:      coord.Version,
		Partial:      r.Partial,
		Caveat:       r.Caveat,
		Capabilities: capsToStrings(r.Capabilities()),
		Findings:     findings,
	}
}

func capabilityDiffToJSON(from, to fetchdomain.ModuleCoordinate, fromReport, toReport capdomain.CapabilityReport, diff capdomain.CapabilityDiff) capabilityDiffJSON {
	return capabilityDiffJSON{
		From:     capabilityReportToJSON(from, fromReport),
		To:       capabilityReportToJSON(to, toReport),
		ParityOK: diff.ParityOK,
		Caveat:   diff.Caveat,
		Added:    capsToStrings(diff.Added),
		Removed:  capsToStrings(diff.Removed),
		Common:   capsToStrings(diff.Common),
	}
}

func capsToStrings(caps []capdomain.Capability) []string {
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		out = append(out, string(c))
	}
	return out
}

// -- text rendering --

func printCapabilityReport(stdout io.Writer, coord fetchdomain.ModuleCoordinate, r capdomain.CapabilityReport) error {
	if _, err := fmt.Fprintf(stdout, "%s@%s capabilities:\n", coord.Path, coord.Version); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}
	if r.Partial {
		if _, err := fmt.Fprintf(stdout, "  ⚠ %s\n", r.Caveat); err != nil {
			return fmt.Errorf("writing caveat: %w", err)
		}
	}
	if len(r.Findings) == 0 {
		if _, err := fmt.Fprintln(stdout, "  (no sensitive capabilities witnessed)"); err != nil {
			return fmt.Errorf("writing empty result: %w", err)
		}
		return nil
	}
	for _, f := range r.Findings {
		if _, err := fmt.Fprintf(stdout, "  %-20s [%s]  via %s.%s\n",
			string(f.Capability), string(f.WeakestConfidence), f.SinkPackage, f.SinkSymbol); err != nil {
			return fmt.Errorf("writing finding: %w", err)
		}
		if _, err := fmt.Fprintf(stdout, "    path: %s\n", strings.Join(f.Path, " → ")); err != nil {
			return fmt.Errorf("writing path: %w", err)
		}
	}
	return nil
}

func printCapabilityDiff(stdout io.Writer, from, to fetchdomain.ModuleCoordinate, diff capdomain.CapabilityDiff) error {
	if _, err := fmt.Fprintf(stdout, "capability diff %s@%s → %s@%s:\n",
		from.Path, from.Version, to.Path, to.Version); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}
	if !diff.ParityOK {
		if _, err := fmt.Fprintf(stdout, "  ⚠ %s\n", diff.Caveat); err != nil {
			return fmt.Errorf("writing caveat: %w", err)
		}
	}
	if len(diff.Added) == 0 && len(diff.Removed) == 0 {
		if _, err := fmt.Fprintln(stdout, "  no capability change"); err != nil {
			return fmt.Errorf("writing no-change: %w", err)
		}
		return nil
	}
	for _, c := range diff.Added {
		if _, err := fmt.Fprintf(stdout, "  + %s\n", string(c)); err != nil {
			return fmt.Errorf("writing added: %w", err)
		}
	}
	for _, c := range diff.Removed {
		if _, err := fmt.Fprintf(stdout, "  - %s\n", string(c)); err != nil {
			return fmt.Errorf("writing removed: %w", err)
		}
	}
	return nil
}
