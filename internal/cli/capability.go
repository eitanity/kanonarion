package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/spf13/cobra"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	capapp "github.com/eitanity/kanonarion/internal/capability/application"
	capdomain "github.com/eitanity/kanonarion/internal/capability/domain"
)

// capabilityTestRootFlagName is the opt-in that puts test declarations back in
// the capability root set. The polarity is the reverse of the edge queries'
// --exclude-tests because the questions differ: an edge query enumerates the
// graph, while this command answers what a dependency can do inside the build
// that consumes it, and a consumer compiles none of its _test.go files.
const capabilityTestRootFlagName = "include-tests"

func newCapabilityCmd(stdout, stderr io.Writer) *cobra.Command {
	var against string
	var includeTests bool

	cmd := &cobra.Command{
		Use: "capability <module>@<version>",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "Report the sensitive capabilities a module's reachable code can use",
		Long: `capability derives, from a module's stored call graph, which sensitive
capabilities (NETWORK, FILES, EXEC, REFLECT, UNSAFE_POINTER, …) its reachable
code can exercise. Each capability is reported with an example witnessing path
and that path's weakest edge confidence, so a capability confirmed by a resolved
direct call is distinguishable from one reached only through interface fanout.

Roots are the module's exported API and its package init functions. Test
declarations do not root the traversal: a consumer compiles none of the
module's _test.go files, so a sink only its test suite reaches is not in the
consuming build. --include-tests widens the roots to them.

With --against, it diffs the capability set of two versions (update-validity):
did the bump add NETWORK/EXEC/UNSAFE? The diff is only valid when both versions
were analysed at equal completeness.

It reads stored call graphs; run 'kanonarion callgraph <module>@<version>' first.`,
		Example: `  kanonarion capability github.com/spf13/cobra@v1.8.1
  kanonarion capability github.com/spf13/cobra@v1.8.1 --json
  kanonarion capability github.com/spf13/cobra@v1.8.1 --include-tests
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
			scope := capabilityRootScope(includeTests)
			if against != "" {
				return runCapabilityDiff(cmd.Context(), args[0], against, uc, scope, jsonOut, stdout)
			}
			return runCapability(cmd.Context(), args[0], uc, scope, jsonOut, stdout)
		},
	}

	cmd.Flags().StringVar(&against, "against", "", "second <module>@<version> to diff the capability set against")
	cmd.Flags().BoolVar(&includeTests, capabilityTestRootFlagName, false,
		"also root the traversal at test functions, which a consumer of the module does not compile")
	return cmd
}

// capabilityRootScope maps the flag to the shared root scope.
func capabilityRootScope(includeTests bool) cgdomain.RootScope {
	if includeTests {
		return cgdomain.RootScopeWithTests
	}
	return cgdomain.RootScopeProduction
}

// capabilityRootScopeLine states which root set produced the answer, on every
// report rather than only on the narrowed one: the default here is the narrow
// set, so silence would leave a reader assuming the graph's whole test surface
// was searched.
func capabilityRootScopeLine(scope cgdomain.RootScope) string {
	if scope == cgdomain.RootScopeWithTests {
		return "roots: exported API, package init and test functions (--" + capabilityTestRootFlagName + " was given)"
	}
	return "roots: exported API and package init; test functions excluded (widen with --" + capabilityTestRootFlagName + ")"
}

// capabilityRootScopeJSON is the machine-readable half of the same disclosure.
func capabilityRootScopeJSON(scope cgdomain.RootScope) string {
	if scope == cgdomain.RootScopeWithTests {
		return "included"
	}
	return "excluded"
}

// capabilityAnalyser is the behaviour runCapability/runCapabilityDiff need,
// extracted so the commands are unit-testable with a fake.
type capabilityAnalyser interface {
	Analyse(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string, scope cgdomain.RootScope) (capdomain.CapabilityReport, error)
	Diff(ctx context.Context, from, to coordinate.ModuleCoordinate, pipelineVersion string, scope cgdomain.RootScope) (capdomain.CapabilityReport, capdomain.CapabilityReport, capdomain.CapabilityDiff, error)
}

func runCapability(ctx context.Context, arg string, uc capabilityAnalyser, scope cgdomain.RootScope, jsonOut bool, stdout io.Writer) error {
	coord, err := parseCoordinate(arg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", arg, err)
	}
	report, err := uc.Analyse(ctx, coord, cgapp.PipelineVersion, scope)
	if err != nil {
		return fmt.Errorf("analysing capabilities: %w", err)
	}
	if jsonOut {
		return encodeJSON(stdout, capabilityReportToJSON(coord, report, scope))
	}
	return printCapabilityReport(stdout, coord, report, scope)
}

func runCapabilityDiff(ctx context.Context, fromArg, toArg string, uc capabilityAnalyser, scope cgdomain.RootScope, jsonOut bool, stdout io.Writer) error {
	from, err := parseCoordinate(fromArg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", fromArg, err)
	}
	to, err := parseCoordinate(toArg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", toArg, err)
	}
	fromReport, toReport, diff, err := uc.Diff(ctx, from, to, cgapp.PipelineVersion, scope)
	if err != nil {
		return fmt.Errorf("diffing capabilities: %w", err)
	}
	if jsonOut {
		return encodeJSON(stdout, capabilityDiffToJSON(from, to, fromReport, toReport, diff, scope))
	}
	return printCapabilityDiff(stdout, from, to, diff, scope)
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
	Module  string `json:"module"`
	Version string `json:"version"`
	// TestRoots is "excluded" or "included": which root set produced the
	// answer. It is always populated, so a consumer cannot mistake an unstated
	// axis for a missing one.
	TestRoots    string                  `json:"test_roots"`
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

func capabilityReportToJSON(coord coordinate.ModuleCoordinate, r capdomain.CapabilityReport, scope cgdomain.RootScope) capabilityReportJSON {
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
		Module:       coord.Path(),
		Version:      coord.Version(),
		TestRoots:    capabilityRootScopeJSON(scope),
		Partial:      r.Partial,
		Caveat:       r.Caveat,
		Capabilities: capsToStrings(r.Capabilities()),
		Findings:     findings,
	}
}

func capabilityDiffToJSON(from, to coordinate.ModuleCoordinate, fromReport, toReport capdomain.CapabilityReport, diff capdomain.CapabilityDiff, scope cgdomain.RootScope) capabilityDiffJSON {
	return capabilityDiffJSON{
		From:     capabilityReportToJSON(from, fromReport, scope),
		To:       capabilityReportToJSON(to, toReport, scope),
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

func printCapabilityReport(stdout io.Writer, coord coordinate.ModuleCoordinate, r capdomain.CapabilityReport, scope cgdomain.RootScope) error {
	if _, err := fmt.Fprintf(stdout, "%s@%s capabilities:\n", coord.Path(), coord.Version()); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}
	if _, err := fmt.Fprintf(stdout, "  %s\n", capabilityRootScopeLine(scope)); err != nil {
		return fmt.Errorf("writing root scope: %w", err)
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

func printCapabilityDiff(stdout io.Writer, from, to coordinate.ModuleCoordinate, diff capdomain.CapabilityDiff, scope cgdomain.RootScope) error {
	if _, err := fmt.Fprintf(stdout, "capability diff %s@%s → %s@%s:\n",
		from.Path(), from.Version(), to.Path(), to.Version()); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}
	if _, err := fmt.Fprintf(stdout, "  %s\n", capabilityRootScopeLine(scope)); err != nil {
		return fmt.Errorf("writing root scope: %w", err)
	}
	if !diff.ParityOK {
		if _, err := fmt.Fprintf(stdout, "  ⚠ %s\n", diff.Caveat); err != nil {
			return fmt.Errorf("writing caveat: %w", err)
		}
	}
	if len(diff.Added) == 0 && len(diff.Removed) == 0 {
		// The set held in common is stated with the zero, because "no capability
		// change" over two empty sets and over two identical non-empty sets are
		// different findings that otherwise print the same line.
		line := "  no capability change: neither version witnesses any capability"
		if len(diff.Common) > 0 {
			line = fmt.Sprintf("  no capability change: both versions witness the same %s (%s)",
				countOf(len(diff.Common), "capabilities"), strings.Join(capsToStrings(diff.Common), ", "))
		}
		if _, err := fmt.Fprintln(stdout, line); err != nil {
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
