package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/spf13/cobra"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
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
	var includeTests, showSuppressed bool

	cmd := &cobra.Command{
		Use: "capability <module>@<version>",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "Report the sensitive capabilities a module's reachable code can use",
		Long: `capability derives, from a module's stored call graph, what its reachable code
can do. Every callee is labelled on three axes:

  capability   what the callee does: EXEC_PROCESS, NET_DIAL, FS_READ, ENV_READ, …
               (Act tier), NET_INSPECT, FS_STREAM, PATH_PURE, … (Context tier),
               RUNTIME_INTERNAL (suppressed)
  reach        how deliberately: DIRECT_CALL (an exported function by name),
               RUNTIME_PLUMBING (unexported), PKG_LINKAGE (an initialiser),
               UNANALYZED (an assembly or //go:linkname body)
  caller kind  the kind of the function making the call: INIT, TEST_INIT, TEST,
               MAIN, EXPORTED_API, INTERNAL

The report gives one finding per capability, with an example witnessing path and
its weakest edge confidence, then "sensitive calls": the exported sensitive
functions this module calls over at least one Direct edge, each with the kinds of
caller that reach it. It names any function that both collects (ENV_READ,
FS_READ) and egresses (NET_DIAL, NET_TRANSFER), and any initialiser whose Direct
edges reach both. The module's own assembly or linkname functions are listed as
unanalysed.

RUNTIME_INTERNAL findings and unexported plumbing rows are hidden in text unless
--show-suppressed is given; a count says how many. A capability whose only
witnesses are plumbing is shown, marked plumbing-only. JSON carries everything.

A path that reaches another package's init, or an external callee carrying a
body-level fact, is reported below the capability set instead of in it: it shows
the package is linked, or classifies the callee, rather than naming something
this module does.

Roots are every function the module owns, exported or not. Test declarations do
not root the traversal: a consumer compiles none of the module's _test.go files.
--include-tests widens the roots to them.

With --against, it diffs two versions row by row: an owned function's call to a
labelled callee, or its own unsafe.Pointer use. Added and removed rows, sensitive
calls, co-location facts and unanalysed bodies are listed separately. The diff is
only valid when both versions were analysed at equal completeness.

It reads stored call graphs; run
'kanonarion fetch <module>@<version> && kanonarion callgraph <module>@<version>' first.`,
		Example: `  kanonarion capability github.com/spf13/cobra@v1.8.1
  kanonarion capability github.com/spf13/cobra@v1.8.1 --json
  kanonarion capability github.com/spf13/cobra@v1.8.1 --show-suppressed
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
			defer releaseStore(cleanup)

			uc := capapp.NewAnalyseCapabilitiesUseCase(ctr.QueryCallGraph)
			scope := capabilityRootScope(includeTests)
			if against != "" {
				return runCapabilityDiff(cmd.Context(), args[0], against, uc, ctr.QueryCallGraph, scope,
					capabilityOutput{json: jsonOut, showSuppressed: showSuppressed}, stdout)
			}
			return runCapability(cmd.Context(), args[0], uc, ctr.QueryCallGraph, scope,
				capabilityOutput{json: jsonOut, showSuppressed: showSuppressed}, stdout)
		},
	}

	cmd.Flags().StringVar(&against, "against", "", "second <module>@<version> to diff the capability set against")
	cmd.Flags().BoolVar(&includeTests, capabilityTestRootFlagName, false,
		"also root the traversal at test functions, which a consumer of the module does not compile")
	cmd.Flags().BoolVar(&showSuppressed, capabilityShowSuppressedFlagName, false,
		"also print what text hides by default: RUNTIME_INTERNAL and unexported plumbing rows (JSON always carries them)")
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
// report and not only the narrowed one: the default is narrow, so silence would
// leave a reader assuming the whole test surface was searched. The test axis is
// the only one that narrows it — every owned node roots the traversal either way.
func capabilityRootScopeLine(scope cgdomain.RootScope) string {
	if scope == cgdomain.RootScopeWithTests {
		return "roots: all of this module's own code, test functions included (--" + capabilityTestRootFlagName + " was given)"
	}
	return "roots: all of this module's own code; test functions excluded (widen with --" + capabilityTestRootFlagName + ")"
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

// capabilityOutput is how a report is rendered.
type capabilityOutput struct {
	json           bool
	showSuppressed bool
}

func runCapability(ctx context.Context, arg string, uc capabilityAnalyser, generations cgports.CallGraphCoordinateLister, scope cgdomain.RootScope, out capabilityOutput, stdout io.Writer) error {
	coord, err := parseCoordinate(arg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", arg, err)
	}
	report, err := uc.Analyse(ctx, coord, cgapp.PipelineVersion, scope)
	if err != nil {
		if missing := capabilityMissingRecord(ctx, err, generations); missing != nil {
			return missing
		}
		return fmt.Errorf("analysing capabilities: %w", err)
	}
	if out.json {
		doc := capabilityReportToJSON(coord, report, scope)
		doc.SetAside = storeSetAside.take().json()
		return encodeJSON(stdout, doc)
	}
	return printCapabilityReport(stdout, coord, report, scope, out.showSuppressed)
}

func runCapabilityDiff(ctx context.Context, fromArg, toArg string, uc capabilityAnalyser, generations cgports.CallGraphCoordinateLister, scope cgdomain.RootScope, out capabilityOutput, stdout io.Writer) error {
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
		if missing := capabilityMissingRecord(ctx, err, generations); missing != nil {
			return missing
		}
		return fmt.Errorf("diffing capabilities: %w", err)
	}
	if out.json {
		doc := capabilityDiffToJSON(from, to, fromReport, toReport, diff, scope)
		doc.SetAside = storeSetAside.take().json()
		return encodeJSON(stdout, doc)
	}
	return printCapabilityDiff(stdout, from, to, diff, scope, out.showSuppressed)
}

// capabilityMissingRecord turns "this coordinate has no call graph" into the
// refusal a caller can act on, and returns nil for anything else.
//
// ExitNotFound, not the invocation-error code: the request was well formed and
// the store was empty, which is the distinction a script branches on. The
// remedy is built from the coordinate that actually missed — a diff reads two —
// so what is printed is an invocation this CLI's own parser accepts.
//
// It is callgraph-show's own refusal, not a restatement of it: both refuse for
// the absence of the same record, so the store is asked what it holds for the
// coordinate instead of an absence being asserted over it. Saying the record
// does not exist where the store holds two superseded generations of it is a
// claim the store itself contradicts, and it leaves a reader with no reason to
// suspect the pipeline bump that is the actual answer.
func capabilityMissingRecord(ctx context.Context, err error, generations cgports.CallGraphCoordinateLister) error {
	missing, ok := errors.AsType[*capapp.NoCallGraphError](err)
	if !ok {
		return nil
	}
	return missingCallGraphRefusal(ctx, missing.Coord, generations)
}
