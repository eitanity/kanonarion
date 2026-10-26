package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"code.eitanity.com/kanonarion/internal/coordinate"

	"github.com/spf13/cobra"

	cgapp "code.eitanity.com/kanonarion/internal/callgraph/application"
	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	capapp "code.eitanity.com/kanonarion/internal/capability/application"
	capdomain "code.eitanity.com/kanonarion/internal/capability/domain"
)

// capabilityTestRootFlagName is the opt-in that puts test declarations back in
// the capability root set. The polarity is the reverse of the edge queries'
// --exclude-tests because the questions differ: an edge query enumerates the
// graph, while this command answers what a dependency can do inside the build
// that consumes it, and a consumer compiles none of its _test.go files.
const capabilityTestRootFlagName = "include-tests"

// capabilityFlags are the capability command's flags.
type capabilityFlags struct {
	against        string
	includeTests   bool
	showSuppressed bool
	target         buildTargetFlags
	walkID         string
}

func newCapabilityCmd(stdout, stderr io.Writer) *cobra.Command {
	var f capabilityFlags

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

The call graph read is the one extracted under this host's build frame, or the
frame --target, --goos/--goarch or --tinygo declares, or the frame of the walk
--walk-id names. The report's frame line says which.

It reads stored call graphs; run
'kanonarion fetch <module>@<version> && kanonarion callgraph <module>@<version>' first.`,
		Example: `  kanonarion capability github.com/spf13/cobra@v1.8.1
  kanonarion capability github.com/spf13/cobra@v1.8.1 --json
  kanonarion capability github.com/spf13/cobra@v1.8.1 --show-suppressed
  kanonarion capability github.com/spf13/cobra@v1.8.1 --include-tests
  kanonarion capability github.com/spf13/cobra@v1.8.1 --target wasip1/wasm
  kanonarion capability github.com/spf13/cobra@v1.8.0 --against github.com/spf13/cobra@v1.8.1`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			return runCapabilityCmd(cmd.Context(), cmd.Name(), args[0], f, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&f.against, "against", "", "second <module>@<version> to diff the capability set against")
	cmd.Flags().BoolVar(&f.includeTests, capabilityTestRootFlagName, false,
		"also root the traversal at test functions, which a consumer of the module does not compile")
	cmd.Flags().BoolVar(&f.showSuppressed, capabilityShowSuppressedFlagName, false,
		"also print what text hides by default: RUNTIME_INTERNAL and unexported plumbing rows (JSON always carries them)")
	registerBuildTargetFlags(cmd, &f.target)
	cmd.Flags().StringVar(&f.walkID, "walk-id", "", "read the call graph extracted under the build frame this walk resolved")
	return cmd
}

// runCapabilityCmd settles the frame the read selects, opens the store, and
// answers. The callers rule applies: a declaration beside --walk-id is refused
// by name, since the walk's own frame is the read frame.
func runCapabilityCmd(ctx context.Context, name, arg string, f capabilityFlags, stdout, stderr io.Writer) error {
	if terr := resolveReadTarget(ctx, f.target, name, f.walkID == "", ""); terr != nil {
		return terr
	}
	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer releaseStore(cleanup)
	if f.walkID != "" {
		// No later read names the walk, so a missing one is refused here.
		if _, werr := ctr.QueryWalks.GetWalk(ctx, f.walkID); werr != nil {
			return fmt.Errorf("loading walk %q: %w", f.walkID, werr)
		}
		if aerr := adoptNamedWalkFrame(ctx, ctr.QueryWalks, f.walkID); aerr != nil {
			return aerr
		}
	}

	served := &servedCallGraphs{source: ctr.QueryCallGraph}
	uc := capapp.NewAnalyseCapabilitiesUseCase(served)
	scope := capabilityRootScope(f.includeTests)
	out := capabilityOutput{json: jsonOut, showSuppressed: f.showSuppressed, served: served}
	if f.against != "" {
		return runCapabilityDiff(ctx, arg, f.against, uc, ctr.QueryCallGraph, scope, out, stdout)
	}
	return runCapability(ctx, arg, uc, ctr.QueryCallGraph, scope, out, stdout)
}

// servedCallGraphs is the capability source that keeps each record it served,
// so the report can state the frame that record was extracted under.
type servedCallGraphs struct {
	source capapp.CallGraphSource
	recs   map[string]cgdomain.CallGraphRecord
}

func (s *servedCallGraphs) GetCallGraphRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (cgdomain.CallGraphRecord, bool, error) {
	rec, found, err := s.source.GetCallGraphRecord(ctx, coord, pipelineVersion)
	if err == nil && found {
		if s.recs == nil {
			s.recs = map[string]cgdomain.CallGraphRecord{}
		}
		s.recs[coord.String()] = rec
	}
	return rec, found, err //nolint:wrapcheck // a pass-through; the use case wraps what it reads
}

// record is the record served for coord; the zero record when none was, or
// when the report was not read through a servedCallGraphs.
func (s *servedCallGraphs) record(coord coordinate.ModuleCoordinate) cgdomain.CallGraphRecord {
	if s == nil {
		return cgdomain.CallGraphRecord{}
	}
	return s.recs[coord.String()]
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
	// served holds the records the reports were drawn from, for the frame line.
	served *servedCallGraphs
}

func runCapability(ctx context.Context, arg string, uc capabilityAnalyser, generations callGraphGenerationReader, scope cgdomain.RootScope, out capabilityOutput, stdout io.Writer) error {
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
		doc.Frame = toFrameJSON(out.served.record(coord).Frame)
		doc.SetAside = storeSetAside.take().json()
		return encodeJSON(stdout, doc)
	}
	return printCapabilityReport(stdout, coord, report, scope, out.showSuppressed, out.served.record(coord))
}

func runCapabilityDiff(ctx context.Context, fromArg, toArg string, uc capabilityAnalyser, generations callGraphGenerationReader, scope cgdomain.RootScope, out capabilityOutput, stdout io.Writer) error {
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
		doc.From.Frame = toFrameJSON(out.served.record(from).Frame)
		doc.To.Frame = toFrameJSON(out.served.record(to).Frame)
		doc.SetAside = storeSetAside.take().json()
		return encodeJSON(stdout, doc)
	}
	return printCapabilityDiff(stdout, from, to, diff, scope, out.showSuppressed,
		out.served.record(from), out.served.record(to))
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
func capabilityMissingRecord(ctx context.Context, err error, generations callGraphGenerationReader) error {
	missing, ok := errors.AsType[*capapp.NoCallGraphError](err)
	if !ok {
		return nil
	}
	return missingCallGraphRefusal(ctx, missing.Coord, generations)
}
