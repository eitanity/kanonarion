package cli

import (
	"code.eitanity.com/kanonarion/internal/composition/cgchild"
	"code.eitanity.com/kanonarion/internal/exitcode"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/gotoolchain"
	"github.com/spf13/cobra"
)

type cgFlags struct {
	goBinary     string
	force        bool
	fromModcache string
	fromWalk     string
	noProgress   bool
	// narrate is the parent's instruction to report phase transitions whatever
	// this store's preferences say. A spawned child's stderr is a pipe to the
	// process bounding it, not a terminal, and those lines are how that process
	// tells a working analysis from a stalled one: leaving them to an operator
	// preference would let a config file disable the stall detector.
	narrate bool
	target  buildTargetFlags
}

func newCallGraphCmd(stdout, stderr io.Writer) *cobra.Command {
	var f cgFlags
	var localShim bool

	cmd := &cobra.Command{
		Use: "callgraph <module>@<version>",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentCreate,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "Extract and summarise the call graph of a Go module",
		Long: `Extract and summarise the call graph of a Go module.

Cost: one run loads the module's full transitive dependency closure into SSA in
a single process. Across this project's own dependency set that measured
0.23-1.22 GB per module on a 32-core, 61 GiB machine, the heaviest of them
taking 5.96 s and 1.22 GB. Running the same analysis over a whole walk is a
different budget: see 'kanonarion extract --help'.`,
		Example: `  kanonarion callgraph github.com/spf13/cobra@v1.8.1
  kanonarion callgraph github.com/spf13/cobra@v1.8.1 --json
  kanonarion callgraph github.com/spf13/cobra@v1.8.1 --force
  kanonarion callgraph golang.org/x/text@v0.3.7 --target wasip1/wasm
  kanonarion callgraph github.com/Masterminds/sprig@v2.22.0+incompatible --from-walk 01KZ3WD9JM9X4S5TWR31HF64H7`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if localShim {
				// Direct, never execute: 'callgraph' analyses fetched
				// (consumer-mode) modules; the local working tree is
				// author-mode and has its own command.
				// The tree meant is the one the reader is standing in — that is what
				// they asked for — so the command names it rather than a placeholder
				// they would have to fill in.
				return errors.New(
					"the 'callgraph' command analyses fetched modules; the local working " +
						"tree is analysed by 'kanonarion local .' run from that tree")
			}
			if len(args) == 0 {
				return usageErr(cmd)
			}
			if len(args) > 1 {
				return fmt.Errorf("accepts 1 arg, received %d", len(args))
			}
			return runCallGraphExtract(cmd.Context(), args[0], f, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&f.goBinary, "go-binary", "", "path to 'go' binary if not in PATH")
	cmd.Flags().BoolVar(&f.force, "force", false, "re-extract even if cached")
	cmd.Flags().StringVar(&f.fromWalk, "from-walk", "",
		"pin a pre-modules module's require directives to the versions this walk resolved")
	cmd.Flags().BoolVar(&localShim, "local", false, "")
	hideFlag(cmd, "local")
	cmd.Flags().BoolVar(&f.narrate, "narrate-progress", false, "")
	hideFlag(cmd, "narrate-progress")
	registerNoProgressFlag(cmd, &f.noProgress)
	registerFromModcacheFlag(cmd, &f.fromModcache)
	registerBuildTargetFlags(cmd, &f.target)

	return cmd
}

func runCallGraphExtract(ctx context.Context, arg string, f cgFlags, stdout, stderr io.Writer) error {
	// A module fetched via --from-modcache is stored under a "modcache:zip:"
	// blob handle, not a content-addressed one; the call-graph extractor needs
	// the same modcache-aware blob store that fetched it, or blob resolution
	// fails. Resolved on the path that consumes it, so the flag is answered for
	// where the work happens rather than in the constructor.
	if err := resolveCallGraphModcache(ctx, f); err != nil {
		return err
	}

	logger := buildLogger(logLevel, stderr)
	// The analysis narrates the phase it is in, so a run that takes minutes says
	// so rather than looking wedged — and so a parent bounding this process can
	// tell the difference. See cgports.ProgressPrefix.
	if f.narrate || (!f.noProgress && activeConfig.Preferences.Progress) {
		callgraphNarration = stderr
	}

	// The frame is settled before the container is built: the analyser and the
	// read frame are wired from it there.
	coord, err := resolveCallGraphFrame(ctx, arg, f)
	if err != nil {
		return err
	}

	ctr, cleanup, err := NewContainer(storeRoot, "", f.goBinary, false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer releaseStore(cleanup)

	// The extraction is the one the call-graph child runs: the frame from
	// --from-walk, the build list, the analysis.
	out, err := cgchild.Extract(ctx, ctr.callGraphChildDeps(stderr), cgchild.Request{
		Coordinate: coord, Force: f.force, FromWalk: f.fromWalk, Declared: f.target.declared(),
	})
	if err != nil {
		return asExitError(err)
	}
	result := out.Result
	var run callGraphRunJSON
	if out.Ambiguity != nil {
		run.BuildListRefusal = ambiguityRefusal(out.Ambiguity).document(callGraphBuildFlag)
	}

	if err := printCallGraphSummary(ctx, result.Record, result.FromCache || result.Reused, jsonOut, "", stdout, run); err != nil {
		return err
	}
	if err := cgchild.NoteReuse(stderr, result); err != nil {
		return err //nolint:wrapcheck // the note's own error names what failed
	}
	return callGraphExtractionExit(result.Record)
}

// resolveCallGraphFrame parses the coordinate and settles the frame this
// extraction runs under. The standard library's graph is read from a toolchain's
// own GOROOT, which a TinyGo frame replaces, so the two are refused together.
func resolveCallGraphFrame(ctx context.Context, arg string, f cgFlags) (coordinate.ModuleCoordinate, error) {
	coord, err := parseCoordinate(arg)
	if err != nil {
		return coord, fmt.Errorf("invalid coordinate %q: %w", arg, err)
	}
	if coord.IsStdlib() && f.target.tinygo != "" {
		return coord, &exitError{code: ExitConfig, msg: fmt.Sprintf(
			"--tinygo applies to a module, not to %s: the standard library's graph is read from a Go toolchain's own GOROOT, "+
				"which a TinyGo frame replaces; --target selects a platform for it", coord)}
	}
	return coord, resolveBuildTarget(ctx, f.target, f.goBinary, "")
}

// resolveCallGraphModcache resolves --from-modcache against the project's
// go.mod, so the extractor reads the store that fetched the module.
func resolveCallGraphModcache(ctx context.Context, f cgFlags) error {
	if f.fromModcache != "" {
		gomodPath, gerr := resolveGoModPath("")
		if gerr != nil {
			return fmt.Errorf("--from-modcache: locating go.mod: %w", gerr)
		}
		if merr := resolveModcacheMode(ctx, f.fromModcache, gomodPath); merr != nil {
			return merr
		}
	}
	return nil
}

// callGraphExtractionExit maps an extraction outcome onto the process exit
// code, as the call-graph child does.
func callGraphExtractionExit(r cgdomain.CallGraphRecord) error {
	return asExitError(cgchild.RecordExit(r))
}

// asExitError is err as this package's exit carrier when it is the shared one.
func asExitError(err error) error {
	if ee, ok := err.(*exitcode.Error); ok { //nolint:errorlint // only the carrier itself is converted; a wrapped one keeps its chain
		return &exitError{code: ee.Code, msg: ee.Msg}
	}
	return err
}

// dir is the working tree a local run was pointed at, so a printed remedy names
// the directory the reader actually ran in rather than a placeholder; it is empty
// where the caller has none.
//
// run is what this invocation states about the record — the build it refused to
// pick, where the answer came from — and it reaches the document only here,
// because stderr, where the same facts are said in words, is not a channel a
// --json consumer reads.
func printCallGraphSummary(
	ctx context.Context, r cgdomain.CallGraphRecord, fromCache bool, jsonOut bool, dir string, stdout io.Writer, run callGraphRunJSON,
) error {
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		doc := toCallGraphJSON(r)
		doc.callGraphRunJSON = run
		doc.FrameExcludes = frameExcludes.take()
		// No nodes and no edges. These commands report what the RUN did — the
		// one fact no later read can recover — and the graph belongs to the
		// record, read with 'callgraph-show --limit-nodes 0 --limit-edges 0
		// --json'. Every scalar stays at the key it had. Nil and not empty, so
		// this is never read as a graph that measured nothing.
		doc.Nodes, doc.Edges = nil, nil
		doc.SetAside = storeSetAside.take().json()
		if err := enc.Encode(doc); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}

	cached := ""
	if fromCache {
		cached = " (cached)"
	}
	if _, err := fmt.Fprintf(stdout, "%s@%s: %s — %d nodes, %d edges [%s]%s%s\n",
		r.Coordinate.Path(), r.Coordinate.Version(),
		r.OverallStatus.String(),
		r.NodeCount, r.EdgeCount,
		string(r.Algorithm),
		summaryFrame(r),
		cached,
	); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	if r.FailureDetail != "" {
		if _, err := fmt.Fprintf(stdout, "  failure: %s\n", r.FailureDetail); err != nil {
			return fmt.Errorf("writing failure detail: %w", err)
		}
	}
	if err := writeFailedPackages(stdout, r); err != nil {
		return err
	}
	if err := writeExclusionInfo(stdout, r); err != nil {
		return err
	}
	return writeIncompletenessRemedy(ctx, stdout, r, dir)
}

// writeIncompletenessRemedy prints, in text mode, what to do about a graph that
// came back incomplete.
//
// The run that produced the record is where the remedy is most useful and was
// the one place not stating it: the failed-package list above says what is
// missing and the failure detail says what the loader reported, and a reader was
// left to work out from that prose whether the fault was in the source or in
// their module cache. The record has already classified it, so the remedy is
// printed from the classification rather than re-derived by the reader.
func writeIncompletenessRemedy(ctx context.Context, stdout io.Writer, r cgdomain.CallGraphRecord, dir string) error {
	// A failure the analyser limit caused is owed its remedy too: no graph is
	// still not a fault in the source.
	_, limited := gotoolchain.ReadAnalyserLimit(r.FailureDetail)
	if !cgdomain.RecordIsIncomplete(r) && (!limited || !cgdomain.RecordIsFailure(r)) {
		return nil
	}
	if _, err := fmt.Fprintln(stdout, incompleteGraphRemedy(ctx, r.Coordinate, r.FailureCause, r.FailureDetail, dir)); err != nil {
		return fmt.Errorf("writing incompleteness remedy: %w", err)
	}
	return nil
}

// writeFailedPackages lists the packages that failed to typecheck (Partial
// graphs only). It scopes the graph's incompleteness to exact packages so a
// reader never infers completeness from the node/edge totals on the line above.
func writeFailedPackages(stdout io.Writer, r cgdomain.CallGraphRecord) error {
	if len(r.FailedPackages) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(stdout, "  failed packages (%d): %s\n",
		len(r.FailedPackages), strings.Join(r.FailedPackages, ", ")); err != nil {
		return fmt.Errorf("writing failed packages: %w", err)
	}
	return nil
}

// writeExclusionInfo prints the exclusion reason (when the module was skipped)
// and the callgraph.exclude policy that was active when the record was
// computed. No output when no exclusion policy was in force.
func writeExclusionInfo(stdout io.Writer, r cgdomain.CallGraphRecord) error {
	if r.ExclusionReason != "" {
		if _, err := fmt.Fprintf(stdout, "  excluded: %s\n", r.ExclusionReason); err != nil {
			return fmt.Errorf("writing exclusion reason: %w", err)
		}
	}
	if len(r.ExclusionList) > 0 {
		if _, err := fmt.Fprintf(stdout, "  exclusion list (active at extraction): %s\n",
			strings.Join(r.ExclusionList, ", ")); err != nil {
			return fmt.Errorf("writing exclusion list: %w", err)
		}
	}
	return nil
}

// discoveredBuildList is the call-graph child's build-list discovery under
// this invocation's frame, its ambiguity rendered as the refusal document.
func discoveredBuildList(
	ctx context.Context,
	walks QueryWalksUseCase,
	coord coordinate.ModuleCoordinate,
	stderr io.Writer,
) (cgdomain.AnalysisInputs, *buildListRefusalJSON) {
	inputs, amb := cgchild.DiscoverBuildList(ctx, walks, coord, invocationFrame(), stderr)
	if amb != nil {
		return inputs, ambiguityRefusal(amb).document(callGraphBuildFlag)
	}
	return inputs, nil
}

// callGraphBuildFlag names the build a coordinate question is about. Named once
// so the remedy a reader is shown and the flag a consumer retries with cannot
// drift apart.
const callGraphBuildFlag = "--from-walk"
