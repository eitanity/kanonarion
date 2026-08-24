package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/spf13/cobra"
)

type cgFlags struct {
	goBinary     string
	force        bool
	fromModcache string
	fromWalk     string
}

func newCallGraphCmd(stdout, stderr io.Writer) *cobra.Command {
	var f cgFlags
	var localShim bool

	cmd := &cobra.Command{
		Use:   "callgraph <module>@<version>",
		Short: "Extract and summarise the call graph of a Go module",
		Example: `  kanonarion callgraph github.com/spf13/cobra@v1.8.1
  kanonarion callgraph github.com/spf13/cobra@v1.8.1 --json
  kanonarion callgraph github.com/spf13/cobra@v1.8.1 --force
  kanonarion callgraph github.com/Masterminds/sprig@v2.22.0+incompatible --from-walk 01KZ3WD9JM9X4S5TWR31HF64H7`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if localShim {
				// Direct, never execute: 'callgraph' analyses fetched
				// (consumer-mode) modules; the local working tree is
				// author-mode and has its own command.
				return errors.New(
					"the 'callgraph' command analyses fetched modules; to analyse the " +
						"local working tree use the 'local' command:\n  kanonarion local <dir>")
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
	_ = cmd.Flags().MarkHidden("local")
	registerFromModcacheFlag(cmd, &f.fromModcache)

	return cmd
}

func runCallGraphExtract(ctx context.Context, arg string, f cgFlags, stdout, stderr io.Writer) error {
	// A module fetched via --from-modcache is stored under a "modcache:zip:"
	// blob handle, not a content-addressed one; the call-graph extractor needs
	// the same modcache-aware blob store that fetched it, or blob resolution
	// fails. Resolved on the path that consumes it, so the flag is answered for
	// where the work happens rather than in the constructor.
	if f.fromModcache != "" {
		gomodPath, gerr := resolveGoModPath("")
		if gerr != nil {
			return fmt.Errorf("--from-modcache: locating go.mod: %w", gerr)
		}
		if merr := resolveModcacheMode(f.fromModcache, gomodPath); merr != nil {
			return merr
		}
	}

	logger := buildLogger(logLevel, stderr)

	coord, err := parseCoordinate(arg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", arg, err)
	}

	ctr, cleanup, err := NewContainer(storeRoot, "", f.goBinary, false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	inputs, err := analysisInputsForWalk(ctx, ctr.QueryWalks, f.fromWalk)
	if err != nil {
		return err
	}
	if f.fromWalk == "" {
		inputs = discoveredBuildList(ctx, ctr.QueryWalks, coord, stderr)
	}

	result, err := ctr.ExtractCallGraph.Execute(ctx, cgapp.ExtractRequest{
		Coordinate: coord,
		Force:      f.force,
		Inputs:     inputs,
	})
	if err != nil {
		return fmt.Errorf("extracting call graph: %w", err)
	}

	if err := printCallGraphSummary(result.Record, result.FromCache || result.Reused, jsonOut, "", stdout); err != nil {
		return err
	}
	if result.Reused {
		// Said plainly, because the two are different facts and the distinction is
		// the one a reader chasing a failing module needs: the analysis DID run,
		// and it came back saying what the ledger already said.
		if _, err := fmt.Fprintln(stderr,
			"re-measured and found identical to the generation already recorded; no new generation was written"); err != nil {
			return fmt.Errorf("writing re-measurement note: %w", err)
		}
	}
	return callGraphExtractionExit(result.Record)
}

// callGraphExtractionExit maps an extraction outcome onto the process exit code.
//
// Three outcomes, three codes: a complete graph, one scoped by its
// FailedPackages line, and no graph at all. Partial took the complete graph's 0
// for being an answer — which it is, and 1 is the code for an answer that is
// known-incomplete. A Partial carrying no nodes stays at 2 with LoadFailed.
func callGraphExtractionExit(r cgdomain.CallGraphRecord) error {
	msg := fmt.Sprintf("%s: %s", r.Coordinate, r.OverallStatus.String())
	if r.FailureDetail != "" {
		msg += " — " + r.FailureDetail
	}
	switch r.OverallStatus {
	// ExcludedByConfig shares Extracted's 0 by decision, not by omission: the
	// operator listed this module in callgraph.exclude, so the absent graph is
	// the outcome they asked for rather than one this run failed to produce.
	case cgdomain.CallGraphStatusExtracted, cgdomain.CallGraphStatusExcludedByConfig:
		return nil
	case cgdomain.CallGraphStatusPartial:
		if r.NodeCount == 0 {
			return &exitError{code: ExitFailed, msg: msg}
		}
		return &exitError{code: ExitPartial, msg: msg}
	case cgdomain.CallGraphStatusCancelled:
		return &exitError{code: ExitCancelled, msg: msg}
	default:
		// LoadFailed, OutOfMemory, ExtractionFailed, Unknown, and any status added
		// later: no graph exists, so nothing downstream can consume this
		// coordinate. Only the two answers above are enumerated as clean.
		return &exitError{code: ExitFailed, msg: msg}
	}
}

// dir is the working tree a local run was pointed at, so a printed remedy names
// the directory the reader actually ran in rather than a placeholder; it is empty
// where the caller has none.
func printCallGraphSummary(r cgdomain.CallGraphRecord, fromCache bool, jsonOut bool, dir string, stdout io.Writer) error {
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(toCallGraphJSON(r)); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}

	cached := ""
	if fromCache {
		cached = " (cached)"
	}
	if _, err := fmt.Fprintf(stdout, "%s@%s: %s — %d nodes, %d edges [%s]%s\n",
		r.Coordinate.Path(), r.Coordinate.Version(),
		r.OverallStatus.String(),
		r.NodeCount, r.EdgeCount,
		string(r.Algorithm),
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
	return writeIncompletenessRemedy(stdout, r, dir)
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
func writeIncompletenessRemedy(stdout io.Writer, r cgdomain.CallGraphRecord, dir string) error {
	if !cgdomain.RecordIsIncomplete(r) {
		return nil
	}
	if _, err := fmt.Fprintln(stdout, cgdomain.IncompleteGraphRemedy(r.Coordinate, r.FailureCause, r.FailureDetail, dir)); err != nil {
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

// discoveredBuildList answers a module that needs a build list nobody named.
//
// A module published before Go modules ships no go.mod, and a synthesised one is
// only honest for a module that imports nothing outside the standard library.
// The versions that make the rest analysable are a property of a BUILD, and this
// store holds several — but until now the operator had to know that, know which
// walk resolved the module, and pass --from-walk. Nobody asking "what does this
// module call" knows any of that, so the default path recorded an empty graph
// while the store held everything needed to fill it.
//
// It runs BEFORE the extraction rather than as a retry after one failed, and
// that ordering is the whole of the design. A retry would analyse the module
// twice and persist both outcomes, and two failure generations differing only in
// which build list they were denied are a divergence: the composed read then
// refuses the coordinate outright, which is a worse answer than the empty graph
// it replaced. One request, one analysis, one generation.
//
// A search that finds nothing is not an error and says nothing. The extraction
// that follows fails exactly as it would have anyway, and the failure it records
// already names the imports it could not pin — the more useful of the two
// messages. --from-walk always wins: an operator who scoped the analysis to a
// build keeps that scope.
func discoveredBuildList(
	ctx context.Context,
	walks QueryWalksUseCase,
	coord coordinate.ModuleCoordinate,
	stderr io.Writer,
) cgdomain.AnalysisInputs {
	walkID, err := findWalkContaining(ctx, walks, coord)
	if err != nil {
		return cgdomain.AnalysisInputs{}
	}
	inputs, err := analysisInputsForWalk(ctx, walks, walkID)
	if err != nil || !inputs.HasBuildList() {
		return cgdomain.AnalysisInputs{}
	}
	// The choice is announced, never enforced: an unwritable stderr does not make
	// a discovered build list the wrong input to analyse with.
	_, _ = fmt.Fprintf(stderr, "no build list was named; a pre-modules module will be pinned to walk %s, "+
		"which resolved %d version(s) and includes this module\n", walkID, len(inputs.BuildList))
	return inputs
}
