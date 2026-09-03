package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/spf13/cobra"
)

// testScopeFlagName is the opt-in that drops the test surface from an edge
// query. Including tests is the default because the correctness risk runs one
// way: a test caller the graph hides is a false negative dressed as a
// measurement, while one the reader did not want is visible and discountable.
const testScopeFlagName = "exclude-tests"

// registerEdgeScopeFlag adds --exclude-tests to an edge query command.
func registerEdgeScopeFlag(cmd *cobra.Command, excludeTests *bool) {
	cmd.Flags().BoolVar(excludeTests, testScopeFlagName, false,
		"omit callers and callees declared in _test.go files and external test packages")
}

// edgeScopeLine states what an edge query measured when the reader narrowed it,
// reusing the clause the implementers query already prints rather than adding a
// second phrasing for the same narrowing.
//
// It is printed on a NON-EMPTY answer, which is the case that had no way to say
// it: a list of one production caller is otherwise indistinguishable from an
// unnarrowed query that found one caller. An empty answer already carries the
// narrowing on its verdict line, so this is not printed there and the statement
// is never made twice.
//
// kind is a plural noun ("callers", "callees").
func edgeScopeLine(kind string, opts ports.EdgeQueryOptions) string {
	if !opts.ExcludeTests {
		return ""
	}
	return "scope: test " + kind + " omitted (--" + testScopeFlagName + " was given)"
}

// writeEdgeScopeLine prints edgeScopeLine, in text mode only, and writes
// nothing when the query was not narrowed.
func writeEdgeScopeLine(stdout io.Writer, kind string, opts ports.EdgeQueryOptions) error {
	line := edgeScopeLine(kind, opts)
	if line == "" {
		return nil
	}
	if _, err := fmt.Fprintln(stdout, line); err != nil {
		return fmt.Errorf("writing scope: %w", err)
	}
	return nil
}

func newCallersCmd(stdout, stderr io.Writer) *cobra.Command {
	var transitive bool
	var depth int
	var excludeTests bool
	var scopeFlags buildScopeFlags

	cmd := &cobra.Command{
		Use: "callers <symbol-id>",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "Find all callers of a symbol across the call graph store",
		Example: `  kanonarion callers 'github.com/spf13/cobra.(*Command).Execute'
  kanonarion callers 'golang.org/x/text/unicode/norm.(Form).String' --gomod ./go.mod
  kanonarion callers 'golang.org/x/text/unicode/norm.(Form).String' --walk-id abc123`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			scopeFlags.bind(cmd)
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			sc, err := scopeFlags.resolve(cmd.Context(), ctr.QueryWalks)
			if err != nil {
				return err
			}
			opts := ports.EdgeQueryOptions{ExcludeTests: excludeTests, Toolchain: sc.toolchain}
			if transitive {
				return runCallersTransitive(cmd.Context(), args[0], depth, jsonOut, ctr.QueryCallGraph, stdout, sc, opts)
			}
			return runCallers(cmd.Context(), args[0], jsonOut, ctr.QueryCallGraph, stdout, sc, opts)
		},
	}

	cmd.Flags().BoolVar(&transitive, "transitive", false, "traverse the call graph transitively, following all reachable edges")
	cmd.Flags().IntVar(&depth, "depth", 0, "maximum traversal depth for --transitive (0 = unlimited)")
	registerEdgeScopeFlag(cmd, &excludeTests)
	registerBuildScopeFlags(cmd, &scopeFlags)

	return cmd
}

func runCallers(ctx context.Context, symbolID string, jsonOut bool, uc QueryCallGraphUseCase, stdout io.Writer, sc buildScope, opts ports.EdgeQueryOptions) error {
	if err := checkSymbolInScope(ctx, symbolID, uc, sc); err != nil {
		return err
	}
	pr, err := rootPartialStatus(ctx, symbolID, uc, sc)
	if err != nil {
		return err
	}

	refs, err := uc.FindCallers(ctx, symbolID, cgapp.PipelineVersion, sc.modules, opts)
	if err != nil {
		return fmt.Errorf("finding callers: %w", err)
	}

	// A dropped package produces no SSA and therefore no node, so the "not a node
	// in the graph" classification below would blame the symbol for its module's
	// build failure. The dropped-edges notice is the accurate reason, and it is
	// printed instead.
	if len(refs) == 0 && pr.failedPkg == "" {
		if cerr := classifyEmptyEdgeResult(ctx, symbolID, uc, sc); cerr != nil {
			return cerr
		}
	}

	if !jsonOut {
		if err := writeScopeNotice(stdout, sc); err != nil {
			return err
		}
	}
	// The dropped-edges notice supersedes the generic Partial caveat when the
	// queried symbol's OWN package is the one that failed: it says the same thing
	// with the part that bears on this answer, and printing both would state the
	// gap twice in two strengths.
	if !jsonOut {
		switch {
		case pr.failedPkg != "":
			if err := writeDroppedEdgesNotice(stdout, "callers", symbolID, pr); err != nil {
				return err
			}
		case pr.isPartial:
			if err := writePartialNotice(stdout, "callers", symbolID, pr.failedPkgs); err != nil {
				return err
			}
		}
	}
	if !jsonOut {
		if err := writeCompletenessNotice(ctx, symbolID, uc, stdout, sc.modules); err != nil {
			return err
		}
		if err := writeWorktreeNotice(ctx, symbolID, uc, stdout, sc.modules); err != nil {
			return err
		}
	}

	if err := printEdgeRefs("callers", symbolID, refs, jsonOut, stdout); err != nil {
		return err
	}
	if len(refs) > 0 && !jsonOut {
		if err := writeEdgeScopeLine(stdout, "callers", opts); err != nil {
			return err
		}
		return writeForeignEdgeAnswer(ctx, newForeignModuleIndex(uc, sc), stdout, "callers", symbolID, refs, true)
	}
	if len(refs) == 0 && !jsonOut {
		v, verr := negativeCallVerdict(ctx, symbolID, true, uc, sc, opts, pr.failedPkg)
		if verr != nil {
			return verr
		}
		return writeCallVerdict(stdout, "callers", symbolID, v, opts)
	}
	return nil
}

func newCalleesCmd(stdout, stderr io.Writer) *cobra.Command {
	var transitive bool
	var depth int
	var excludeTests bool
	var scopeFlags buildScopeFlags

	cmd := &cobra.Command{
		Use: "callees <symbol-id>",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "Find all callees of a symbol across the call graph store",
		Example: `  kanonarion callees 'github.com/spf13/cobra.(*Command).Execute'
  kanonarion callees 'github.com/spf13/cobra.(*Command).Execute' --gomod ./go.mod`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			scopeFlags.bind(cmd)
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			sc, err := scopeFlags.resolve(cmd.Context(), ctr.QueryWalks)
			if err != nil {
				return err
			}
			opts := ports.EdgeQueryOptions{ExcludeTests: excludeTests, Toolchain: sc.toolchain}
			if transitive {
				return runCalleesTransitive(cmd.Context(), args[0], depth, jsonOut, ctr.QueryCallGraph, stdout, sc, opts)
			}
			return runCallees(cmd.Context(), args[0], jsonOut, ctr.QueryCallGraph, stdout, sc, opts)
		},
	}

	cmd.Flags().BoolVar(&transitive, "transitive", false, "traverse the call graph transitively, following all reachable edges")
	cmd.Flags().IntVar(&depth, "depth", 0, "maximum traversal depth for --transitive (0 = unlimited)")
	registerEdgeScopeFlag(cmd, &excludeTests)
	registerBuildScopeFlags(cmd, &scopeFlags)

	return cmd
}

func runCallees(ctx context.Context, symbolID string, jsonOut bool, uc QueryCallGraphUseCase, stdout io.Writer, sc buildScope, opts ports.EdgeQueryOptions) error {
	if err := checkSymbolInScope(ctx, symbolID, uc, sc); err != nil {
		return err
	}
	pr, err := rootPartialStatus(ctx, symbolID, uc, sc)
	if err != nil {
		return err
	}

	refs, err := uc.FindCallees(ctx, symbolID, cgapp.PipelineVersion, sc.modules, opts)
	if err != nil {
		return fmt.Errorf("finding callees: %w", err)
	}

	// A dropped package produces no SSA and therefore no node, so the "not a node
	// in the graph" classification below would blame the symbol for its module's
	// build failure. The dropped-edges notice is the accurate reason, and it is
	// printed instead.
	if len(refs) == 0 && pr.failedPkg == "" {
		if cerr := classifyEmptyEdgeResult(ctx, symbolID, uc, sc); cerr != nil {
			return cerr
		}
	}

	if !jsonOut {
		if err := writeScopeNotice(stdout, sc); err != nil {
			return err
		}
	}
	// The dropped-edges notice supersedes the generic Partial caveat when the
	// queried symbol's OWN package is the one that failed: it says the same thing
	// with the part that bears on this answer, and printing both would state the
	// gap twice in two strengths.
	if !jsonOut {
		switch {
		case pr.failedPkg != "":
			if err := writeDroppedEdgesNotice(stdout, "callees", symbolID, pr); err != nil {
				return err
			}
		case pr.isPartial:
			if err := writePartialNotice(stdout, "callees", symbolID, pr.failedPkgs); err != nil {
				return err
			}
		}
	}
	if !jsonOut {
		if err := writeCompletenessNotice(ctx, symbolID, uc, stdout, sc.modules); err != nil {
			return err
		}
		if err := writeWorktreeNotice(ctx, symbolID, uc, stdout, sc.modules); err != nil {
			return err
		}
	}

	if err := printEdgeRefs("callees", symbolID, refs, jsonOut, stdout); err != nil {
		return err
	}
	if len(refs) > 0 && !jsonOut {
		if err := writeEdgeScopeLine(stdout, "callees", opts); err != nil {
			return err
		}
		return writeForeignEdgeAnswer(ctx, newForeignModuleIndex(uc, sc), stdout, "callees", symbolID, refs, false)
	}
	if len(refs) == 0 && !jsonOut {
		v, verr := negativeCallVerdict(ctx, symbolID, false, uc, sc, opts, pr.failedPkg)
		if verr != nil {
			return verr
		}
		return writeCallVerdict(stdout, "callees", symbolID, v, opts)
	}
	return nil
}

// callEdgeRefJSON is the curated snake_case shape of a stored call edge,
// returned by callers/callees.
type callEdgeRefJSON struct {
	ModulePath      string `json:"module_path"`
	ModuleVersion   string `json:"module_version"`
	PipelineVersion string `json:"pipeline_version"`
	FromID          string `json:"from_id"`
	ToID            string `json:"to_id"`
	Confidence      string `json:"confidence"`
	IsTest          bool   `json:"is_test"`
	// Kind is "call" or "reference". A reference names the site where the
	// symbol's value was TAKEN — a route registration, a callback handed to a
	// framework — which is not a claim that it was invoked there. Always
	// populated, so a consumer never has to read an absent field as "call".
	Kind string `json:"kind"`
}

// toEdgeRefsJSON maps to the curated shape. The result is always non-nil so
// JSON output is "[]" (not "null") on no matches.
func toEdgeRefsJSON(refs []ports.CallEdgeRef) []callEdgeRefJSON {
	out := make([]callEdgeRefJSON, 0, len(refs))
	for _, r := range refs {
		out = append(out, callEdgeRefJSON{
			ModulePath:      r.ModulePath,
			ModuleVersion:   r.ModuleVersion,
			PipelineVersion: r.PipelineVersion,
			FromID:          r.FromID,
			ToID:            r.ToID,
			Confidence:      string(r.Confidence),
			IsTest:          r.IsTest,
			Kind:            edgeKindLabel(r.Kind),
		})
	}
	return out
}

func printEdgeRefs(kind, symbolID string, refs []ports.CallEdgeRef, jsonOut bool, stdout io.Writer) error {
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(toEdgeRefsJSON(refs)); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}

	if len(refs) == 0 {
		if _, err := fmt.Fprintf(stdout, "No %s found for %s\n", kind, symbolID); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	}

	if _, err := fmt.Fprintf(stdout, "%s of %s:\n", countOf(len(refs), kind), symbolID); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}
	for _, ref := range refs {
		other := ref.ToID
		if kind == "callers" {
			other = ref.FromID
		}
		testTag := ""
		if ref.IsTest {
			testTag = "  [test]"
		}
		kindTag := ""
		if ref.Kind.IsReference() {
			// Said on the line rather than in a footnote: a reader scanning a
			// caller list must not take a registration for an invocation.
			kindTag = "  [reference — the symbol's value is taken here, not called]"
		}
		if _, err := fmt.Fprintf(stdout, "  %s  [%s]%s%s  (%s@%s)\n",
			other, string(ref.Confidence), kindTag, testTag,
			ref.ModulePath, ref.ModuleVersion,
		); err != nil {
			return fmt.Errorf("writing ref: %w", err)
		}
	}
	return nil
}

// countOf renders a count with the right number: "1 caller", not "1 callers".
// kind is a plural noun ("callers", "callees"), singularised by dropping the
// trailing "s" — which is correct for every kind this renders.
func countOf(n int, kind string) string {
	if n == 1 {
		return "1 " + strings.TrimSuffix(kind, "s")
	}
	return fmt.Sprintf("%d %s", n, kind)
}

// transitiveResult is the JSON shape for --transitive output.
type transitiveResult struct {
	Root      string `json:"root"`
	Direction string `json:"direction"`
	// MaxDepth is the depth limit the traversal ran under, and 0 is the answer
	// "unlimited" rather than the absence of one — the caller always set it, by
	// flag or by default, so there is no unmeasured state to encode.
	MaxDepth  int               `json:"max_depth"`
	NodeCount int               `json:"node_count"`
	EdgeCount int               `json:"edge_count"`
	Nodes     []string          `json:"nodes"`
	Edges     []callEdgeRefJSON `json:"edges"`
	// Scope names the narrowing the reader asked for, empty when they asked for
	// none. Always present, so a consumer never has to read an absent field as
	// "nothing was excluded" — the rows carry is_test, which describes the rows
	// PRESENT and says nothing about the rows removed.
	Scope string `json:"scope"`
}

func runCallersTransitive(ctx context.Context, symbolID string, maxDepth int, jsonOut bool, uc QueryCallGraphUseCase, stdout io.Writer, sc buildScope, opts ports.EdgeQueryOptions) error {
	if err := checkSymbolInScope(ctx, symbolID, uc, sc); err != nil {
		return err
	}
	pr, err := rootPartialStatus(ctx, symbolID, uc, sc)
	if err != nil {
		return err
	}
	edges, nodes, err := uc.TraverseCallers(ctx, symbolID, cgapp.PipelineVersion, maxDepth, sc.modules, opts)
	if err != nil {
		return fmt.Errorf("traversing callers: %w", err)
	}

	// A transitive walk is emptied by the same conditions a single hop is —
	// a module never analysed, a symbol that is not a node, a module served by
	// nothing at this pipeline version — and an empty walk that names none of
	// them reads as a measured absence.
	if len(edges) == 0 && pr.failedPkg == "" {
		if cerr := classifyEmptyEdgeResult(ctx, symbolID, uc, sc); cerr != nil {
			return cerr
		}
	}
	if !jsonOut {
		if err := writeScopeNotice(stdout, sc); err != nil {
			return err
		}
	}
	// The dropped-edges notice supersedes the generic Partial caveat when the
	// queried symbol's OWN package is the one that failed: it says the same thing
	// with the part that bears on this answer, and printing both would state the
	// gap twice in two strengths.
	if !jsonOut {
		switch {
		case pr.failedPkg != "":
			if err := writeDroppedEdgesNotice(stdout, "transitive callers", symbolID, pr); err != nil {
				return err
			}
		case pr.isPartial:
			if err := writePartialNotice(stdout, "transitive callers", symbolID, pr.failedPkgs); err != nil {
				return err
			}
		}
	}
	if !jsonOut {
		if err := writeCompletenessNotice(ctx, symbolID, uc, stdout, sc.modules); err != nil {
			return err
		}
		if err := writeWorktreeNotice(ctx, symbolID, uc, stdout, sc.modules); err != nil {
			return err
		}
	}
	if err := printTransitiveResult("callers", symbolID, maxDepth, nodes, edges, jsonOut, stdout, opts); err != nil {
		return err
	}
	if len(nodes) > 0 && !jsonOut {
		if err := writeEdgeScopeLine(stdout, "callers", opts); err != nil {
			return err
		}
		return writeForeignTransitiveAnswer(ctx, newForeignModuleIndex(uc, sc), stdout, "transitive callers", symbolID, edges, nodes, true)
	}
	if len(nodes) == 0 && !jsonOut {
		v, verr := negativeCallVerdict(ctx, symbolID, true, uc, sc, opts, pr.failedPkg)
		if verr != nil {
			return verr
		}
		return writeCallVerdict(stdout, "transitive callers", symbolID, v, opts)
	}
	return nil
}

func runCalleesTransitive(ctx context.Context, symbolID string, maxDepth int, jsonOut bool, uc QueryCallGraphUseCase, stdout io.Writer, sc buildScope, opts ports.EdgeQueryOptions) error {
	if err := checkSymbolInScope(ctx, symbolID, uc, sc); err != nil {
		return err
	}
	pr, err := rootPartialStatus(ctx, symbolID, uc, sc)
	if err != nil {
		return err
	}
	edges, nodes, err := uc.TraverseCallees(ctx, symbolID, cgapp.PipelineVersion, maxDepth, sc.modules, opts)
	if err != nil {
		return fmt.Errorf("traversing callees: %w", err)
	}

	// A transitive walk is emptied by the same conditions a single hop is —
	// a module never analysed, a symbol that is not a node, a module served by
	// nothing at this pipeline version — and an empty walk that names none of
	// them reads as a measured absence.
	if len(edges) == 0 && pr.failedPkg == "" {
		if cerr := classifyEmptyEdgeResult(ctx, symbolID, uc, sc); cerr != nil {
			return cerr
		}
	}
	if !jsonOut {
		if err := writeScopeNotice(stdout, sc); err != nil {
			return err
		}
	}
	// The dropped-edges notice supersedes the generic Partial caveat when the
	// queried symbol's OWN package is the one that failed: it says the same thing
	// with the part that bears on this answer, and printing both would state the
	// gap twice in two strengths.
	if !jsonOut {
		switch {
		case pr.failedPkg != "":
			if err := writeDroppedEdgesNotice(stdout, "transitive callees", symbolID, pr); err != nil {
				return err
			}
		case pr.isPartial:
			if err := writePartialNotice(stdout, "transitive callees", symbolID, pr.failedPkgs); err != nil {
				return err
			}
		}
	}
	if !jsonOut {
		if err := writeCompletenessNotice(ctx, symbolID, uc, stdout, sc.modules); err != nil {
			return err
		}
		if err := writeWorktreeNotice(ctx, symbolID, uc, stdout, sc.modules); err != nil {
			return err
		}
	}
	if err := printTransitiveResult("callees", symbolID, maxDepth, nodes, edges, jsonOut, stdout, opts); err != nil {
		return err
	}
	if len(nodes) > 0 && !jsonOut {
		if err := writeEdgeScopeLine(stdout, "callees", opts); err != nil {
			return err
		}
		return writeForeignTransitiveAnswer(ctx, newForeignModuleIndex(uc, sc), stdout, "transitive callees", symbolID, edges, nodes, false)
	}
	if len(nodes) == 0 && !jsonOut {
		v, verr := negativeCallVerdict(ctx, symbolID, false, uc, sc, opts, pr.failedPkg)
		if verr != nil {
			return verr
		}
		return writeCallVerdict(stdout, "transitive callees", symbolID, v, opts)
	}
	return nil
}

func printTransitiveResult(direction, root string, maxDepth int, nodes []string, edges []ports.CallEdgeRef, jsonOut bool, stdout io.Writer, opts ports.EdgeQueryOptions) error {
	if jsonOut {
		if nodes == nil {
			nodes = []string{}
		}
		result := transitiveResult{
			Root:      root,
			Direction: direction,
			MaxDepth:  maxDepth,
			NodeCount: len(nodes),
			EdgeCount: len(edges),
			Nodes:     nodes,
			Edges:     toEdgeRefsJSON(edges),
			Scope:     edgeScopeLine(direction, opts),
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}

	if len(nodes) == 0 {
		if _, err := fmt.Fprintf(stdout, "No transitive %s found for %s\n", direction, root); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	}

	depthNote := ""
	if maxDepth > 0 {
		depthNote = fmt.Sprintf(" (depth limit: %d)", maxDepth)
	}
	if _, err := fmt.Fprintf(stdout, "Transitive %s of %s%s (%d nodes):\n", direction, root, depthNote, len(nodes)); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}
	for _, n := range nodes {
		if _, err := fmt.Fprintf(stdout, "  %s\n", n); err != nil {
			return fmt.Errorf("writing node: %w", err)
		}
	}
	return nil
}

// edgeKindLabel renders an edge kind for JSON consumers, naming the zero value
// rather than emitting an empty string a reader would have to know to interpret.
func edgeKindLabel(k domain.EdgeKind) string {
	if k.IsReference() {
		return "reference"
	}
	return "call"
}
