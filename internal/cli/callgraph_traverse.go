package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/spf13/cobra"
)

func newCallersCmd(stdout, stderr io.Writer) *cobra.Command {
	var transitive bool
	var depth int

	cmd := &cobra.Command{
		Use:     "callers <symbol-id>",
		Short:   "Find all callers of a symbol across the call graph store",
		Example: `  kanonarion callers 'github.com/spf13/cobra.(*Command).Execute'`,
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
			if transitive {
				return runCallersTransitive(cmd.Context(), args[0], depth, jsonOut, ctr.QueryCallGraph, stdout)
			}
			return runCallers(cmd.Context(), args[0], jsonOut, ctr.QueryCallGraph, stdout)
		},
	}

	cmd.Flags().BoolVar(&transitive, "transitive", false, "traverse the call graph transitively, following all reachable edges")
	cmd.Flags().IntVar(&depth, "depth", 0, "maximum traversal depth for --transitive (0 = unlimited)")

	return cmd
}

func runCallers(ctx context.Context, symbolID string, jsonOut bool, uc QueryCallGraphUseCase, stdout io.Writer) error {
	refs, err := uc.FindCallers(ctx, symbolID, cgapp.PipelineVersion)
	if err != nil {
		return fmt.Errorf("finding callers: %w", err)
	}

	if len(refs) == 0 {
		if cerr := classifyEmptyEdgeResult(ctx, symbolID, uc); cerr != nil {
			return cerr
		}
	}

	return printEdgeRefs("callers", symbolID, refs, jsonOut, stdout)
}

func newCalleesCmd(stdout, stderr io.Writer) *cobra.Command {
	var transitive bool
	var depth int

	cmd := &cobra.Command{
		Use:     "callees <symbol-id>",
		Short:   "Find all callees of a symbol across the call graph store",
		Example: `  kanonarion callees 'github.com/spf13/cobra.(*Command).Execute'`,
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
			if transitive {
				return runCalleesTransitive(cmd.Context(), args[0], depth, jsonOut, ctr.QueryCallGraph, stdout)
			}
			return runCallees(cmd.Context(), args[0], jsonOut, ctr.QueryCallGraph, stdout)
		},
	}

	cmd.Flags().BoolVar(&transitive, "transitive", false, "traverse the call graph transitively, following all reachable edges")
	cmd.Flags().IntVar(&depth, "depth", 0, "maximum traversal depth for --transitive (0 = unlimited)")

	return cmd
}

func runCallees(ctx context.Context, symbolID string, jsonOut bool, uc QueryCallGraphUseCase, stdout io.Writer) error {
	refs, err := uc.FindCallees(ctx, symbolID, cgapp.PipelineVersion)
	if err != nil {
		return fmt.Errorf("finding callees: %w", err)
	}

	if len(refs) == 0 {
		if cerr := classifyEmptyEdgeResult(ctx, symbolID, uc); cerr != nil {
			return cerr
		}
	}

	return printEdgeRefs("callees", symbolID, refs, jsonOut, stdout)
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

	if _, err := fmt.Fprintf(stdout, "%d %s of %s:\n", len(refs), kind, symbolID); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}
	for _, ref := range refs {
		other := ref.ToID
		if kind == "callers" {
			other = ref.FromID
		}
		if _, err := fmt.Fprintf(stdout, "  %s  [%s]  (%s@%s)\n",
			other, string(ref.Confidence),
			ref.ModulePath, ref.ModuleVersion,
		); err != nil {
			return fmt.Errorf("writing ref: %w", err)
		}
	}
	return nil
}

// transitiveResult is the JSON shape for --transitive output.
type transitiveResult struct {
	Root      string            `json:"root"`
	Direction string            `json:"direction"`
	MaxDepth  int               `json:"max_depth,omitempty"`
	NodeCount int               `json:"node_count"`
	EdgeCount int               `json:"edge_count"`
	Nodes     []string          `json:"nodes"`
	Edges     []callEdgeRefJSON `json:"edges"`
}

func runCallersTransitive(ctx context.Context, symbolID string, maxDepth int, jsonOut bool, uc QueryCallGraphUseCase, stdout io.Writer) error {
	edges, nodes, err := uc.TraverseCallers(ctx, symbolID, cgapp.PipelineVersion, maxDepth)
	if err != nil {
		return fmt.Errorf("traversing callers: %w", err)
	}
	return printTransitiveResult("callers", symbolID, maxDepth, nodes, edges, jsonOut, stdout)
}

func runCalleesTransitive(ctx context.Context, symbolID string, maxDepth int, jsonOut bool, uc QueryCallGraphUseCase, stdout io.Writer) error {
	edges, nodes, err := uc.TraverseCallees(ctx, symbolID, cgapp.PipelineVersion, maxDepth)
	if err != nil {
		return fmt.Errorf("traversing callees: %w", err)
	}
	return printTransitiveResult("callees", symbolID, maxDepth, nodes, edges, jsonOut, stdout)
}

func printTransitiveResult(direction, root string, maxDepth int, nodes []string, edges []ports.CallEdgeRef, jsonOut bool, stdout io.Writer) error {
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
