package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/spf13/cobra"

	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

func newDependentsCmd(stdout, stderr io.Writer) *cobra.Command {
	var walkID string
	var directOnly, includeRoot bool

	cmd := &cobra.Command{
		Use:   "dependents <module>@<version>",
		Short: "Find which modules in a walk depend on a given module",
		Long: `Find which modules in a walk depend on the given <module>@<version>.

Scans the stored walk graph for every module with a direct import edge to the
target and prints them sorted lexicographically. The walk root (your own module)
is excluded by default; pass --include-root to include it.

Text output annotations:
  [root]    the walk root module itself — only shown with --include-root
  [direct]  a direct dependency of the walk root (in its go.mod)
  (none)    a transitive dependency

The [root] entry, when present, sorts first.

JSON output adds "root" and "direct" boolean fields to each entry. To find all
entries that represent a first-party concern (root or direct dep), filter on
root || direct.

Flag combinations:
  (default)                    all dependents, root excluded
  --include-root               all dependents, root shown as [root]
  --direct-only                only [direct] entries, root excluded
  --direct-only --include-root [direct] entries plus [root] if the root also depends on the target`,
		Example: `  # All modules that depend on x/net in a walk
  kanonarion dependents golang.org/x/net@v0.51.0 --walk-id <id>

  # Include the walk root module itself (your own go.mod)
  kanonarion dependents golang.org/x/net@v0.51.0 --walk-id <id> --include-root

  # Pre-upgrade blast radius: only direct deps + root
  kanonarion dependents golang.org/x/net@v0.51.0 --walk-id <id> --direct-only --include-root

  # Machine-readable output for agent pipelines
  kanonarion dependents golang.org/x/net@v0.51.0 --walk-id <id> --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			return runDependents(cmd.Context(), args[0], storeRoot, walkID, jsonOut, directOnly, includeRoot, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&walkID, "walk-id", "", "walk record ID to query (optional; defaults to most recent walk containing the target module)")
	cmd.Flags().BoolVar(&directOnly, "direct-only", false, "only show direct dependencies of the walk root")
	cmd.Flags().BoolVar(&includeRoot, "include-root", false, "show the walk root module itself if it depends on the target")

	return cmd
}

func runDependents(ctx context.Context, moduleArg, storeRoot, walkID string, jsonOut, directOnly, includeRoot bool, stdout, stderr io.Writer) error {
	coord, err := parseCoordinate(moduleArg)
	if err != nil {
		return fmt.Errorf("invalid module coordinate %q: %w", moduleArg, err)
	}

	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	if walkID == "" {
		resolved, rerr := findWalkContaining(ctx, ctr.QueryWalks, coord)
		if rerr != nil {
			return rerr
		}
		walkID = resolved
	}

	rec, err := ctr.QueryWalks.GetWalk(ctx, walkID)
	if err != nil {
		if isWalkNotFound(err) {
			return &exitError{code: ExitConfig, msg: fmt.Sprintf("walk record %q not found", walkID)}
		}
		if isWalkIntegrity(err) {
			return &exitError{code: ExitIntegrity, msg: fmt.Sprintf("walk record %q failed integrity check", walkID)}
		}
		return fmt.Errorf("getting walk: %w", err)
	}

	deps := walkDependents(rec, coord, includeRoot)
	if directOnly {
		filtered := deps[:0]
		for _, d := range deps {
			if d.Direct || d.Root {
				filtered = append(filtered, d)
			}
		}
		deps = filtered
	}

	if jsonOut {
		return writeDependentsJSON(stdout, walkID, coord.String(), deps)
	}
	return writeDependentsText(stdout, walkID, coord.String(), deps, directOnly)
}

// dependentResult holds a single module that depends on the queried target.
type dependentResult struct {
	Coord  coordinate.ModuleCoordinate
	Direct bool // true when this module is a direct dep of the walk root (GraphNode.DirectDependency)
	Root   bool // true when this module IS the walk root
}

// walkDependents returns all modules in rec that have a direct graph edge
// pointing to coord, sorted lexicographically by (path, version). When
// includeRoot is true, the walk root is included if it has such an edge and
// is annotated with Root=true. Direct is set from GraphNode.DirectDependency
// and is never true for the walk root (the root is not a dependency of itself).
func walkDependents(rec walkdomain.WalkRecord, coord coordinate.ModuleCoordinate, includeRoot bool) []dependentResult {
	directDeps := make(map[coordinate.ModuleCoordinate]bool)
	for _, n := range rec.Graph.Nodes {
		if n.DirectDependency {
			directDeps[n.Coordinate] = true
		}
	}

	seen := make(map[coordinate.ModuleCoordinate]bool)
	var out []dependentResult

	for _, edge := range rec.Graph.Edges {
		if edge.To.Path != coord.Path || edge.To.Version != coord.Version {
			continue
		}
		if seen[edge.From] {
			continue
		}
		seen[edge.From] = true
		isRoot := edge.From.Path == rec.Target.Path && edge.From.Version == rec.Target.Version
		if isRoot && !includeRoot {
			continue
		}
		out = append(out, dependentResult{
			Coord:  edge.From,
			Direct: directDeps[edge.From],
			Root:   isRoot,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		// Root sorts first so it stands out at the top.
		if out[i].Root != out[j].Root {
			return out[i].Root
		}
		if out[i].Coord.Path != out[j].Coord.Path {
			return out[i].Coord.Path < out[j].Coord.Path
		}
		return out[i].Coord.Version < out[j].Coord.Version
	})
	return out
}

type dependentsJSON struct {
	WalkID     string               `json:"walk_id"`
	Target     string               `json:"target"`
	Dependents []dependentEntryJSON `json:"dependents"`
}

type dependentEntryJSON struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	Direct  bool   `json:"direct"`
	Root    bool   `json:"root"`
}

func writeDependentsJSON(w io.Writer, walkID, target string, deps []dependentResult) error {
	entries := make([]dependentEntryJSON, len(deps))
	for i, d := range deps {
		entries[i] = dependentEntryJSON{
			Module:  d.Coord.Path,
			Version: d.Coord.Version,
			Direct:  d.Direct,
			Root:    d.Root,
		}
	}
	result := dependentsJSON{
		WalkID:     walkID,
		Target:     target,
		Dependents: entries,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return nil
}

// findWalkContaining returns the ID of the most recent walk (by started_at) that
// contains coord as a node in its graph. Returns an error if no such walk exists.
func findWalkContaining(ctx context.Context, uc QueryWalksUseCase, coord coordinate.ModuleCoordinate) (string, error) {
	const searchLimit = 50
	summaries, err := uc.ListWalks(ctx, walkports.WalkFilter{Limit: searchLimit})
	if err != nil {
		return "", fmt.Errorf("listing walks: %w", err)
	}
	for _, s := range summaries {
		rec, rerr := uc.GetWalk(ctx, s.ID)
		if rerr != nil {
			continue
		}
		for _, node := range rec.Graph.Nodes {
			if node.Coordinate == coord {
				return s.ID, nil
			}
		}
	}
	return "", fmt.Errorf("no walk found containing %s", coord)
}

func writeDependentsText(w io.Writer, walkID, target string, deps []dependentResult, directOnly bool) error {
	qualifier := ""
	if directOnly {
		qualifier = "direct "
	}
	if len(deps) == 0 {
		if _, err := fmt.Fprintf(w, "No %smodules in walk %s depend on %s\n", qualifier, walkID, target); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	}
	if _, err := fmt.Fprintf(w, "%d %smodule(s) in walk %s depend on %s:\n", len(deps), qualifier, walkID, target); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}
	for _, d := range deps {
		annotation := ""
		switch {
		case d.Root:
			annotation = "  [root]"
		case d.Direct:
			annotation = "  [direct]"
		}
		if _, err := fmt.Fprintf(w, "  %s@%s%s\n", d.Coord.Path, d.Coord.Version, annotation); err != nil {
			return fmt.Errorf("writing dependent: %w", err)
		}
	}
	return nil
}
