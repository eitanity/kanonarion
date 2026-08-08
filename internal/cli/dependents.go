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

	return dependentsWith(ctx, ctr, coord, walkID, jsonOut, directOnly, includeRoot, stdout, stderr)
}

// dependentsWith holds the query over an injected Container, so the walk
// selection — the named --walk-id and the containment search that stands in for
// it — is exercisable without a live store. Split from runDependents on the
// same terms as licenseCompatWith.
func dependentsWith(ctx context.Context, ctr *Container, coord coordinate.ModuleCoordinate, walkID string,
	jsonOut, directOnly, includeRoot bool, stdout, stderr io.Writer,
) error {
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
			return walkIDMiss(ctx, ctr.QueryWalks, walkID, stderr)
		}
		if isWalkIntegrity(err) {
			return &exitError{code: ExitIntegrity, msg: fmt.Sprintf("walk record %q failed integrity check", walkID)}
		}
		return fmt.Errorf("getting walk: %w", err)
	}

	deps, rootExcluded := walkDependents(rec, coord, includeRoot)
	if directOnly {
		filtered := deps[:0]
		for _, d := range deps {
			if d.Direct || d.Root {
				filtered = append(filtered, d)
			}
		}
		deps = filtered
	}

	// The frame comes off the record, so it is stated whether the walk was named
	// with --walk-id or found by the containment search — the search takes the
	// newest walk containing the coordinate and cannot tell two platforms apart.
	walkFrame := rec.Graph.BuildEnv.Frame()
	// Both directions of the question are bounded by the same fact. Asking about a
	// +incompatible target, the answer covers only edges the module system
	// resolved; asking about anything else, a +incompatible module in the walk can
	// never appear as a dependent, because no requirement edge was resolved under
	// it. Naming the coordinates responsible is what stops an absence being read
	// as a measurement.
	preModules := preModulesNodesIn(rec.Graph)
	if jsonOut {
		return writeDependentsJSON(stdout, walkID, walkFrame, coord.String(), deps,
			preModulesCaveatFor(append(preModules, coord)...))
	}
	if err := writeDependentsText(stdout, walkID, walkFrame, coord.String(), deps, directOnly, rootExcluded, includeRoot); err != nil {
		return err
	}
	return writeWalkPreModulesCaveat(stdout, rec.Graph)
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
//
// The second return value reports that the root WAS dropped from the answer —
// it depends on coord and includeRoot was off. That fact is only knowable here,
// where the edge is seen and the exclusion applied, and it is exactly the fact
// an empty answer needs in order to state its own scope. Without it a caller
// cannot tell "nothing depends on this module" from "nothing except the thing
// you are asking on behalf of".
func walkDependents(rec walkdomain.WalkRecord, coord coordinate.ModuleCoordinate, includeRoot bool) ([]dependentResult, bool) {
	directDeps := make(map[coordinate.ModuleCoordinate]bool)
	for _, n := range rec.Graph.Nodes {
		if n.DirectDependency {
			directDeps[n.Coordinate] = true
		}
	}

	seen := make(map[coordinate.ModuleCoordinate]bool)
	var out []dependentResult
	var rootExcluded bool

	for _, edge := range rec.Graph.Edges {
		if edge.To.Path() != coord.Path() || edge.To.Version() != coord.Version() {
			continue
		}
		if seen[edge.From] {
			continue
		}
		seen[edge.From] = true
		isRoot := edge.From.Path() == rec.Target.Path() && edge.From.Version() == rec.Target.Version()
		if isRoot && !includeRoot {
			rootExcluded = true
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
		if out[i].Coord.Path() != out[j].Coord.Path() {
			return out[i].Coord.Path() < out[j].Coord.Path()
		}
		return out[i].Coord.Version() < out[j].Coord.Version()
	})
	return out, rootExcluded
}

type dependentsJSON struct {
	WalkID string `json:"walk_id"`
	// WalkFrame is the GOOS/GOARCH the answering walk resolved for, or
	// "unrecorded" for a walk written before the frame was projected.
	WalkFrame  string               `json:"walk_frame"`
	Target     string               `json:"target"`
	Dependents []dependentEntryJSON `json:"dependents"`
	// PreModulesCaveat is present only when the answer is bounded by a module
	// resolved under pre-modules semantics; absent means no coordinate in scope is
	// one, so an answer that never meets the class marshals exactly as before.
	PreModulesCaveat *preModulesCaveatJSON `json:"pre_modules_caveat,omitempty"`
}

type dependentEntryJSON struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	Direct  bool   `json:"direct"`
	Root    bool   `json:"root"`
}

func writeDependentsJSON(
	w io.Writer,
	walkID, walkFrame, target string,
	deps []dependentResult,
	caveat *preModulesCaveatJSON,
) error {
	entries := make([]dependentEntryJSON, len(deps))
	for i, d := range deps {
		entries[i] = dependentEntryJSON{
			Module:  d.Coord.Path(),
			Version: d.Coord.Version(),
			Direct:  d.Direct,
			Root:    d.Root,
		}
	}
	result := dependentsJSON{
		WalkID:           walkID,
		WalkFrame:        walkFrame,
		Target:           target,
		Dependents:       entries,
		PreModulesCaveat: caveat,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return nil
}

// walkSearchLimit is how many of the newest walks the containment search reads.
// It is a bound on cost — each candidate costs a whole walk record read — and
// not a statement that older walks hold nothing.
const walkSearchLimit = 50

// findWalkContaining returns the ID of the most recent walk (by started_at) that
// contains coord as a node in its graph.
//
// The search is bounded, and its failure says so. A negative from a search that
// did not exhaust the population is not an absence: phrased flat, "no walk found
// containing X" reads as "this store has never seen X" while the walk holding it
// sits at position 51. That is the same rule the call-graph verdict applies —
// RESOLVED-ABSENT only where the axis was measurable — on a store search.
//
// One extra row is fetched so the search knows whether its own bound bit,
// exactly as the listings do. When it did not, the population WAS exhausted and
// the negative is stated plainly: a caveat emitted unconditionally would teach
// the reader to discount it in the case where it is real.
func findWalkContaining(ctx context.Context, uc QueryWalksUseCase, coord coordinate.ModuleCoordinate) (string, error) {
	summaries, err := uc.ListWalks(ctx, walkports.WalkFilter{Limit: truncationFetchLimit(walkSearchLimit)})
	if err != nil {
		return "", fmt.Errorf("listing walks: %w", err)
	}
	searched, bounded := truncateList(summaries, walkSearchLimit)
	for _, s := range searched {
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
	if !bounded {
		return "", fmt.Errorf("no walk in this store contains %s (all %d walk(s) searched)", coord, len(searched))
	}
	// Only now is the store's own size worth a read: it is what turns "the
	// search stopped" into a number the caller can act on.
	total := len(searched)
	if all, aerr := uc.ListWalks(ctx, walkports.WalkFilter{}); aerr == nil {
		total = len(all)
	}
	return "", fmt.Errorf("no walk containing %s among the %d most recent walks searched — the store holds %d; "+
		"name the walk to query with --walk-id, or list them with: kanonarion walk-list --limit 0",
		coord, walkSearchLimit, total)
}

// Scope suffixes for the answer line. The root is excluded by default, so
// every answer produced under that default is narrower than the question asked
// and has to say so — an empty one most of all, because a reader relaying it
// verbatim otherwise reports the module as unused.
const (
	// rootDependsSuffix is used when the root itself depends on the target and
	// was dropped: the answer names the omission and the flag that reverses it.
	rootDependsSuffix = " (the walk root does; it is excluded by default — pass --include-root)"
	// rootScopeSuffix is used when the root does not depend on the target
	// either. There is nothing being withheld, only a scope to state.
	rootScopeSuffix = " (walk root excluded by default)"
)

// dependentsScopeSuffix returns the suffix the answer line carries.
//
// It is empty when --include-root was passed: the root was in scope, so there
// is no exclusion to disclose and a hint pointing at a flag already in effect
// would be noise.
func dependentsScopeSuffix(rootExcluded, includeRoot bool) string {
	switch {
	case includeRoot:
		return ""
	case rootExcluded:
		return rootDependsSuffix
	default:
		return rootScopeSuffix
	}
}

func writeDependentsText(w io.Writer, walkID, walkFrame, target string, deps []dependentResult, directOnly, rootExcluded, includeRoot bool) error {
	qualifier := ""
	if directOnly {
		qualifier = "direct "
	}
	if len(deps) == 0 {
		if _, err := fmt.Fprintf(w, "No %smodules in walk %s (frame %s) depend on %s%s\n",
			qualifier, walkID, walkFrame, target, dependentsScopeSuffix(rootExcluded, includeRoot)); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	}
	// A non-zero answer states the exclusion only when something was actually
	// withheld. "walk root excluded by default" on a list that names ten
	// modules teaches nothing the help text does not already carry.
	header := ""
	if rootExcluded && !includeRoot {
		header = rootDependsSuffix
	}
	if _, err := fmt.Fprintf(w, "%d %smodule(s) in walk %s (frame %s) depend on %s%s:\n",
		len(deps), qualifier, walkID, walkFrame, target, header); err != nil {
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
		if _, err := fmt.Fprintf(w, "  %s@%s%s\n", d.Coord.Path(), d.Coord.Version(), annotation); err != nil {
			return fmt.Errorf("writing dependent: %w", err)
		}
	}
	return nil
}
