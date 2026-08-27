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
)

// dependentsFlags carries how a `dependents` question names the build it is
// about, and how much of that build's answer to print.
//
// The build is not a preference: what a coordinate is surrounded by is a
// property of one build, so a question that names none has no answer. The first
// four fields are the ways to name one.
type dependentsFlags struct {
	walkID  string
	gomod   string
	tool    bool
	project bool
	// anyBuild reaches the store-wide containment search: "which of my projects
	// uses this", which is a real question and not the default one.
	anyBuild    bool
	directOnly  bool
	includeRoot bool
}

func newDependentsCmd(stdout, stderr io.Writer) *cobra.Command {
	var f dependentsFlags

	cmd := &cobra.Command{
		Use:         "dependents <module>@<version>",
		Annotations: map[string]string{annotationStoreIntent: StoreIntentRead},
		Short:       "Find which modules in a build depend on a given module",
		Long: `Find which modules in one build depend on the given <module>@<version>.

Scans the stored walk graph for every module with a direct import edge to the
target and prints them sorted lexicographically. The walk root (your own module)
is excluded by default; pass --include-root to include it.

Which build answers:
  --walk-id <id>   one stored walk, queried as named
  --gomod <path>   the latest project walk for that go.mod, in the scope asked
                   for (default code; --tool, --project)
  (neither)        the go.mod in the working directory, on the same terms
  --any-build      search the store for a build that holds the target

With no go.mod in the working directory and none of the flags, the command
refuses rather than picking a build for you.

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
		Example: `  # What in this project's build depends on x/net
  kanonarion dependents golang.org/x/net@v0.51.0

  # A linter is in the tooling closure, not the code build
  kanonarion dependents 4d63.com/gochecknoglobals@v0.2.2 --tool

  # Another project's build
  kanonarion dependents golang.org/x/net@v0.51.0 --gomod ../other/go.mod

  # One stored walk, queried as named
  kanonarion dependents golang.org/x/net@v0.51.0 --walk-id <id> --include-root

  # Which of my projects uses this at all
  kanonarion dependents golang.org/x/net@v0.51.0 --any-build

  # Machine-readable output for agent pipelines
  kanonarion dependents golang.org/x/net@v0.51.0 --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			return runDependents(cmd.Context(), args[0], storeRoot, f, jsonOut, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&f.walkID, "walk-id", "", "walk record ID to query, in place of a manifest")
	cmd.Flags().StringVar(&f.gomod, "gomod", "",
		"answer in the frame of the latest project walk for this go.mod; takes a path, e.g. --gomod "+defaultGoModPath)
	cmd.Flags().BoolVar(&f.tool, "tool", false, "scope to the tooling supply chain (the go.mod tool directives' closure)")
	cmd.Flags().BoolVar(&f.project, "project", false, "scope to the complete set: the project's code AND tooling")
	cmd.Flags().BoolVar(&f.anyBuild, "any-build", false, "search the store for a build that holds the target, instead of rooting at a project")
	cmd.Flags().BoolVar(&f.directOnly, "direct-only", false, "only show direct dependencies of the walk root")
	cmd.Flags().BoolVar(&f.includeRoot, "include-root", false, "show the walk root module itself if it depends on the target")

	return cmd
}

func runDependents(ctx context.Context, moduleArg, storeRoot string, f dependentsFlags, jsonOut bool, stdout, stderr io.Writer) error {
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

	return dependentsWith(ctx, ctr, coord, f, jsonOut, stdout, stderr)
}

// dependentsWith holds the query over an injected Container, so the rooting —
// the named --walk-id, the manifest selector, and the --any-build search — is
// exercisable without a live store. Split from runDependents on the same terms
// as licenseCompatWith.
func dependentsWith(ctx context.Context, ctr *Container, coord coordinate.ModuleCoordinate, f dependentsFlags,
	jsonOut bool, stdout, stderr io.Writer,
) error {
	containment, rec, err := resolveDependentsRoot(ctx, ctr.QueryWalks, coord, f, stderr)
	if err != nil {
		return err
	}
	walkID := containment.walkID

	deps, rootExcluded := walkDependents(rec, coord, f.includeRoot)
	if f.directOnly {
		filtered := deps[:0]
		for _, d := range deps {
			if d.Direct || d.Root {
				filtered = append(filtered, d)
			}
		}
		deps = filtered
	}

	// The frame comes off the record, so it is stated however the walk was
	// reached. Which walk answered is carried alongside it: two walks holding one
	// coordinate answer two questions, and the id alone does not say which was
	// asked.
	walkFrame := rec.Graph.Frame()
	// Both directions of the question are bounded by the same fact. Asking about a
	// +incompatible target, the answer covers only edges the module system
	// resolved; asking about anything else, a +incompatible module in the walk can
	// never appear as a dependent, because no requirement edge was resolved under
	// it. Naming the coordinates responsible is what stops an absence being read
	// as a measurement.
	preModules := preModulesNodesIn(rec.Graph)
	if jsonOut {
		return writeDependentsJSON(stdout, walkID, walkFrame, containment.selection(), coord.String(), deps,
			preModulesCaveatFor(append(preModules, coord)...))
	}
	// Above the answer, not after it: it says which build the rows below describe,
	// and a reader who has read the rows has already decided what they are about.
	if note := containment.statement(coord); note != "" {
		if _, werr := fmt.Fprint(stdout, note); werr != nil {
			return fmt.Errorf("writing walk selection notice: %w", werr)
		}
	}
	if err := writeDependentsText(stdout, walkID, walkFrame, coord.String(), deps, f.directOnly, rootExcluded, f.includeRoot); err != nil {
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
	// WalkFrame is the GOOS/GOARCH the answering walk resolved for, or a token
	// standing for the reason there is none. WalkFrameBasis is the same fact as
	// data: "platform", "not_platform_scoped" for a module-rooted walk (no
	// platform applies, and re-walking never produces one), or "unrecorded" (the
	// platform is simply not known). Both are always emitted.
	WalkFrame      string `json:"walk_frame"`
	WalkFrameBasis string `json:"walk_frame_basis"`
	// WalkSelection says how that walk was reached: pinned by the caller, chosen
	// because it is rooted at a build that consumes the target, or fallen back to
	// because the only walks holding the target are rooted at the target itself.
	// The last of those answers a different question and the field is what says
	// so on a stream that carries no prose.
	WalkSelection walkSelectionJSON    `json:"walk_selection"`
	Target        string               `json:"target"`
	Dependents    []dependentEntryJSON `json:"dependents"`
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
	walkID string,
	walkFrame walkdomain.WalkFrame,
	selection walkSelectionJSON,
	target string,
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
		WalkFrame:        walkFrame.Text,
		WalkFrameBasis:   string(walkFrame.Basis),
		WalkSelection:    selection,
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

func writeDependentsText(w io.Writer, walkID string, walkFrame walkdomain.WalkFrame, target string, deps []dependentResult, directOnly, rootExcluded, includeRoot bool) error {
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
