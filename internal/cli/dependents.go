package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"golang.org/x/mod/module"

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
	// target is the platform the manifest route selects its walk for. The search
	// and a pinned walk each arrive at a build that already recorded one, so it
	// is refused there rather than ignored.
	target buildTargetFlags
}

func newDependentsCmd(stdout, stderr io.Writer) *cobra.Command {
	var f dependentsFlags

	cmd := &cobra.Command{
		Use: "dependents <module>[@<version>]",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "Find which modules in a build depend on a given module",
		Long: `Find which modules in one build depend on the given module.

Scans the stored walk graph for every module with a direct import edge to the
target and prints them sorted lexicographically. The walk root (your own module)
is excluded by default; pass --include-root to include it.

The target may be a coordinate or a bare module path. A bare path is answered
across every version of it the answering build resolved, and the answer names
those versions — on the text path as a notice above the rows, under --json as
the "target_versions" field. "Who depends on jwt/v4" is a question about a path,
and having to learn which version the build resolved before it can be asked has
the answer-ordering backwards.

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

JSON output also carries "root_scope" on every answer: which module the walk is
rooted at, whether it was excluded from the search, whether it depends on the
target, and the flag that includes it. An empty "dependents" with
root_scope.depends_on_target true is not "nothing uses this" — the walk root
does, and it was out of scope.

Flag combinations:
  (default)                    all dependents, root excluded
  --include-root               all dependents, root shown as [root]
  --direct-only                only [direct] entries, root excluded
  --direct-only --include-root [direct] entries plus [root] if the root also depends on the target`,
		Example: `  # What in this project's build depends on x/net
  kanonarion dependents golang.org/x/net@v0.51.0

  # The same question about whatever version this build resolved
  kanonarion dependents golang.org/x/net

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
	registerBuildTargetFlags(cmd, &f.target)

	return cmd
}

func runDependents(ctx context.Context, moduleArg, storeRoot string, f dependentsFlags, jsonOut bool, stdout, stderr io.Writer) error {
	coord, err := parseDependentsTarget(moduleArg)
	if err != nil {
		return err
	}

	// The manifest route is the one that chooses a walk, so it is the one a
	// declared target can act on; --walk-id and --any-build refuse it by name in
	// resolveDependentsRoot, through the flag list they already carry.
	if terr := resolveReadTarget(ctx, f.target, "dependents", f.walkID == "" && !f.anyBuild, f.gomod); terr != nil {
		return terr
	}

	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	return dependentsWith(ctx, ctr, coord, f, jsonOut, stdout, stderr)
}

// parseDependentsTarget reads the module a question is about. A coordinate pins
// one version; a bare path names the module and leaves the versions to the
// build, and is carried as a version-less coordinate so one value describes both
// forms.
func parseDependentsTarget(arg string) (coordinate.ModuleCoordinate, error) {
	if strings.Contains(arg, "@") {
		coord, err := parseCoordinate(arg)
		if err != nil {
			return coordinate.ModuleCoordinate{}, fmt.Errorf("invalid module coordinate %q: %w", arg, err)
		}
		return coord, nil
	}
	// A walk id is named by shape, not read as a malformed module path: the walk
	// goes on --walk-id here, and "missing dot in first path element" does not say
	// so. Same refusal license-compat gives for the same mistake.
	if looksLikeWalkID(arg) {
		return coordinate.ModuleCoordinate{}, &exitError{code: ExitConfig, msg: fmt.Sprintf(
			"%q is a walk id, and dependents takes a module here; the walk it is answered in goes "+
				"on --walk-id:\n  kanonarion dependents <module> --walk-id %s", arg, arg)}
	}
	// The path is checked before it is answered over: a string that cannot be a
	// module path has no versions in any build, and reporting that as "no modules
	// depend on it" is an absence presented as a measurement.
	if err := module.CheckPath(arg); err != nil {
		return coordinate.ModuleCoordinate{}, fmt.Errorf("invalid module path %q: %w", arg, err)
	}
	coord, err := coordinate.NewPathOnlyCoordinate(arg)
	if err != nil {
		return coordinate.ModuleCoordinate{}, fmt.Errorf("invalid module path %q: %w", arg, err)
	}
	return coord, nil
}

// dependentsTargetText is how the target is written back to the caller: the
// coordinate where one was named, the bare path where it was not. A version-less
// ModuleCoordinate renders with a trailing "@", which is not what was typed.
func dependentsTargetText(coord coordinate.ModuleCoordinate) string {
	if coord.HasVersion() {
		return coord.String()
	}
	return coord.Path()
}

// graphHoldsTarget reports whether g holds the target: the exact coordinate
// where one was named, any version of the path where it was not.
func graphHoldsTarget(g walkdomain.Graph, coord coordinate.ModuleCoordinate) bool {
	if coord.HasVersion() {
		return graphHolds(g, coord)
	}
	return len(graphVersionsOf(g, coord.Path())) > 0
}

// dependentsTargets are the coordinates one question is answered over, newest
// version first: the one that was named, or every version of the path the
// answering build resolved.
func dependentsTargets(g walkdomain.Graph, coord coordinate.ModuleCoordinate) ([]coordinate.ModuleCoordinate, []string) {
	if coord.HasVersion() {
		return []coordinate.ModuleCoordinate{coord}, nil
	}
	versions := graphVersionsOf(g, coord.Path())
	out := make([]coordinate.ModuleCoordinate, 0, len(versions))
	for _, v := range versions {
		c, err := coordinate.NewModuleCoordinate(coord.Path(), v)
		if err != nil {
			// The version came off a stored graph node, so it is one this store
			// already accepted; a rejection here would drop a real row silently.
			continue
		}
		out = append(out, c)
	}
	return out, versions
}

// dependentsVersionNotice says which versions a bare-path answer covers. It
// stands above the rows for the same reason every other selection notice does:
// a reader who has read them has already decided what they were about.
func dependentsVersionNotice(path, walkID string, versions []string) string {
	if len(versions) == 0 {
		return ""
	}
	if len(versions) == 1 {
		return fmt.Sprintf("notice: no version was named; walk %s resolves %s at %s, and the answer below covers it\n",
			walkID, path, versions[0])
	}
	return fmt.Sprintf("notice: no version was named; walk %s resolves %s at %d versions (%s), and the answer below covers all of them\n",
		walkID, path, len(versions), strings.Join(versions, ", "))
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

	// A bare path is several questions with one answer: each version the build
	// resolved is asked separately and the rows are unioned, because "who depends
	// on this module" is one list however many versions sit behind it.
	targets, coveredVersions := dependentsTargets(rec.Graph, coord)
	deps, rootScope := walkDependentsOver(rec, targets, f.includeRoot)
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
	target := dependentsTargetText(coord)
	if jsonOut {
		return writeDependentsJSON(stdout, walkID, walkFrame, containment.selection(), target, coveredVersions,
			deps, rootScope, preModulesCaveatFor(append(preModules, targets...)...))
	}
	// Above the answer, not after it: it says which build the rows below describe,
	// and a reader who has read the rows has already decided what they are about.
	if note := containment.statement(coord); note != "" {
		if _, werr := fmt.Fprint(stdout, note); werr != nil {
			return fmt.Errorf("writing walk selection notice: %w", werr)
		}
	}
	if note := dependentsVersionNotice(target, walkID, coveredVersions); note != "" {
		if _, werr := fmt.Fprint(stdout, note); werr != nil {
			return fmt.Errorf("writing version notice: %w", werr)
		}
	}
	if err := writeDependentsText(stdout, walkID, walkFrame, target, deps, f.directOnly,
		rootScope.withheld(), f.includeRoot); err != nil {
		return err
	}
	return writeWalkPreModulesCaveat(stdout, rec.Graph)
}

// walkDependentsOver unions the answers for every target coordinate, which is
// one for a pinned question and one per resolved version for a bare path. A
// module that depends on two versions of the target is one row, and its
// annotations are the strongest of the ones it earned.
func walkDependentsOver(rec walkdomain.WalkRecord, targets []coordinate.ModuleCoordinate, includeRoot bool,
) ([]dependentResult, dependentsRootScope) {
	var out []dependentResult
	var scope dependentsRootScope
	at := make(map[coordinate.ModuleCoordinate]int)
	for i, t := range targets {
		deps, sc := walkDependents(rec, t, includeRoot)
		if i == 0 {
			scope = sc
		} else {
			scope.DependsOnTarget = scope.DependsOnTarget || sc.DependsOnTarget
		}
		for _, d := range deps {
			j, seen := at[d.Coord]
			if !seen {
				at[d.Coord] = len(out)
				out = append(out, d)
				continue
			}
			out[j].Direct = out[j].Direct || d.Direct
			out[j].Root = out[j].Root || d.Root
		}
	}
	sortDependents(out)
	return out, scope
}

// dependentResult holds a single module that depends on the queried target.
type dependentResult struct {
	Coord  coordinate.ModuleCoordinate
	Direct bool // true when this module is a direct dep of the walk root (GraphNode.DirectDependency)
	Root   bool // true when this module IS the walk root
}

// dependentsRootScope is what the search left out, measured whether or not it
// mattered on this answer.
//
// Excluded says the root was not searched; DependsOnTarget says it would have
// been an answer. The pair is what separates "nothing depends on this module"
// from "nothing except the thing you are asking on behalf of", and only the two
// together do it: Excluded alone cannot tell a scope from a withheld row, and
// DependsOnTarget alone cannot say whether the row reached the answer.
type dependentsRootScope struct {
	Root            coordinate.ModuleCoordinate
	Excluded        bool
	DependsOnTarget bool
}

// withheld reports that a row was actually dropped: the root depends on the
// target and was out of scope. It is the narrower fact the text rendering
// discloses, and it is derived here rather than measured separately so the two
// channels cannot drift apart.
func (s dependentsRootScope) withheld() bool { return s.Excluded && s.DependsOnTarget }

// walkDependents returns all modules in rec that have a direct graph edge
// pointing to coord, sorted lexicographically by (path, version). When
// includeRoot is true, the walk root is included if it has such an edge and
// is annotated with Root=true. Direct is set from GraphNode.DirectDependency
// and is never true for the walk root (the root is not a dependency of itself).
//
// The second return value is the scope of the search itself. That fact is only
// knowable here, where the edge is seen and the exclusion applied, and it is
// exactly the fact an empty answer needs in order to state what it covered.
func walkDependents(rec walkdomain.WalkRecord, coord coordinate.ModuleCoordinate, includeRoot bool) ([]dependentResult, dependentsRootScope) {
	directDeps := make(map[coordinate.ModuleCoordinate]bool)
	for _, n := range rec.Graph.Nodes {
		if n.DirectDependency {
			directDeps[n.Coordinate] = true
		}
	}

	seen := make(map[coordinate.ModuleCoordinate]bool)
	var out []dependentResult
	scope := dependentsRootScope{Root: rec.Target, Excluded: !includeRoot}

	for _, edge := range rec.Graph.Edges {
		if edge.To.Path() != coord.Path() || edge.To.Version() != coord.Version() {
			continue
		}
		if seen[edge.From] {
			continue
		}
		seen[edge.From] = true
		isRoot := edge.From.Path() == rec.Target.Path() && edge.From.Version() == rec.Target.Version()
		if isRoot {
			scope.DependsOnTarget = true
		}
		if isRoot && !includeRoot {
			continue
		}
		out = append(out, dependentResult{
			Coord:  edge.From,
			Direct: directDeps[edge.From],
			Root:   isRoot,
		})
	}

	sortDependents(out)
	return out, scope
}

// sortDependents is the answer's order, shared by the single-coordinate read and
// the union a bare path produces so the two cannot come to disagree.
func sortDependents(out []dependentResult) {
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
	WalkSelection walkSelectionJSON `json:"walk_selection"`
	Target        string            `json:"target"`
	// TargetVersions are the versions of the target path this answer covers,
	// present only where the question named none. A machine consumer cannot infer
	// the scope of a bare-path answer from the rows, and the absence is not
	// ambiguous: no field means one version was named and "target" carries it.
	TargetVersions []string             `json:"target_versions,omitempty"`
	Dependents     []dependentEntryJSON `json:"dependents"`
	// RootScope states what the search left out. It is emitted on every answer,
	// not only when something was withheld: a field that appears only when it
	// would be alarming is one no consumer can rely on reading, and the reader
	// this exists for is the one holding an empty "dependents" and deciding
	// whether the module can be dropped.
	RootScope dependentsRootScopeJSON `json:"root_scope"`
	// PreModulesCaveat is present only when the answer is bounded by a module
	// resolved under pre-modules semantics; absent means no coordinate in scope is
	// one, so an answer that never meets the class marshals exactly as before.
	PreModulesCaveat *preModulesCaveatJSON `json:"pre_modules_caveat,omitempty"`
}

// dependentsRootScopeJSON is the exclusion as data.
//
// Excluded and DependsOnTarget answer different questions and both are needed:
// excluded true with depends_on_target true means an empty "dependents" is NOT
// a confirmed negative — something in the build uses the target, and it is the
// walk root. IncludeFlag names the flag that puts it back, so a consumer can act
// on the fact without knowing the command's flag set.
type dependentsRootScopeJSON struct {
	Root            string `json:"root"`
	Excluded        bool   `json:"excluded"`
	DependsOnTarget bool   `json:"depends_on_target"`
	IncludeFlag     string `json:"include_flag"`
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
	targetVersions []string,
	deps []dependentResult,
	rootScope dependentsRootScope,
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
		WalkID:         walkID,
		WalkFrame:      walkFrame.Text,
		WalkFrameBasis: string(walkFrame.Basis),
		WalkSelection:  selection,
		Target:         target,
		TargetVersions: targetVersions,
		Dependents:     entries,
		RootScope: dependentsRootScopeJSON{
			Root:            rootScope.Root.String(),
			Excluded:        rootScope.Excluded,
			DependsOnTarget: rootScope.DependsOnTarget,
			IncludeFlag:     dependentsIncludeRootFlag,
		},
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
	// dependentsIncludeRootFlag is the flag that puts the walk root back in
	// scope. Named once, so the text suffix and the JSON field cannot come to
	// offer different remedies.
	dependentsIncludeRootFlag = "--include-root"
	// rootDependsSuffix is used when the root itself depends on the target and
	// was dropped: the answer names the omission and the flag that reverses it.
	rootDependsSuffix = " (the walk root does; it is excluded by default — pass " + dependentsIncludeRootFlag + ")"
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
