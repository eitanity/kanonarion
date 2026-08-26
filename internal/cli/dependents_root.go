package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// resolveDependentsRoot returns the walk a `dependents` question is answered in,
// and the containment that says how it was reached.
//
// What a coordinate is surrounded by is a property of one build, so the build is
// part of the question. The root is taken in the order a caller states it:
// --walk-id names a record, --gomod names a manifest, and standing in a project
// names its go.mod. Only --any-build reaches the store-wide containment search,
// which is a different question — "which of my projects uses this" — and is
// nobody's default.
//
// Where none of the three is available the read refuses. It does not fall back
// to the search: a fallback picks a build the caller never named and reports it
// at exit 0, which is the whole of what this rooting exists to stop.
func resolveDependentsRoot(
	ctx context.Context,
	walks QueryWalksUseCase,
	coord coordinate.ModuleCoordinate,
	f dependentsFlags,
	stderr io.Writer,
) (walkContainment, walkdomain.WalkRecord, error) {
	switch {
	case f.walkID != "":
		if err := refuseInapplicableFlags("dependents --walk-id", dependentsRootFlags(f)); err != nil {
			return walkContainment{}, walkdomain.WalkRecord{}, err
		}
		rec, err := getDependentsWalk(ctx, walks, f.walkID, stderr)
		if err != nil {
			return walkContainment{}, walkdomain.WalkRecord{}, err
		}
		return pinnedContainment(rec), rec, nil

	case f.anyBuild:
		if err := refuseInapplicableFlags("dependents --any-build", dependentsScopeFlags(f)); err != nil {
			return walkContainment{}, walkdomain.WalkRecord{}, err
		}
		found, err := findWalkContaining(ctx, walks, coord,
			fmt.Sprintf("kanonarion dependents %s --walk-id <walk of that build>", coord))
		if err != nil {
			return walkContainment{}, walkdomain.WalkRecord{}, err
		}
		rec, err := getDependentsWalk(ctx, walks, found.walkID, stderr)
		if err != nil {
			return walkContainment{}, walkdomain.WalkRecord{}, err
		}
		return found, rec, nil
	}

	scope, err := scopeFromFlags(f.tool, f.project)
	if err != nil {
		return walkContainment{}, walkdomain.WalkRecord{}, err
	}
	gomodPath, err := resolveGoModPath(f.gomod)
	if err != nil {
		// It fails on exactly one condition: nothing was passed and the working
		// directory has no manifest. That is the question with no build at all, and
		// it gets the refusal that names every way to give it one rather than a
		// sentence about a missing file.
		return walkContainment{}, walkdomain.WalkRecord{}, noDependentsRoot(coord)
	}
	choice, err := latestWalkForGoMod(ctx, walks, gomodPath, scope)
	if err != nil {
		return walkContainment{}, walkdomain.WalkRecord{}, err
	}
	rec, err := choice.walkRecord(ctx, walks)
	if err != nil {
		return walkContainment{}, walkdomain.WalkRecord{}, err
	}
	containment := gomodContainment(choice, rec, scope)
	if !graphHolds(rec.Graph, coord) {
		return walkContainment{}, walkdomain.WalkRecord{},
			buildLacksModule(ctx, walks, rec, coord, containment.build, gomodPath)
	}
	return containment, rec, nil
}

// getDependentsWalk loads a walk record, translating the two failures a caller
// can act on into the answers they already have elsewhere: a named record that
// is not there, and a record whose seal does not verify.
func getDependentsWalk(ctx context.Context, walks QueryWalksUseCase, walkID string, stderr io.Writer) (walkdomain.WalkRecord, error) {
	rec, err := walks.GetWalk(ctx, walkID)
	if err == nil {
		return rec, nil
	}
	if isWalkNotFound(err) {
		return walkdomain.WalkRecord{}, walkIDMiss(ctx, walks, walkID, stderr)
	}
	if isWalkIntegrity(err) {
		return walkdomain.WalkRecord{}, &exitError{code: ExitIntegrity,
			msg: fmt.Sprintf("walk record %q failed integrity check", walkID)}
	}
	return walkdomain.WalkRecord{}, fmt.Errorf("getting walk: %w", err)
}

// noDependentsRoot is the refusal for a question that names no build and has no
// working-directory manifest to take one from.
//
// It names all three ways to give one, --any-build included, because a caller
// standing outside a project may genuinely want the search — and a refusal that
// hides the flag which answers it teaches the reader the question is
// unanswerable.
func noDependentsRoot(coord coordinate.ModuleCoordinate) error {
	return &exitError{code: ExitConfig, msg: fmt.Sprintf(
		"what a coordinate is surrounded by is a property of one build, and this question names none: "+
			"no --walk-id, no --gomod, and no go.mod in the working directory. Name the build you mean:"+
			"\n  --gomod %s    answer from the latest project walk for that go.mod (add --tool or --project for another scope)"+
			"\n  --walk-id <id>      answer from one stored walk (kanonarion walk-list lists them)"+
			"\n  --any-build         search this store for a build that holds %s",
		defaultGoModPath, coord)}
}

// buildLacksModule is the refusal for a rooted question whose build does not
// hold the coordinate.
//
// It is a refusal rather than an empty answer because "no modules depend on X"
// and "X is not in this build" are different facts, and only the first is a
// measurement. It costs one listing of the project's other builds to say which
// of them does hold the coordinate — paid on this path only — because the scope
// is the axis the caller most often has wrong: a linter is in the tool closure
// and not in the code walk, and the remedy is a flag, not another command.
//
// A version the build resolved differently is named for the same reason. Asked
// about v0.9.0 of a module the build pins at v0.9.1, the caller wants the
// version, not the news that the coordinate is absent.
func buildLacksModule(
	ctx context.Context,
	walks QueryWalksUseCase,
	rec walkdomain.WalkRecord,
	coord coordinate.ModuleCoordinate,
	build, gomodPath string,
) error {
	msg := fmt.Sprintf("%s, rooted at %s, does not contain %s", build, rec.Target, coord)
	if versions := graphVersionsOf(rec.Graph, coord.Path()); len(versions) > 0 {
		msg += fmt.Sprintf("; it resolved %s at %s", coord.Path(), strings.Join(versions, ", "))
	}
	holding := buildsHolding(ctx, walks, rec, coord)
	switch {
	case len(holding) > 0:
		msg += fmt.Sprintf("; the store holds it in the %s of %s — ask there:\n  kanonarion dependents %s --gomod %s%s",
			joinHoldingBuilds(holding), rec.Target, coord, gomodPath, holding[0].flag)
	default:
		msg += fmt.Sprintf("; no current build of %s holds it either — the newest walk of each scope and "+
			"platform was checked, and an older one still may, so search them all with:"+
			"\n  kanonarion dependents %s --any-build", rec.Target, coord)
	}
	return &exitError{code: ExitConfig, msg: msg}
}

// holdingBuild is one build of the project that does hold the coordinate the
// rooted build lacks, named the way a caller has to ask for it.
type holdingBuild struct {
	// label is "<scope> on <platform>", the same terms describeWalkBuilds uses.
	label string
	// flag is the scope flag that selects it, empty for the code scope.
	flag   string
	walkID string
	// rank orders the builds by how much each holds, narrowest first.
	rank int
}

// buildsHolding returns the project's other builds whose CURRENT walk holds
// coord, one per distinct scope-and-platform.
//
// The newest walk of each build is the one a rooted read would answer from, so
// it is the only one worth reading: naming a build whose current walk no longer
// holds the coordinate would send the caller to a flag that refuses in turn.
// That bounds the record reads to the number of builds the project has, which is
// three scopes times the platforms it was walked on.
func buildsHolding(ctx context.Context, walks QueryWalksUseCase, rec walkdomain.WalkRecord, coord coordinate.ModuleCoordinate) []holdingBuild {
	target := rec.Target
	succeeded := walkdomain.WalkSucceeded
	summaries, err := walks.ListWalks(ctx, walkports.WalkFilter{Target: &target, OverallStatus: &succeeded})
	if err != nil {
		return nil
	}
	seen := map[string]struct{}{
		buildKey(rec.Scope, rec.Graph.BuildEnv.GOOS, rec.Graph.BuildEnv.GOARCH): {},
	}
	var out []holdingBuild
	for _, s := range summaries {
		key := buildKey(s.Scope, s.GOOS, s.GOARCH)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		other, gerr := walks.GetWalk(ctx, s.ID)
		if gerr != nil || !graphHolds(other.Graph, coord) {
			continue
		}
		out = append(out, holdingBuild{
			label:  fmt.Sprintf("%s on %s", walkScopeLabel(s.Scope), walkports.BuildEnvFilter{GOOS: s.GOOS, GOARCH: s.GOARCH}),
			flag:   scopeWalkFlagHint(depScope(s.Scope)),
			walkID: s.ID,
			rank:   scopeBreadth(s.Scope),
		})
	}
	// Narrowest scope first, so the remedy the refusal offers is the smallest
	// build that answers. The complete scope is code plus tooling, so it holds
	// every module either of the others does and would otherwise be offered for
	// every miss by alphabet alone.
	sort.Slice(out, func(i, j int) bool {
		if out[i].rank != out[j].rank {
			return out[i].rank < out[j].rank
		}
		return out[i].label < out[j].label
	})
	return out
}

// scopeBreadth ranks a walk scope by how much it holds, for a refusal choosing
// which build to send the caller to. An unrecorded scope sorts last: it is not
// known to be narrow.
func scopeBreadth(scope walkdomain.WalkScope) int {
	switch depScope(scope) {
	case scopeCode:
		return 0
	case scopeTool:
		return 1
	case scopeComplete:
		return 2
	default:
		return 3
	}
}

// buildKey identifies one build of a project: a scope resolved for a platform.
func buildKey(scope walkdomain.WalkScope, goos, goarch string) string {
	return string(scope) + "|" + goos + "/" + goarch
}

// joinHoldingBuilds renders the builds that hold the coordinate, each with the
// walk that would answer for it.
func joinHoldingBuilds(builds []holdingBuild) string {
	parts := make([]string, 0, len(builds))
	for _, b := range builds {
		parts = append(parts, fmt.Sprintf("%s (walk %s)", b.label, b.walkID))
	}
	return strings.Join(parts, " and ")
}

// graphVersionsOf returns the versions of path the graph resolved, sorted. It is
// what turns "this build does not contain module@version" into the version the
// build actually pins.
func graphVersionsOf(g walkdomain.Graph, path string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, n := range g.Nodes {
		if n.Coordinate.Path() != path {
			continue
		}
		if _, ok := seen[n.Coordinate.Version()]; ok {
			continue
		}
		seen[n.Coordinate.Version()] = struct{}{}
		out = append(out, n.Coordinate.Version())
	}
	sort.Strings(out)
	return out
}
