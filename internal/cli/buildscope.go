package cli

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// buildScopeFlags carries the two ways a query command can name the build whose
// version set it wants results restricted to.
//
// The call-graph and interface stores accumulate every version of every module
// ever analysed, so a symbol query keyed on the symbol alone answers across all
// of them. That is correct for "where has this ever been called" and wrong for
// "is this called in my build": on a project that resolves one version of a
// dependency, the unfiltered answer includes callers from versions the build
// does not contain, which read as live edges. These flags are how the caller
// says which build it means.
//
// Neither flag set is the default and keeps the historical all-versions
// behaviour, so existing invocations are unchanged.
type buildScopeFlags struct {
	walkID string
	gomod  string
	// gomodSet distinguishes "--gomod was not passed" from "--gomod was passed".
	// A path is always given, so the two cases differ only in whether the caller
	// spelled the flag, which the string value cannot carry: it is read from
	// cobra at run time.
	gomodSet  bool
	toolchain string
}

// defaultGoModPath is the manifest a caller means when they name no other: the
// working tree's own go.mod. It is what --gomod's help text and the docs offer
// as the path to pass, and what resolveGoModPath falls back to.
const defaultGoModPath = "./go.mod"

// registerBuildScopeFlags adds --walk-id and --gomod to a query command.
func registerBuildScopeFlags(cmd *cobra.Command, f *buildScopeFlags) {
	cmd.Flags().StringVar(&f.walkID, "walk-id", "",
		"restrict results to the resolved version set of this walk")
	cmd.Flags().StringVar(&f.gomod, "gomod", "",
		"restrict results to the latest code-scope project walk for this go.mod on this platform; takes a path, e.g. --gomod "+defaultGoModPath)
	// Registered here rather than per command so that every read which resolves a
	// stored call graph by scope can act on a toolchain refusal. A refusal that
	// names a flag the command does not have is a dead end: the reader is told to
	// name a toolchain and has no way to name one.
	cmd.Flags().StringVar(&f.toolchain, "toolchain", "",
		"restrict to graphs built by one Go toolchain, in `go env GOVERSION` form (e.g. go1.26.6)")
}

// bind reads the flag state cobra holds but a string variable cannot express.
// Call it from RunE, where cmd is in hand.
func (f *buildScopeFlags) bind(cmd *cobra.Command) {
	f.gomodSet = cmd.Flags().Changed("gomod")
}

// requested reports whether the caller named a build at all.
func (f buildScopeFlags) requested() bool {
	return f.walkID != "" || f.gomodSet
}

// buildScope is a resolved version set together with the human-readable name of
// where it came from, so a diagnostic can say which build it filtered against
// rather than reporting a bare empty result.
type buildScope struct {
	modules coordinate.ModuleSet
	// source names the build for diagnostics, e.g. `walk "abc123" (code scope,
	// frame linux/amd64)`. Empty when no build was named and modules is
	// unrestricted.
	source string
	// toolchain restricts the read to graphs built by one Go toolchain. The zero
	// value names none and composition groups on its own. It rides on the scope
	// rather than beside it because every helper that resolves a record already
	// carries the scope, and a preference the caller had to thread separately is
	// one the next read path forgets.
	toolchain gotoolchain.Version
	// staleness is the clause the notice appends when the build was named by a
	// manifest rather than by walk id: the walk was found by the module path the
	// manifest declares, and this read did not re-resolve the manifest to check
	// that the walk still describes it. Empty for --walk-id, which names a record
	// directly and has nothing to go stale against.
	staleness string
}

// resolve turns the flags into a version set. With neither flag set it returns
// the unrestricted scope, which is the documented default.
func (f buildScopeFlags) resolve(ctx context.Context, walks QueryWalksUseCase) (buildScope, error) {
	if f.walkID != "" && f.gomodSet {
		return buildScope{}, fmt.Errorf("--walk-id and --gomod are mutually exclusive: both name a build, and they may name different ones")
	}
	if !f.requested() {
		// A toolchain preference is not a build: it narrows WHICH measurement of a
		// module answers, not which versions are in scope, so it stands on its own.
		return buildScope{toolchain: gotoolchain.Version(f.toolchain)}, nil
	}

	walkID := f.walkID
	var staleness string
	if f.gomodSet {
		// These commands register no --tool/--project, so the scope they mean is
		// the one their help text names: the latest project walk for this go.mod,
		// which is what `walk --gomod` produces without a scope flag. Passing it
		// explicitly is what stops a tool- or project-scope walk that happens to be
		// newer from answering a question about the project's own code.
		choice, err := latestWalkForGoMod(ctx, walks, f.gomod, scopeCode)
		if err != nil {
			return buildScope{}, err
		}
		walkID = choice.summary.ID
		staleness = choice.stalenessNote() + choice.statementClause()
	}

	rec, err := walks.GetWalk(ctx, walkID)
	if err != nil {
		return buildScope{}, fmt.Errorf("loading walk %q: %w", walkID, err)
	}
	// The scope and frame come off the record, not the summary, so a build named
	// by --walk-id states them too: both routes end at the same walk, and the
	// notice must not say more for one than the other. The scope is named because
	// a --gomod read now selects on it, and a selection the notice does not
	// mention is one the reader cannot check.
	return buildScope{
		modules:   walkModuleSet(rec),
		source:    fmt.Sprintf("walk %q (%s, frame %s)", walkID, walkScopeLabel(rec.Scope), rec.Graph.Frame()),
		staleness: staleness,
		toolchain: gotoolchain.Version(f.toolchain),
	}, nil
}

// writeScopeNotice prints, in text mode, the build a scoped result was filtered
// against, and how many module versions that build pins.
//
// A filtered list looks exactly like an unfiltered one, so without this the
// output gives the reader no way to tell that rows were withheld — and a shorter
// caller list read as an unfiltered measurement is the same wrong conclusion in
// the other direction. Silent for an unscoped query, which withholds nothing.
func writeScopeNotice(stdout io.Writer, sc buildScope) error {
	if !sc.modules.IsRestricted() {
		return nil
	}
	if _, err := fmt.Fprintf(stdout,
		"notice: results restricted to the %d module versions resolved by %s%s\n",
		sc.modules.Len(), sc.source, sc.staleness); err != nil {
		return fmt.Errorf("writing scope notice: %w", err)
	}
	return nil
}

// latestWalkForGoMod returns the succeeded project walk of the requested scope a
// read defaults to for the module declared in gomod (or ./go.mod when gomod is
// empty), together with the manifest path it resolved and the rule that picked
// the walk.
//
// The scope is part of the question, not a preference. One project is walked in
// several scopes — code, tool, complete — and they are different builds holding
// different modules, so recency across all of them answers whichever was walked
// last. That is how a 22-node code walk came to answer a question about a
// 246-node tool closure, 235 of whose modules the code walk does not contain.
// The platform is pinned for the same reason, in the same terms the walk
// recorded it: a build for another GOOS/GOARCH selects other files.
//
// The toolchain is deliberately NOT pinned here. Two walks under two toolchains
// link different standard libraries, so this selection is not complete — it
// narrows to one scope and one platform, and among those recency still decides
// which toolchain's walk answers. The choice states the toolchain it landed on
// whenever the candidates disagreed (walkChoice.toolchainNote), which is the
// disclosure this read offers in place of a filter.
//
// The whole choice is returned rather than the ID alone because a scope derived
// from this walk has to be able to say which platform's build it pins, and,
// where the store held more than one candidate, which of them answered and why.
//
// The lookup keys on the module path, so it finds walks by the go.mod's NAME.
// Among those it prefers one whose recorded resolution still agrees with the
// manifest's require directives, because recency alone answered from a walk of a
// manifest that had since been restored — and, since walk identity reuses a
// record rather than re-dating it, re-walking the restored tree could not undo
// that. The comparison is a file parse, not a re-resolution through the
// toolchain, so it is bounded and the caller still states what it did not check;
// `vuln-scan --gomod`, which measures rather than reads, pays the full
// re-resolution instead.
func latestWalkForGoMod(ctx context.Context, walks QueryWalksUseCase, gomod string, scope depScope) (walkChoice, error) {
	gomodPath, err := resolveGoModPath(gomod)
	if err != nil {
		return walkChoice{}, err
	}
	modulePath, err := readGoModulePath(gomodPath)
	if err != nil {
		return walkChoice{manifestPath: gomodPath}, err
	}
	coord, err := coordinate.NewLocalCoordinate(modulePath)
	if err != nil {
		return walkChoice{manifestPath: gomodPath}, fmt.Errorf("building project coordinate for %s: %w", modulePath, err)
	}
	succeeded := walkdomain.WalkSucceeded
	walkScope := walkScopeFor(scope)
	// The same `go env` probe the walk resolver runs, in the same directory, so
	// the read asks for the platform in the terms the walk answered in —
	// including any GOOS/GOARCH override in the environment. A failed probe falls
	// back to the host platform, which is the resolver's own fallback.
	platform := currentWalkBuildEnv(ctx, "", filepath.Dir(gomodPath), nil).platform
	summaries, err := walks.ListWalks(ctx, walkports.WalkFilter{
		Target:        &coord,
		Scope:         &walkScope,
		OverallStatus: &succeeded,
		BuildEnv:      &platform,
	})
	if err != nil {
		return walkChoice{manifestPath: gomodPath}, fmt.Errorf("listing %s project walks for %s: %w", scope, modulePath, err)
	}
	if len(summaries) == 0 {
		return walkChoice{manifestPath: gomodPath}, noProjectWalkOfScope(ctx, walks, coord, scope, platform, gomodPath)
	}
	choice := chooseWalk(ctx, walks, summaries, gomodPath)
	choice.candidateSet = fmt.Sprintf("in the %s scope on %s", scope, platform)
	return choice, nil
}

// noProjectWalkOfScope is the refusal for a read that found no walk of the scope
// and platform it asked for, and it distinguishes the two ways that happens.
//
// A project nobody has walked yet and a project walked in another scope are
// different situations with the same symptom, and the reader can act on only one
// of them. So the miss costs a second, unfiltered listing to say which it was —
// paid on the refusal path only, never on the path that answers. The other
// scopes are named rather than served: a walk of another scope describes another
// build, and serving it is the defect this refusal exists to stop.
func noProjectWalkOfScope(
	ctx context.Context,
	walks QueryWalksUseCase,
	coord coordinate.ModuleCoordinate,
	scope depScope,
	platform walkports.BuildEnvFilter,
	gomodPath string,
) error {
	remedy := fmt.Sprintf("run: kanonarion walk --gomod %s%s", gomodPath, scopeWalkFlagHint(scope))
	succeeded := walkdomain.WalkSucceeded
	others, err := walks.ListWalks(ctx, walkports.WalkFilter{Target: &coord, OverallStatus: &succeeded})
	if err != nil || len(others) == 0 {
		return fmt.Errorf("no succeeded project walk for %s — %s", coord.Path(), remedy)
	}
	return fmt.Errorf("no succeeded %s project walk for %s on %s, though the store holds %d succeeded walk(s) of it (%s); a walk of another scope or platform is a different build, so it does not answer here — %s",
		scope, coord.Path(), platform, len(others), describeWalkBuilds(others), remedy)
}

// describeWalkBuilds names the distinct builds a candidate list covers, as
// "<scope> on <platform>", sorted and deduplicated. It is what a refusal shows
// instead of the walk ids: the reader is deciding which walk to take, not which
// record to open.
func describeWalkBuilds(summaries []walkports.WalkSummary) string {
	seen := make(map[string]struct{}, len(summaries))
	out := make([]string, 0, len(summaries))
	for _, s := range summaries {
		scope := string(s.Scope)
		if scope == "" {
			// A walk written before scopes were recorded is listed as such rather
			// than as a blank, which would read as a walk of no scope at all.
			scope = "unrecorded scope"
		}
		build := fmt.Sprintf("%s on %s", scope, walkports.BuildEnvFilter{GOOS: s.GOOS, GOARCH: s.GOARCH})
		if _, ok := seen[build]; ok {
			continue
		}
		seen[build] = struct{}{}
		out = append(out, build)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// walkModuleSet is the version set of the build a walk recorded: every module in
// its dependency graph, plus the target itself.
//
// The main module and any local-path replace target appear in the walk at
// coordinate.LocalVersion, because nothing published them and there is no
// version to name. `kanonarion local` now ingests their call graphs at that same
// version, so one coordinate covers both and no second synthetic name has to be
// admitted alongside it. Before that, a working-tree ingest landed at a
// synthetic "v0.0.0" and this function had to admit the module twice or scoping
// a query to a project's own build would have filtered out the project's own
// symbols — the case the filter exists to serve.
func walkModuleSet(rec walkdomain.WalkRecord) coordinate.ModuleSet {
	coords := make([]coordinate.ModuleCoordinate, 0, len(rec.Graph.Nodes)+1)
	admit := func(c coordinate.ModuleCoordinate) {
		if c.IsZero() {
			return
		}
		coords = append(coords, c)
	}

	admit(rec.Target)
	for _, n := range rec.Graph.Nodes {
		admit(n.Coordinate)
	}
	return coordinate.NewModuleSet(coords)
}
