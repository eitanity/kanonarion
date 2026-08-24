package cli

import (
	"context"
	"fmt"
	"io"

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
		"restrict results to the latest project walk for this go.mod; takes a path, e.g. --gomod "+defaultGoModPath)
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
	// source names the build for diagnostics, e.g. `walk "abc123" (frame
	// linux/amd64)`. Empty when no build was named and modules is unrestricted.
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
		choice, err := latestWalkForGoMod(ctx, walks, f.gomod)
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
	// The frame comes off the record, not the summary, so a scope named by
	// --walk-id states it too: both routes end at the same walk, and the notice
	// must not say more for one than the other.
	return buildScope{
		modules:   walkModuleSet(rec),
		source:    fmt.Sprintf("walk %q (frame %s)", walkID, rec.Graph.Frame()),
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

// latestWalkForGoMod returns the succeeded project walk a read defaults to for
// the module declared in gomod (or ./go.mod when gomod is empty), together with
// the manifest path it resolved and the rule that picked the walk.
//
// The whole choice is returned rather than the ID alone because a scope derived
// from this walk has to be able to say which platform's build it pins — the
// lookup has no build-environment axis — and, where the store held more than
// one candidate, which of them answered and why.
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
func latestWalkForGoMod(ctx context.Context, walks QueryWalksUseCase, gomod string) (walkChoice, error) {
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
	summaries, err := walks.ListWalks(ctx, walkports.WalkFilter{
		Target:        &coord,
		OverallStatus: &succeeded,
	})
	if err != nil {
		return walkChoice{manifestPath: gomodPath}, fmt.Errorf("listing project walks for %s: %w", modulePath, err)
	}
	if len(summaries) == 0 {
		return walkChoice{manifestPath: gomodPath}, fmt.Errorf("no succeeded project walk for %s — run: kanonarion walk --gomod %s", modulePath, gomodPath)
	}
	return chooseWalk(ctx, walks, summaries, gomodPath), nil
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
