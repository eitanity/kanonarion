package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/eitanity/kanonarion/internal/coordinate"
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
	// gomodSet distinguishes "--gomod was not passed" from "--gomod was passed
	// with no value", which means the working tree's ./go.mod. The flag's string
	// value cannot carry that difference, so it is read from cobra at run time.
	gomodSet bool
}

// defaultGoModPath is what a valueless --gomod means: the working tree's own
// go.mod.
const defaultGoModPath = "./go.mod"

// registerBuildScopeFlags adds --walk-id and --gomod to a query command.
func registerBuildScopeFlags(cmd *cobra.Command, f *buildScopeFlags) {
	cmd.Flags().StringVar(&f.walkID, "walk-id", "",
		"restrict results to the resolved version set of this walk")
	cmd.Flags().StringVar(&f.gomod, "gomod", "",
		"restrict results to the latest project walk for this go.mod (default: ./go.mod)")
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
	// source names the build for diagnostics, e.g. `walk "abc123"`. Empty when
	// no build was named and modules is unrestricted.
	source string
}

// resolve turns the flags into a version set. With neither flag set it returns
// the unrestricted scope, which is the documented default.
func (f buildScopeFlags) resolve(ctx context.Context, walks QueryWalksUseCase) (buildScope, error) {
	if f.walkID != "" && f.gomodSet {
		return buildScope{}, fmt.Errorf("--walk-id and --gomod are mutually exclusive: both name a build, and they may name different ones")
	}
	if !f.requested() {
		return buildScope{}, nil
	}

	walkID := f.walkID
	if f.gomodSet {
		resolved, err := latestWalkForGoMod(ctx, walks, f.gomod)
		if err != nil {
			return buildScope{}, err
		}
		walkID = resolved
	}

	rec, err := walks.GetWalk(ctx, walkID)
	if err != nil {
		return buildScope{}, fmt.Errorf("loading walk %q: %w", walkID, err)
	}
	return buildScope{modules: walkModuleSet(rec), source: fmt.Sprintf("walk %q", walkID)}, nil
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
		"notice: results restricted to the %d module versions resolved by %s\n",
		sc.modules.Len(), sc.source); err != nil {
		return fmt.Errorf("writing scope notice: %w", err)
	}
	return nil
}

// latestWalkForGoMod returns the ID of the most recent succeeded project walk
// rooted at the module declared in gomod (or ./go.mod when gomod is empty).
func latestWalkForGoMod(ctx context.Context, walks QueryWalksUseCase, gomod string) (string, error) {
	gomodPath, err := resolveGoModPath(gomod)
	if err != nil {
		return "", err
	}
	modulePath, err := readGoModulePath(gomodPath)
	if err != nil {
		return "", err
	}
	coord, err := coordinate.NewLocalCoordinate(modulePath)
	if err != nil {
		return "", fmt.Errorf("building project coordinate for %s: %w", modulePath, err)
	}
	succeeded := walkdomain.WalkSucceeded
	summaries, err := walks.ListWalks(ctx, walkports.WalkFilter{
		Target:        &coord,
		OverallStatus: &succeeded,
		Limit:         1,
	})
	if err != nil {
		return "", fmt.Errorf("listing project walks for %s: %w", modulePath, err)
	}
	if len(summaries) == 0 {
		return "", fmt.Errorf("no succeeded project walk for %s — run: kanonarion walk --gomod %s", modulePath, gomodPath)
	}
	return summaries[0].ID, nil
}

// walkModuleSet is the version set of the build a walk recorded: every module in
// its dependency graph, plus the target itself.
//
// The main module and any local-path replace target appear in the walk at
// coordinate.LocalVersion, because nothing published them and there is no
// version to name. Their call graphs, however, are ingested by `kanonarion
// local` under localCallGraphVersion. Those are the same module under two
// synthetic names, so both are admitted — otherwise scoping a query to a
// project's own build would filter out the project's own symbols, which is the
// case the filter exists to serve.
func walkModuleSet(rec walkdomain.WalkRecord) coordinate.ModuleSet {
	coords := make([]coordinate.ModuleCoordinate, 0, len(rec.Graph.Nodes)+2)
	admit := func(c coordinate.ModuleCoordinate) {
		if c.IsZero() {
			return
		}
		coords = append(coords, c)
		if c.Version() != coordinate.LocalVersion {
			return
		}
		if local, err := coordinate.NewModuleCoordinate(c.Path(), localCallGraphVersion); err == nil {
			coords = append(coords, local)
		}
	}

	admit(rec.Target)
	for _, n := range rec.Graph.Nodes {
		admit(n.Coordinate)
	}
	return coordinate.NewModuleSet(coords)
}
