package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"
	dirdomain "github.com/eitanity/kanonarion/internal/directive/domain"
	dirports "github.com/eitanity/kanonarion/internal/directive/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// licenceRemedyBuild is the build a missing-licence diagnostic is written
// about: the go.mod that declares it, and the modules that go.mod replaces
// with a filesystem path.
//
// A local-replace target's source was never published, so the fetch that
// 'kanonarion license <coord>' begins with can never reach it — naming that
// command for one sends the reader to 'fetch' and leaves them there. Which
// coordinates those are is a fact of the build, not of the coordinate, so it
// has to travel with the question.
//
// The zero value means the build is not known: no go.mod to read, or a walk
// taken from no working tree. A remedy written against it keeps the published
// -dependency form rather than inferring a local replace from a coordinate
// alone, because a confidently wrong instruction is the defect this branch
// exists to remove.
type licenceRemedyBuild struct {
	goModPath     string
	localReplaced map[string]struct{}
	// localSources names, by module path, where a walk read each module it
	// recorded at <path>@local other than its root: a replacement's path as
	// written, or a go.work member's directory. Empty without a walk.
	localSources map[string]string
}

// localSource reports where a dependency read from disk comes from. The
// walk's own record answers first; a go.mod replace answers when there is no
// walk to read.
func (b licenceRemedyBuild) localSource(coord coordinate.ModuleCoordinate) (string, bool) {
	if src, ok := b.localSources[coord.Path()]; ok {
		return src, true
	}
	if b.replacesLocally(coord) {
		return "the local path this build replaces it with", true
	}
	return "", false
}

// licenceRemedyBuildFor reads goModPath through the directive parser — the
// same parse 'kanonarion directives' reports — and keeps the applied replaces
// whose right-hand side is a filesystem path. The directive context already
// records that distinction in a dedicated field, so nothing here re-implements
// it. A go.mod that cannot be read yields the unknown build, never a guess.
func licenceRemedyBuildFor(parser dirports.DirectiveParser, goModPath string) licenceRemedyBuild {
	if parser == nil || goModPath == "" {
		return licenceRemedyBuild{}
	}
	res, err := parser.ParseProject(goModPath)
	if err != nil {
		return licenceRemedyBuild{}
	}
	build := licenceRemedyBuild{goModPath: goModPath, localReplaced: make(map[string]struct{})}
	for _, d := range res.Directives {
		// Applied matters: a go.mod replace a go.work overrides is recorded but
		// does not shape this build, and its target is fetched like any other.
		if d.Kind == dirdomain.KindReplace && d.IsLocal && d.Applied {
			build.localReplaced[d.OldPath] = struct{}{}
		}
	}
	return build
}

// licenceRemedyBuildForWalk names the build a walk was taken from, so a
// diagnostic about that walk's components can pick a remedy that terminates.
//
// A walk of a published coordinate records no project directory, and a working
// tree that has since moved cannot be read: both give the unknown build. The
// directory is provenance, never an oracle, so its absence degrades the message
// rather than failing the command.
func licenceRemedyBuildForWalk(ctx context.Context, ctr *Container, walkID string) licenceRemedyBuild {
	if ctr == nil || ctr.QueryWalks == nil || walkID == "" {
		return licenceRemedyBuild{}
	}
	rec, err := ctr.QueryWalks.GetWalk(ctx, walkID)
	if err != nil || rec.ProjectDir == "" {
		return licenceRemedyBuild{}
	}
	build := licenceRemedyBuildFor(ctr.DirectiveParser, filepath.Join(rec.ProjectDir, "go.mod"))
	if build.goModPath == "" {
		return build
	}
	for _, n := range rec.Graph.Nodes {
		if !n.Coordinate.IsLocal() || n.Coordinate == rec.Graph.Target {
			continue
		}
		if build.localSources == nil {
			build.localSources = map[string]string{}
		}
		switch n.ResolutionSource {
		case walkdomain.ResolutionLocalReplace:
			build.localSources[n.Coordinate.Path()] = "the local path " + n.LocalPath + " this build replaces it with"
		case walkdomain.ResolutionLocalWorkspaceMember:
			build.localSources[n.Coordinate.Path()] = "its directory in the go.work workspace"
		}
	}
	return build
}

// noteWorkspaceMembers records the go.work members a go.mod scope holds, so a
// missing record of one is sent to the walk that reads its directory rather
// than to --analyse-root, which reads only the project's own tree.
func (b *licenceRemedyBuild) noteWorkspaceMembers(mods []scopeModule, gomodPath string) {
	if b.goModPath == "" || gomodPath == "" {
		return
	}
	self, err := readGoModulePath(gomodPath)
	if err != nil {
		return
	}
	for _, m := range mods {
		if !m.coord.IsLocal() || !m.original.IsZero() || m.coord.Path() == self {
			continue
		}
		if b.localSources == nil {
			b.localSources = map[string]string{}
		}
		b.localSources[m.coord.Path()] = "its directory in the go.work workspace"
	}
}

// replacesLocally reports whether this build resolves coord from a local path.
// An unknown build answers false: it has measured nothing, and the caller must
// not read that as a measurement.
func (b licenceRemedyBuild) replacesLocally(coord coordinate.ModuleCoordinate) bool {
	if b.goModPath == "" {
		return false
	}
	_, ok := b.localReplaced[coord.Path()]
	return ok
}

// missingLicenceRecordRemedy names the command that produces the licence record
// a coordinate does not have.
//
// One missing record has one fix, so the commands that meet the gap from
// different ends — 'sbom' inventorying a closure, 'license-compat' judging one —
// state it from here instead of each phrasing its own. The split is on where
// the component's source is, not on the caller: the local main module is
// unpublished, so its own licence comes from re-walking the project with
// --analyse-root; a module the build replaces with a local path is unpublished
// too and comes from a project walk, which reads it from disk; every other
// component is a published module that is analysed by coordinate.
func missingLicenceRecordRemedy(coord coordinate.ModuleCoordinate, build licenceRemedyBuild) string {
	// A dependency read from disk is analysed by the walk that reads its
	// directory, never by re-walking the root with --analyse-root.
	if source, ok := build.localSource(coord); ok {
		return fmt.Sprintf("run 'kanonarion walk --gomod %s%s' then "+
			"'kanonarion extract <walk-id>' to analyse %s@%s from %s",
			build.goModPath, targetFlagHint(), coord.Path(), coordinate.LocalVersion, source)
	}
	if coord.IsLocal() {
		// The declaration this run was made under rides along, so the walk the
		// reader is told to take is a walk of the platform they asked about
		// rather than of this host.
		return "run 'kanonarion walk --gomod ./go.mod --analyse-root" + targetFlagHint() + "' then " +
			"'kanonarion extract <walk-id>' to analyse the project's own licence"
	}
	return fmt.Sprintf("run 'kanonarion license %s'", coord)
}

// missingLicenceRecordRemedies states the fix for a SET of coordinates with no
// licence record — one sentence per kind of missing record, because the root's
// own licence, a local-replace target's and a published dependency's are
// produced by different commands and a message that always named one of them
// would send most of its readers to the wrong one.
//
// Within a kind the coordinates share a remedy that differs only in the
// coordinate, so one is spelled out and the rest are counted: the components
// themselves are already named in the message this joins.
func missingLicenceRecordRemedies(coords []coordinate.ModuleCoordinate, build licenceRemedyBuild) string {
	var parts []string
	var firstLocal, firstDep coordinate.ModuleCoordinate
	root := false
	locals, deps := 0, 0
	for _, c := range coords {
		_, fromDisk := build.localSource(c)
		switch {
		case fromDisk:
			if locals == 0 {
				firstLocal = c
			}
			locals++
		case c.IsLocal():
			if !root {
				root = true
				parts = append(parts, missingLicenceRecordRemedy(c, build))
			}
		default:
			if deps == 0 {
				firstDep = c
			}
			deps++
		}
	}
	// One project walk reads every local-replace target the build has,
	// so the others are covered by the run already named rather than by a
	// repeat of it.
	if locals > 0 {
		local := missingLicenceRecordRemedy(firstLocal, build)
		if locals > 1 {
			local += fmt.Sprintf(", and the same run covers the other %d component(s) named that are read from disk", locals-1)
		}
		parts = append(parts, local)
	}
	if deps > 0 {
		dep := missingLicenceRecordRemedy(firstDep, build)
		if deps > 1 {
			dep += fmt.Sprintf(", and the same for the other %d component(s) named", deps-1)
		}
		parts = append(parts, dep)
	}
	return strings.Join(parts, "; ")
}
