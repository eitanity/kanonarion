package domain

import (
	"sort"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// AnalysisInputs carries what an analysis was offered BEYOND the artefact
// itself: the resolved build list of the walk that asked for it.
//
// It exists because a module published before Go modules ships no go.mod, and a
// synthesised one with no require list can only be honest for a module that
// imports nothing outside the standard library. The versions that make the
// others analysable are not discoverable from the artefact — they are a property
// of the build that wants the answer, and kanonarion already holds it.
//
// The zero value is a request that offers nothing, which is what a coordinate
// asked about on its own means. Synthesis then refuses exactly as it did before
// this type existed.
type AnalysisInputs struct {
	// BuildList is the requesting walk's resolved version set: one coordinate per
	// module the build selected. It is read, never written.
	BuildList map[coordinate.ModuleCoordinate]struct{}
	// Source names the walk the build list was read from, so a record can say
	// which build pinned it rather than merely that something did. It is
	// provenance: two walks resolving the same versions produce the same graph.
	Source string
}

// HasBuildList reports whether these inputs can pin anything at all.
func (i AnalysisInputs) HasBuildList() bool { return len(i.BuildList) > 0 }

// PinRequires resolves each of a module's third-party imports to a require
// directive taken from the build list, and reports the imports it could not.
//
// Nothing is guessed. An import no build-list entry provides is returned as
// unpinned, and the caller refuses synthesis on it: a go.mod that names some
// imports and silently omits others sends the loader looking for the rest at
// whatever is latest, which is the outcome refusing exists to prevent.
//
// A path may appear at more than one version — a replaced node is recorded
// alongside the coordinate it stands in for — but go.mod admits one require per
// path, so the highest wins, which is what minimal version selection would
// itself resolve. Ordering is by path so the file written, and therefore the
// graph, is deterministic.
func PinRequires(
	coord coordinate.ModuleCoordinate,
	imports []string,
	inputs AnalysisInputs,
) (pinned []SynthesisedRequire, unpinned []string) {
	candidates := candidateVersions(coord, inputs.BuildList)

	selected := make(map[string]string, len(imports))
	for _, imp := range imports {
		path, ok := providingModulePath(imp, candidates)
		if !ok {
			unpinned = append(unpinned, imp)
			continue
		}
		selected[path] = candidates[path]
	}
	sort.Strings(unpinned)
	if len(unpinned) > 0 {
		// Partial pinning is not a partial answer, it is a wrong one. Returning no
		// requires alongside the unpinned imports keeps the caller from writing a
		// file that resolves half the graph against chosen versions and the other
		// half against whatever the proxy serves today.
		return nil, unpinned
	}

	pinned = make([]SynthesisedRequire, 0, len(selected))
	for path, version := range selected {
		pinned = append(pinned, SynthesisedRequire{Path: path, Version: version})
	}
	sort.Slice(pinned, func(i, j int) bool { return pinned[i].Path < pinned[j].Path })
	return pinned, nil
}

// candidateVersions reduces a build list to one version per module path, dropping
// the three kinds of coordinate a go.mod cannot express: the module itself, an
// unpublished local working tree, and anything missing a path or a version.
func candidateVersions(
	coord coordinate.ModuleCoordinate,
	buildList map[coordinate.ModuleCoordinate]struct{},
) map[string]string {
	candidates := make(map[string]string, len(buildList))
	for c := range buildList {
		switch {
		case c.Path() == coord.Path(), c.IsLocal(), c.Path() == "", c.Version() == "":
			continue
		}
		if prev, ok := candidates[c.Path()]; !ok || semver.Compare(c.Version(), prev) > 0 {
			candidates[c.Path()] = c.Version()
		}
	}
	return candidates
}

// providingModulePath finds the build-list module that provides an imported
// package.
//
// A package path is its module path plus an optional subdirectory, and neither is
// recoverable from the string alone, so the longest matching module path wins:
// "github.com/gorilla/css/scanner" is provided by "github.com/gorilla/css" rather
// than by a hypothetical "github.com/gorilla". Matching is on whole path elements
// so "example.com/mod-extra" is never taken for "example.com/mod".
func providingModulePath(importPath string, candidates map[string]string) (string, bool) {
	best := ""
	// Map order cannot reach the answer: two distinct keys of the same length
	// cannot both be a prefix of one path, so the longest match is unique and
	// `len > len(best)` never ties.
	for path := range candidates {
		if importPath != path && !strings.HasPrefix(importPath, path+"/") {
			continue
		}
		if len(path) > len(best) {
			best = path
		}
	}
	return best, best != ""
}

// PinnedAnalysisSupersedes reports whether a cached record must NOT be served
// back to a request that carries a resolved build list.
//
// Two cases, and only two, so the ordinary cache path is untouched:
//
// A FAILED record that was never offered a build list may be the pre-feature
// generation of a pre-modules module whose synthesis was refused for want of
// require directives. That refusal is now answerable, and serving the old failure
// back would make it permanent — the exact outcome the failure-cause axis was
// kept off the refusal path to avoid. It happens at most once per module: the
// re-analysis records which build list it was offered, so a third request is
// served from cache whether or not the second one succeeded.
//
// A record whose requires were pinned from a DIFFERENT build list answers a
// different question: the graph it describes was built against versions this
// walk did not select. Re-analysis appends a second generation; nothing is
// overwritten, and composition decides which one answers.
//
// Everything else — every record that produced a graph, every module excluded by
// config, every request that carries no build list — is served exactly as before.
func PinnedAnalysisSupersedes(existing CallGraphRecord, inputs AnalysisInputs) bool {
	if !inputs.HasBuildList() || inputs.Source == "" {
		return false
	}
	if existing.BuildListSource == inputs.Source {
		return false
	}
	if len(existing.SynthesisedGoMod.Requires) > 0 {
		return true
	}
	return existing.BuildListSource == "" && RecordIsFailure(existing)
}
