package domain

import (
	"sort"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// SynthesiseGoMod renders the go.mod that lets a module published before Go
// modules be analysed from source.
//
// govulncheck refuses source analysis when the directory it is pointed at has
// no go.mod. That is a precondition on the scan directory, not a property of
// the artefact: the check runs before any package loading, and the tool's own
// diagnostic directs the caller to create one. A module zip published before Go
// modules will never contain a go.mod — the zip is immutable and
// checksum-verified — so the file is supplied in the scratch directory the scan
// already extracted into, leaving the artefact untouched.
//
// The require set is the project's own build list, so the isolated scan
// resolves the versions the project actually selected. It is deliberately not
// derived by tidying: resolving requirements from the network would analyse a
// dependency graph the project never built, which is the outcome
// UnscanReasonVersionNotInToolchain exists to name.
//
// goVersion is the language version to declare, with or without its "go"
// prefix; when empty the directive is omitted rather than guessed, since a
// wrong language version silently changes which files build constraints select.
//
// imports are the package paths the module's own source imports. Only build
// list entries providing one of them are required. Requiring the whole build
// list instead would make every synthesised scan depend on the entire graph
// resolving: the toolchain reads each requirement's go.mod and runs MVS across
// all of them, so one unrelated module demanding a version the store does not
// hold fails a module that never referenced it.
func SynthesiseGoMod(coord coordinate.ModuleCoordinate, goVersion string, imports []string, buildList map[coordinate.ModuleCoordinate]struct{}) string {
	var b strings.Builder
	b.WriteString("module " + coord.Path + "\n")
	if v := strings.TrimPrefix(strings.TrimSpace(goVersion), "go"); v != "" {
		b.WriteString("\ngo " + v + "\n")
	}
	if reqs := goModRequires(coord, imports, buildList); len(reqs) > 0 {
		b.WriteString("\nrequire (\n")
		for _, r := range reqs {
			b.WriteString("\t" + r.Path + " " + r.Version + "\n")
		}
		b.WriteString(")\n")
	}
	return b.String()
}

// goModRequires selects and orders the build-list entries that provide one of
// the module's imports.
//
// Three kinds of coordinate are excluded because go.mod cannot express them: a
// module never requires itself; the standard library is govulncheck's
// pseudo-module rather than a fetchable one; and a local coordinate names an
// unpublished working tree with no resolvable version.
//
// An import satisfied by no build-list entry contributes no require. That is
// not silent: the package importing it cannot compile, and the toolchain names
// it, which is the truthful outcome — the project's build never selected a
// module providing it, so there is no version to pin it to.
//
// A path may appear at more than one version — the build list records the
// coordinate a replaced node stands in for alongside the node itself — but
// go.mod admits one require per path. The highest version wins, which is the
// version minimal version selection would itself resolve. Ordering is by path
// so the rendered file, and therefore the scan environment, is deterministic.
func goModRequires(coord coordinate.ModuleCoordinate, imports []string, buildList map[coordinate.ModuleCoordinate]struct{}) []coordinate.ModuleCoordinate {
	candidates := make(map[string]string, len(buildList))
	for c := range buildList {
		switch {
		case c.Path == coord.Path:
			continue
		case c.Path == StdlibModulePath:
			continue
		case c.IsLocal():
			continue
		case c.Path == "" || c.Version == "":
			continue
		}
		if prev, ok := candidates[c.Path]; !ok || semver.Compare(c.Version, prev) > 0 {
			candidates[c.Path] = c.Version
		}
	}
	selected := make(map[string]string, len(imports))
	for _, imp := range imports {
		if path, ok := providingModule(imp, candidates); ok {
			selected[path] = candidates[path]
		}
	}
	reqs := make([]coordinate.ModuleCoordinate, 0, len(selected))
	for path, version := range selected {
		reqs = append(reqs, coordinate.ModuleCoordinate{Path: path, Version: version})
	}
	sort.Slice(reqs, func(i, j int) bool { return reqs[i].Path < reqs[j].Path })
	return reqs
}

// providingModule finds the build-list module that provides an imported package.
//
// A package path is its module path plus an optional subdirectory, and neither
// is recoverable from the string alone, so the longest matching module path
// wins: "github.com/gorilla/css/scanner" is provided by "github.com/gorilla/css"
// rather than by a hypothetical "github.com/gorilla". Matching is on whole path
// elements so "example.com/mod-extra" is never taken for "example.com/mod".
func providingModule(importPath string, candidates map[string]string) (string, bool) {
	best := ""
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
