package cli

import (
	"fmt"
	"strings"
)

// inapplicableFlag names a flag that was set on a dispatch path which cannot
// act on it, together with the path that can.
type inapplicableFlag struct {
	flag  string // as the caller typed it
	where string // the path that does honour it
}

// refuseInapplicableFlags reports flags set on a path that does not read them,
// naming both the path that ignored the flag and the path that would honour it.
//
// A command registers its flags once and dispatches to one of several
// path-specific run functions. A flag only some of those paths can act on is
// still parsed on all of them, so accepting it elsewhere and emitting
// byte-identical output tells the caller nothing: the question was discarded
// with exit 0, and no output difference remains to notice. Refusing turns a
// silent discard into an answer the caller can act on.
func refuseInapplicableFlags(path string, flags []inapplicableFlag) error {
	if len(flags) == 0 {
		return nil
	}
	parts := make([]string, 0, len(flags))
	for _, f := range flags {
		parts = append(parts, fmt.Sprintf("%s (applies to %s)", f.flag, f.where))
	}
	return fmt.Errorf("%s does not act on %s", path, strings.Join(parts, "; "))
}

// fetchGoModOnlyFlags returns the fetch flags that only a go.mod scope fetch
// can act on, for whichever of them the caller set. A positional fetch names
// its own module, so there is no scope for them to project.
func fetchGoModOnlyFlags(f fetchFlags) []inapplicableFlag {
	const where = "fetch --gomod"
	var out []inapplicableFlag
	if f.gomod != "" {
		out = append(out, inapplicableFlag{flag: "--gomod", where: where})
	}
	if f.tool {
		out = append(out, inapplicableFlag{flag: "--tool", where: where})
	}
	if f.project {
		out = append(out, inapplicableFlag{flag: "--project", where: where})
	}
	return out
}

// inspectGoModOnlyFlags returns the inspect flags that only a go.mod scan can
// act on, for whichever of them the caller set.
func inspectGoModOnlyFlags(f inspectFlags) []inapplicableFlag {
	const where = "inspect --gomod"
	var out []inapplicableFlag
	if f.gomodPath != "" {
		out = append(out, inapplicableFlag{flag: "--gomod", where: where})
	}
	if f.tool {
		out = append(out, inapplicableFlag{flag: "--tool", where: where})
	}
	if f.project {
		out = append(out, inapplicableFlag{flag: "--project", where: where})
	}
	return out
}

// vulnScanGoModScopeFlags returns the vuln-scan flags that only a go.mod scope
// scan can act on, for whichever of them the caller set. Setting any of them is
// what selects that path, so the two other paths never see one set; they are
// named here so a change of dispatch cannot turn a scope flag into a silent
// no-op on the path it lands on.
func vulnScanGoModScopeFlags(f vulnScanFlags) []inapplicableFlag {
	const where = "vuln-scan --gomod/--tool/--project"
	var out []inapplicableFlag
	if f.gomod != "" {
		out = append(out, inapplicableFlag{flag: "--gomod", where: where})
	}
	if f.tool {
		out = append(out, inapplicableFlag{flag: "--tool", where: where})
	}
	if f.project {
		out = append(out, inapplicableFlag{flag: "--project", where: where})
	}
	return out
}

// vulnScanModuleFlag returns --module when the caller set it. Only the module
// path resolves a coordinate to the walk rooted at it.
func vulnScanModuleFlag(f vulnScanFlags) []inapplicableFlag {
	if f.moduleCoord == "" {
		return nil
	}
	return []inapplicableFlag{{flag: "--module", where: "vuln-scan --module"}}
}

// binaryPrePassFlag returns --binary-pre-pass when the caller set it. Only a
// scan of a named walk carries the pre-pass into the scan request.
func binaryPrePassFlag(set bool) []inapplicableFlag {
	if !set {
		return nil
	}
	return []inapplicableFlag{{flag: "--binary-pre-pass", where: "vuln-scan <walk-id>"}}
}

// walkGoModOnlyFlags returns the walk flags that only a go.mod walk can act on,
// for whichever of them the caller set. --stdlib-from-gomod reads a toolchain
// directive out of a project go.mod, --analyse-local resolves local-replace
// targets relative to one, and --from-modcache verifies the carried-in cache
// bytes against the go.sum beside one; a positional walk has none of them.
func walkGoModOnlyFlags(f walkFlags) []inapplicableFlag {
	const where = "walk --gomod"
	var out []inapplicableFlag
	if f.gomodPath != "" {
		out = append(out, inapplicableFlag{flag: "--gomod", where: where})
	}
	if f.analyseLocal {
		out = append(out, inapplicableFlag{flag: "--analyse-local", where: where})
	}
	if f.stdlibFromGoMod {
		out = append(out, inapplicableFlag{flag: "--stdlib-from-gomod", where: where})
	}
	if f.fromModcache != "" {
		// Named with its reason: under --from-modcache go.sum is the sole anchor
		// for the bytes read out of the cache, and a published coordinate walk
		// has no project go.sum to check them against.
		out = append(out, inapplicableFlag{
			flag:  "--from-modcache",
			where: "walk --gomod, which has the project go.sum the cache is verified against; a published coordinate has none",
		})
	}
	return out
}

// contextWalkOnlyFlags returns the context flags that only the --walk-id path
// can act on, for whichever of them the caller set.
func contextWalkOnlyFlags(f contextFlags) []inapplicableFlag {
	const where = "context --walk-id"
	var out []inapplicableFlag
	if f.walkID != "" {
		out = append(out, inapplicableFlag{flag: "--walk-id", where: where})
	}
	if f.directOnly {
		out = append(out, inapplicableFlag{flag: "--direct-only", where: where})
	}
	if f.affectedOnly {
		out = append(out, inapplicableFlag{flag: "--affected-only", where: where})
	}
	if f.modulesFile != "" {
		out = append(out, inapplicableFlag{flag: "--modules", where: where})
	}
	return out
}

// contextGoModOnlyFlags returns the context flags that only the --gomod path
// can act on, for whichever of them the caller set. --tool and --project select
// a projection of a go.mod's build list; a coordinate, a walk id and a local
// tree each name their own module set, and none of them has a go.mod scope to
// project.
func contextGoModOnlyFlags(f contextFlags) []inapplicableFlag {
	const where = "context --gomod"
	var out []inapplicableFlag
	if f.gomodPath != "" {
		out = append(out, inapplicableFlag{flag: "--gomod", where: where})
	}
	if f.tool {
		out = append(out, inapplicableFlag{flag: "--tool", where: where})
	}
	if f.project {
		out = append(out, inapplicableFlag{flag: "--project", where: where})
	}
	return out
}

// contextStreamFlag returns --stream when the caller set it. Only the two
// multi-module paths emit a stream; a single-document path has one object to
// print and nothing to stream.
func contextStreamFlag(f contextFlags) []inapplicableFlag {
	if !f.stream {
		return nil
	}
	return []inapplicableFlag{{flag: "--stream", where: "context --walk-id or --gomod"}}
}

// contextLocalOnlyFlags returns the context flags that only a local working-tree
// path can act on, for whichever of them the caller set.
//
// --exclude-tests is no longer one of them: it narrows the go.mod dependency
// scopes too, and is refused separately by the two paths that project no scope
// at all. See contextTestScopeFlag.
func contextLocalOnlyFlags(f contextFlags) []inapplicableFlag {
	const where = "context <local path>"
	var out []inapplicableFlag
	if f.symbol {
		out = append(out, inapplicableFlag{flag: "--symbol", where: where})
	}
	if f.reachability {
		out = append(out, inapplicableFlag{flag: "--reachability", where: where})
	}
	return out
}

// contextTestScopeFlag returns --exclude-tests when the caller set it on a path
// that measures no test axis: a single coordinate and a pinned walk each name a
// module set that was fixed elsewhere, so there is nothing here to narrow.
func contextTestScopeFlag(f contextFlags) []inapplicableFlag {
	if !f.excludeTests {
		return nil
	}
	return []inapplicableFlag{{
		flag:  "--" + testScopeFlagName,
		where: "context <local path> or context --gomod",
	}}
}

// contextRenderFlags returns the context flags that shape a stored-record
// context document — its doc comments, example bodies, package filter and
// entry-point list — for whichever of them the caller set. A local working-tree
// context has none of those sections, so it can act on none of these.
//
// --compact is reported only when the caller set it explicitly: it defaults to
// true, so refusing on its value alone would refuse every invocation.
func contextRenderFlags(f contextFlags) []inapplicableFlag {
	const where = "a module coordinate, --walk-id or --gomod"
	var out []inapplicableFlag
	if f.full {
		out = append(out, inapplicableFlag{flag: "--full", where: where})
	}
	if f.compactSet {
		out = append(out, inapplicableFlag{flag: fmt.Sprintf("--compact=%t", f.compact), where: where})
	}
	if f.packageFilter != "" {
		out = append(out, inapplicableFlag{flag: "--package", where: where})
	}
	if f.entryPointsFull {
		out = append(out, inapplicableFlag{flag: "--entry-points-full", where: where})
	}
	return out
}

// dependentsRootFlags returns the dependents flags that name a root other than
// --walk-id, for whichever of them the caller set. A pinned walk IS the build,
// so a manifest or a scope beside it names a second one and only one of the two
// can be answered.
func dependentsRootFlags(f dependentsFlags) []inapplicableFlag {
	out := dependentsScopeFlags(f)
	if f.anyBuild {
		out = append(out, inapplicableFlag{flag: "--any-build", where: "dependents --any-build, which names no walk"})
	}
	return out
}

// dependentsScopeFlags returns the dependents flags that project a go.mod into
// one of its build scopes, for whichever of them the caller set. The search and
// a pinned walk each arrive at a build without a manifest to project.
func dependentsScopeFlags(f dependentsFlags) []inapplicableFlag {
	const where = "dependents --gomod (or no flag, which reads ./go.mod)"
	var out []inapplicableFlag
	if f.gomod != "" {
		out = append(out, inapplicableFlag{flag: "--gomod", where: where})
	}
	if f.tool {
		out = append(out, inapplicableFlag{flag: "--tool", where: where})
	}
	if f.project {
		out = append(out, inapplicableFlag{flag: "--project", where: where})
	}
	return out
}
