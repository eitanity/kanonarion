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

// contextWalkOnlyFlags returns the context flags that only the --walk-id path
// can act on, for whichever of them the caller set.
func contextWalkOnlyFlags(f contextFlags) []inapplicableFlag {
	const where = "context --walk-id"
	var out []inapplicableFlag
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

// contextLocalOnlyFlags returns the context flags that only a local working-tree
// path can act on, for whichever of them the caller set.
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
