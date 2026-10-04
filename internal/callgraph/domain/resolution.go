package domain

import (
	"strings"
)

// IsStdlibPackage reports whether an import path names a standard-library
// package, by the go command's own rule: a module path's first element carries
// a dot and a standard-library path's does not.
//
// It is the same test `fetch` applies when it refuses "stdlib" with "missing
// dot in first path element", and it correctly admits the vendored trees the
// toolchain links into the same binaries, whose paths begin "vendor/".
//
// It takes a PACKAGE path and not a symbol id, deliberately. A node id appends
// the symbol to the package — "fmt.Println" — and the first element of that is
// "fmt.Println", which carries a dot and would read as a module. A caller
// deciding what a node belongs to has the package on the node and must use it.
func IsStdlibPackage(pkgPath string) bool {
	if pkgPath == "" {
		return false
	}
	first, _, _ := strings.Cut(pkgPath, "/")
	return !strings.Contains(first, ".")
}

// ResolveSymbolModule reports whether symbolID falls under one of the analysed
// module paths. It returns the longest matching module path and true, or ""
// and false when no analysed module could contain the symbol.
//
// A module path matches when symbolID equals it or continues with '.' or '/',
// so "example.com/m" matches "example.com/m.Fn" and "example.com/m/pkg.Fn"
// but not "example.com/much.Fn". This lets callers distinguish "the symbol's
// module was never analysed" (unresolved) from "analysed, genuinely zero
// edges" (resolved but empty) — see.
func ResolveSymbolModule(symbolID string, analysedModulePaths []string) (string, bool) {
	best := ""
	for _, m := range analysedModulePaths {
		if m == "" || !strings.HasPrefix(symbolID, m) {
			continue
		}
		if len(symbolID) > len(m) {
			switch symbolID[len(m)] {
			case '.', '/':
			default:
				continue
			}
		}
		if len(m) > len(best) {
			best = m
		}
	}
	return best, best != ""
}
