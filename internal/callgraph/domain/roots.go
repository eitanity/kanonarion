package domain

import (
	"sort"
	"strings"
)

// RootCandidate is the minimal node view SelectReachabilityRoots needs to
// classify a node as a reachability root. It is deliberately decoupled from
// CallNode (and from any adapter's projection type) so every reachability
// analysis can feed the shared selector its own node representation and the
// root-selection rule can never drift between them.
type RootCandidate struct {
	ID            string
	Symbol        string
	IsExternal    bool
	IsExportedAPI bool
}

// IsInitSymbol reports whether a symbol name denotes a package init function.
// The Go compiler names the user-written init as "init" and any additional
// generated package-initialisation work as "init#1", "init#2", ... All of them
// run unconditionally when the package is loaded.
func IsInitSymbol(symbol string) bool {
	return symbol == "init" || strings.HasPrefix(symbol, "init#")
}

// SelectReachabilityRoots returns the reachability roots for an analysis over a
// call graph: every module-owned (non-external) node that is either part of the
// public API or a package init function. Package init runs whenever the package
// is loaded, so init-reachable code is reachable in any real execution and must
// root the traversal too; omitting it makes init-only sinks a false-"safe"
// under-approximation. When no node qualifies — typically a main-package binary
// with no exported API — it falls back to every owned node so the analysis still
// reasons about the analysed code. Results are sorted for determinism.
func SelectReachabilityRoots(candidates []RootCandidate) []string {
	var roots, owned []string
	for _, c := range candidates {
		if c.IsExternal {
			continue
		}
		owned = append(owned, c.ID)
		if c.IsExportedAPI || IsInitSymbol(c.Symbol) {
			roots = append(roots, c.ID)
		}
	}
	if len(roots) > 0 {
		sort.Strings(roots)
		return roots
	}
	sort.Strings(owned)
	return owned
}
