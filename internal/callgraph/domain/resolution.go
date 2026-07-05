package domain

import "strings"

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
