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

// ExternalEntryPointReason names why a node is entered from OUTSIDE the
// analysed module's own call structure, or returns the empty string when nothing
// about the node says so.
//
// It lives beside SelectReachabilityRoots because it answers the same kind of
// question — what starts a path — and the two must not drift into different
// ideas of an entry point. It reads only the node's own identity, which is what
// makes it usable from a stored record with no source in hand.
//
// The three facts it can witness, and the limit of each:
//
//   - Package initialisation, recognised by IsInitSymbol. The runtime runs it
//     when the package is loaded, so it runs unconditionally — a stronger claim
//     than reachable, not a weaker one. It is named separately from the HTTP case
//     because the two are not equally attacker-facing and a bare "ingress" would
//     flatten them.
//   - The process entry point, recognised as a receiverless "main". A function
//     named main outside package main would also match; that is a vet error and
//     the graph does not record which package is the command, so the
//     over-approximation is stated rather than hidden.
//   - An http.Handler implementation, recognised as a "ServeHTTP" method. The
//     graph records no signatures, so this is the method NAME, not a proof the
//     type satisfies http.Handler. In Go the name has essentially one meaning,
//     and the reason string says what was matched so a reader can check it.
//
// A registered route — a handler function stored into a router — is NOT
// witnessed here. Registration is a value flowing into a data structure, and
// nothing in a node's identity records it; the caller edges do, several hops
// up. Claiming it from a node fact would be a guess, so a root reached only that
// way classifies on its callers instead.
func ExternalEntryPointReason(symbol, receiver string) string {
	switch {
	case IsInitSymbol(symbol):
		return "package initialisation — the runtime runs it when the package is loaded, so it runs unconditionally"
	case symbol == "main" && receiver == "":
		return "the process entry point — the runtime invokes it"
	case symbol == "ServeHTTP" && receiver != "":
		return "an http.Handler implementation (method named ServeHTTP) — an HTTP server invokes it per request"
	}
	return ""
}

// SelectReachabilityRoots returns the reachability roots for an analysis over a
// call graph, conditioned on what the analysed module is.
//
// For an application (kind ArtifactApplication) every module-owned (non-external)
// node is a root. An application's functions are entered in ways no static
// analysis can enumerate — framework dispatch, registered callbacks, goroutine
// entry functions — so rooting only the exported API would leave those subgraphs
// dark and under-report the capabilities the shipped code really exercises.
// Whole-graph rooting witnesses them with zero framework knowledge.
//
// For a library it is every owned node that is either part of the public API or
// a package init function: a library only runs what its consumer can reach.
// Package init runs whenever the package is loaded, so init-reachable code is
// reachable in any real execution and must root the traversal too; omitting it
// makes init-only sinks a false-"safe" under-approximation. When no node
// qualifies it falls back to every owned node so the analysis still reasons
// about the analysed code.
//
// Results are sorted for determinism.
func SelectReachabilityRoots(candidates []RootCandidate, kind ArtifactKind) []string {
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
	if kind == ArtifactApplication {
		sort.Strings(owned)
		return owned
	}
	if len(roots) > 0 {
		sort.Strings(roots)
		return roots
	}
	sort.Strings(owned)
	return owned
}
