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
	// IsTest is the node's test axis: declared in a _test.go file or an external
	// test package. It is carried because a test declaration is exported and
	// owned like any other, so without it the selector cannot tell a consumer's
	// entry point from one only `go test` runs.
	IsTest bool
}

// RootScope says whether test-declared nodes may root a traversal.
//
// The two answers are both correct and belong to different questions, so the
// caller states which it is asking rather than the selector guessing: a
// consumer does not compile a dependency's _test.go files, while an analysis
// that names the test root in its answer is showing the reader a real path.
type RootScope int

const (
	// RootScopeProduction drops test-declared candidates before the artifact
	// kind's rule is applied — the consumer's question, and the zero value so a
	// caller that says nothing gets the narrower root set rather than the wider.
	RootScopeProduction RootScope = iota
	// RootScopeWithTests keeps them, for a surface whose answer states that the
	// root it found is a test declaration.
	RootScopeWithTests
)

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
// witnessed here, and cannot be. Registration is a value flowing into a data
// structure, so nothing in a NODE's identity records it. The edges do: the graph
// carries a reference edge from the registration site (see EdgeKind), and the
// distance measurement built on it says how far a node sits below an entry
// point. Claiming ingress from a node fact would be a guess; measuring the hops
// is not, so a root reached only that way keeps its kind and states the
// distance.
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
// A RootScopeProduction scope drops test-declared candidates first, so the
// exclusion holds for the application rule and the owned-node fallback too: a
// consumer compiles none of those files whatever the analysed module is.
//
// Results are sorted for determinism.
func SelectReachabilityRoots(candidates []RootCandidate, kind ArtifactKind, scope RootScope) []string {
	var roots, owned []string
	for _, c := range candidates {
		if c.IsExternal {
			continue
		}
		if c.IsTest && scope == RootScopeProduction {
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

// ConfidenceRank orders the edge-confidence vocabulary from most to least
// precise, so a traversal can carry the WEAKEST confidence it has crossed
// without every consumer re-deriving the ordering and drifting.
//
// It is a rank, not a score: the gaps between tiers carry no meaning and must
// not be averaged. An unrecognised value ranks with Unknown, because a
// confidence this build does not know is one it cannot vouch for.
func ConfidenceRank(c EdgeConfidence) int {
	switch c {
	case ConfidenceDirect:
		return 4
	case ConfidenceVTA:
		return 3
	case ConfidenceFramework:
		return 2
	case ConfidenceCHAOverapprox:
		return 1
	case ConfidenceUnknown:
		return 0
	default:
		return 0
	}
}

// WeakestConfidence returns whichever of two confidences a path may claim after
// crossing both: the weaker one. A path is only as good as its worst hop.
func WeakestConfidence(a, b EdgeConfidence) EdgeConfidence {
	if ConfidenceRank(b) < ConfidenceRank(a) {
		return b
	}
	return a
}
