package domain

import "strconv"

// ClassifyRouteRoot classifies the root of one route.
//
// The order of the tests is the design. Test scope is asked first because a
// test-scope root makes every other reading of the route wrong, and an exported
// test helper would otherwise answer exported-api. Ingress is asked next because
// an entry point is what it is regardless of who else calls it. The remaining
// two split on whether the project itself drives the root, which is the
// difference between "a consumer could reach this" and "we do".
//
// A route with no frames is not classified at all. There is nothing to classify,
// and answering "unrooted" there would re-open a question that is already
// answered elsewhere: an absent route on a package-level finding is explained by
// the advisory naming no symbols, not by a root that could not be found.
func ClassifyRouteRoot(route ReachabilityRoute, rooting Rooting, rootModule string, facts RootFacts) RouteRoot {
	if len(route) == 0 {
		return RouteRoot{}
	}

	root := RouteRoot{NodeID: facts.NodeID, Ancestry: facts.Ancestry}

	// The route is target-rooted only when it begins inside the module the
	// analysis was rooted at. An isolated or unrecorded frame had no application
	// to be rooted at — the --gomod case, where reachability roots at the
	// dependency closure — and a target-rooted record whose route starts in a
	// dependency reached that dependency without keeping a frame in the
	// application. Both are closure-rooted and both say so, rather than
	// presenting a dependency's own entry point as the project's.
	//
	// The one case left undecided is the bare "target-rooted" frame that names no
	// target: it states an application WAS the root and merely does not say
	// which, so asserting closure-rooted for it would be a claim about a build
	// this record does not describe.
	switch {
	case !rooting.IsTargetRooted():
		root.ClosureRooted = true
	case rootModule != "" && route[0].ModulePath != rootModule:
		root.ClosureRooted = true
	}
	if root.ClosureRooted {
		root.Remedy = "kanonarion vuln-scan --project --reachability, run from the application's own tree, to root the analysis at its entry points"
	}

	if !facts.Resolved {
		root.Kind = RootUnrooted
		root.Reason = facts.Unavailable
		if facts.UnavailableRemedy != "" {
			root.Remedy = facts.UnavailableRemedy
		}
		return root
	}

	switch {
	case facts.IsTest:
		root.Kind = RootTest
		root.Reason = "declared in test scope, so this route is not a production one"
	case facts.ExternalInvocation != "":
		root.Kind = RootIngress
		root.Reason = facts.ExternalInvocation
	case facts.IsExportedAPI && facts.InProjectCallers == 0:
		root.Kind = RootExportedAPI
		root.Reason = "exported by the analysed module and called by nothing in it — a consumer could drive it, this project does not"
	case facts.InProjectCallers > 0:
		root.Kind = RootInternal
		root.Reason = inProjectCallerReason(facts.InProjectCallers)
		if facts.NodeID != "" {
			root.Remedy = "kanonarion callers '" + facts.NodeID + "', to walk the hops above the route"
		}
	default:
		// Owned, unexported, entered by nothing the graph recorded. The analysis
		// rooted at it anyway, because an application's functions are entered in
		// ways static analysis cannot enumerate — framework dispatch, registered
		// callbacks, goroutine entry — which is exactly the rooting rule the
		// call-graph domain applies. Saying "ingress" for it would assert an entry
		// the graph never witnessed.
		root.Kind = RootInternal
		root.Reason = "not exported and no caller recorded in the analysed module — nothing in the graph says what enters it"
	}
	return root
}

// inProjectCallerReason states the caller count as the evidence for internal,
// rather than asserting the classification bare.
func inProjectCallerReason(callers int) string {
	suffix := " callers"
	if callers == 1 {
		suffix = " caller"
	}
	return "called from within the analysed module (" + strconv.Itoa(callers) + suffix +
		"), so the route begins where the analyser stopped, not where execution starts"
}
