package domain

import "strings"

// RootKind names what sits at the ROOT of a reachability route.
//
// A route says a path exists. It does not say what starts the path, and the
// three cases a reader most needs to tell apart — an HTTP handler, a test
// helper, and an exported function nothing in the project calls — were reported
// identically. This is the fact that separates them, and it is a fact about the
// root node, drawn from what the call graph already records: the test axis, the
// exported-API flag, and the edges into the node.
//
// It is NOT an exploitability claim and must never be rendered as one. "The
// root of this route is an http.Handler implementation" is a measurement;
// "this is exploitable" is a judgement about data flow that kanonarion does not
// make and this type does not introduce. Reading a kind as a severity is the one
// misuse the rendering guards against, by printing the reason beside the kind
// everywhere it appears.
type RootKind string

const (
	// RootUnclassified is the zero value: no classification was computed. It
	// means "not asked", never "no root" — a route with no root that COULD be
	// determined is RootUnrooted, which is a measurement.
	RootUnclassified RootKind = ""

	// RootIngress is a root entered from outside the analysed module's own call
	// structure: an http.Handler implementation, the process entry point, a
	// package initialiser, or a function a dependency calls back into. The
	// reason on the RouteRoot names which, because they are not equally
	// attacker-facing and the kind alone would flatten them.
	RootIngress RootKind = "ingress"

	// RootExportedAPI is an exported symbol of the analysed module that no
	// in-project caller reaches. A consumer of the module could drive it; this
	// project does not. It is the ordinary shape of a route in an isolated
	// library scan, whose roots ARE the exported API.
	RootExportedAPI RootKind = "exported-api"

	// RootInternal is a root with in-project callers that is not itself an entry
	// point. It is what the analyser stopped at, not where execution starts:
	// govulncheck reports a compressed trace, so the first frame is frequently
	// several hops below the handler that drives it. The remedy on the RouteRoot
	// names the command that walks the remaining hops.
	RootInternal RootKind = "internal"

	// RootTest is a test-scope root — a declaration in a _test.go file or an
	// external test package, on the IsTest axis the call graph has carried since
	// its schema v13. A test-only reach read as a production one is the single
	// most costly misreading of a route, so this kind is printed on the same line
	// as the verdict rather than below it.
	RootTest RootKind = "test"

	// RootUnrooted is a route whose root could not be classified, with the reason
	// named. It is a measurement — the graph was consulted and could not say —
	// and never a silent fallthrough: every producer of this value sets Reason,
	// and Remedy where a command would close the gap.
	RootUnrooted RootKind = "unrooted"
)

// RootKinds returns every classification a route root can carry, excluding the
// zero value, which is produced by omission rather than by an assignment.
func RootKinds() []RootKind {
	return []RootKind{RootIngress, RootExportedAPI, RootInternal, RootTest, RootUnrooted}
}

// IsClassified reports whether a classification was computed at all.
func (k RootKind) IsClassified() bool { return k != RootUnclassified }

// String renders the kind, naming the uncomputed case rather than printing an
// empty field.
func (k RootKind) String() string {
	if k == RootUnclassified {
		return "not classified"
	}
	return string(k)
}

// RouteRoot is the classification of one route's root, with the evidence that
// produced it.
//
// Reason is not decoration. The kinds are coarse by design — five values cannot
// carry "invoked by the runtime at package load" and "invoked by the HTTP server
// per request" separately — so the reason is what stops the kind being read as
// more, or less, than it is.
//
// It carries NO json tags, deliberately. It is derived at read time and is not
// part of any stored record's shape; tagging it would invite it into one, and a
// classification frozen into a sealed record would be stuck at whichever
// call-graph generation existed when the scan ran.
type RouteRoot struct {
	// Kind is the classification.
	Kind RootKind
	// Reason is the fact that produced the kind, in the graph's own terms.
	Reason string
	// ClosureRooted is true when the route does NOT begin in the module the
	// analysis was rooted at — the --gomod case, where reachability roots at the
	// dependency closure and the application's own entry points were never
	// analysed. It qualifies every kind rather than replacing one: the root node
	// is still whatever it is, and what is missing is the hop above it. An
	// honest "closure-rooted, application root not analysed" is the answer, and
	// Remedy carries the command that would close it.
	ClosureRooted bool
	// NodeID is the call-graph node the classification was read off, empty when
	// no node was resolved. It is carried so a reader can re-run the measurement
	// rather than take it on trust.
	NodeID string
	// Remedy is the command that would answer what this classification could
	// not. Empty when nothing further is owed.
	Remedy string
}

// IsRecorded reports whether a classification was computed.
func (r RouteRoot) IsRecorded() bool { return r.Kind.IsClassified() }

// String renders the classification for a report: the kind, the reason, and the
// closure-rooted caveat where it applies.
func (r RouteRoot) String() string {
	if !r.IsRecorded() {
		return "root not classified"
	}
	parts := []string{r.Kind.String()}
	if r.Reason != "" {
		parts = append(parts, r.Reason)
	}
	if r.ClosureRooted {
		parts = append(parts, "closure-rooted: the analysis was not rooted at an application, so the application root was not analysed")
	}
	return strings.Join(parts, " — ")
}

// RootFacts is the minimal node view ClassifyRouteRoot needs.
//
// It is deliberately decoupled from any call-graph type, on the same terms as
// callgraph domain's RootCandidate: the classification rule lives here, in the
// vuln domain that owns the route, and every adapter that can supply these facts
// feeds it the same shape. The vuln context does not import the call-graph
// domain, and this is what keeps that true.
type RootFacts struct {
	// Resolved is true when a call-graph node was found for the route's root
	// frame. When false, Unavailable says why and UnavailableRemedy names the
	// command that would fix it; every other field is meaningless.
	Resolved bool
	// Unavailable is why no node could be resolved. Required when Resolved is
	// false — an unrooted answer that does not say why is the silent negative
	// this classification exists to prevent.
	Unavailable string
	// UnavailableRemedy is the command that would resolve the root, where one
	// exists.
	UnavailableRemedy string
	// NodeID is the resolved node's identifier.
	NodeID string
	// IsTest is the call graph's test axis for the node.
	IsTest bool
	// IsExportedAPI is the call graph's exported-API flag for the node.
	IsExportedAPI bool
	// ExternalInvocation names the fact that makes the node entered from outside
	// the analysed module's own call structure, or is empty when nothing does.
	ExternalInvocation string
	// InProjectCallers is how many edges in the analysed module's own graph call
	// the node.
	InProjectCallers int
}
