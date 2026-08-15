package cli

import (
	"context"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/rootclass"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// routeRootFunc classifies the root of one stored reachability route.
//
// It is a closure rather than a parameter list because the presenters that need
// it — the route block in vuln-show, the verdict line in reachability — take
// neither a context nor a store, and threading both through every renderer to
// answer one question per route would put I/O in the printers.
type routeRootFunc func(vuldomain.ReachabilityRoute) vuldomain.RouteRoot

// unclassifiedRoutes is the classifier for a caller with no call-graph reader.
//
// It answers the zero RouteRoot, which every presenter renders as nothing rather
// than as a negative — "unrooted" is a measurement and this is the absence of
// one. No production path uses it: every command that prints a route builds a
// real classifier from the container, and this exists so a unit test can
// exercise a presenter without a store.
func unclassifiedRoutes(vuldomain.ReachabilityRoute) vuldomain.RouteRoot {
	return vuldomain.RouteRoot{}
}

// recordRootFunc binds one record to the classifier for its own routes.
//
// It exists because the classification is a question about a RECORD's routes,
// not about a route alone: only the record states the frame the analysis was
// rooted in. A presenter holding one record asks for its classifier once; a
// presenter walking a list asks per record, and every classifier it gets shares
// one loaded-graph cache, because a list of forty records of one project asks
// the same module for the same graph forty times.
type recordRootFunc func(vuldomain.VulnerabilityRecord) routeRootFunc

// unclassifiedRecords is the binder for a caller with no call-graph reader: it
// hands every record the classifier that answers nothing.
func unclassifiedRecords(vuldomain.VulnerabilityRecord) routeRootFunc {
	return unclassifiedRoutes
}

// newRecordRootFunc returns the binder above, reading the stored call graphs.
//
// The record supplies both halves of the question the route cannot answer
// alone: its analysis frame says what the analysis was rooted at, and its
// coordinate is the fallback for a route whose first frame carries no version —
// which is every route into a main module, since a main module has none in a Go
// build. A caller that cannot supply a record must not classify at all: the
// frame decides whether a route is closure-rooted, so a fabricated one would
// make two surfaces disagree about a route they read from the same store.
func newRecordRootFunc(ctx context.Context, graphs QueryCallGraphUseCase) recordRootFunc {
	if graphs == nil {
		return unclassifiedRecords
	}
	classifier := rootclass.New(graphs, cgapp.PipelineVersion)
	return func(rec vuldomain.VulnerabilityRecord) routeRootFunc {
		rooting := vuldomain.RecordRooting(rec)
		coord := rec.Coordinate
		return func(route vuldomain.ReachabilityRoute) vuldomain.RouteRoot {
			return classifier.Classify(ctx, rooting, coord, route)
		}
	}
}

// newRouteRootFunc binds a record to a classifier reading the stored call
// graphs, so the presenters can ask what sits at the root of each of its routes.
func newRouteRootFunc(ctx context.Context, graphs QueryCallGraphUseCase, rec vuldomain.VulnerabilityRecord) routeRootFunc {
	return newRecordRootFunc(ctx, graphs)(rec)
}

// firstRouteRootOf classifies the first route a finding records, or answers the
// zero classification when it records none.
//
// A finding with no route is not classified at all. The absence is already
// explained where it arises — an advisory naming no symbols for the module path
// has no symbol to route to — and answering "unrooted" there would offer a
// missing root as the reason for a route that was never possible.
func firstRouteRootOf(f vuldomain.VulnerabilityFinding, classify routeRootFunc) vuldomain.RouteRoot {
	if f.Reachable == nil || len(f.Reachable.Routes) == 0 {
		return vuldomain.RouteRoot{}
	}
	return classify(f.Reachable.Routes[0])
}

// routeRootTag renders the root classification for the same line as the verdict.
//
// The kind goes on the verdict line and the reason below it, because one of the
// five carries a warning that must not be a line further down: a route rooted in
// test scope read as a production one is the misreading this classification
// exists to prevent.
func routeRootTag(root vuldomain.RouteRoot) string {
	if !root.IsRecorded() {
		return ""
	}
	return rootTag(root.Kind.String(), root.ClosureRooted)
}

// rootTagFromOutput is the same tag for a presenter holding the curated JSON
// shape rather than the domain value.
func rootTagFromOutput(root *routeRootOutput) string {
	if root == nil {
		return ""
	}
	return rootTag(root.Kind, root.ClosureRooted)
}

// rootTag renders the tag itself. The test kind spells its consequence out
// instead of naming the kind alone, because "test" beside a REACHABLE verdict is
// exactly the pairing a reader skims past.
func rootTag(kind string, closureRooted bool) string {
	if kind == "" {
		return ""
	}
	if kind == string(vuldomain.RootTest) {
		return " [root: test — this route is test-scope, not a production one]"
	}
	if closureRooted {
		return " [root: " + kind + ", closure-rooted]"
	}
	return " [root: " + kind + "]"
}
