package reachability

import (
	"context"
	"log/slog"
	"strconv"
	"sync"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// DispatchAnnotator states how control reached each hop of the routes a
// vulnerability record carries, reading the call graph of the module each call
// site is in.
//
// It enriches; it never edits. The hop sequence it hands back is the one it was
// given, hop for hop and field for field — the annotation is written into a
// field of its own and nothing else on the frame is touched. A route govulncheck
// produced is govulncheck's answer, and a call graph that cannot corroborate a
// hop is not grounds for withholding, altering, dropping or reordering any part
// of it.
//
// A hop it cannot read is left unannotated AND SAYS SO, with the reason in the
// graph's own terms. Measured on a working store, that is the majority path
// rather than the edge case: the standard library is not analysed by the
// call-graph stage at all, and a walk's own root is analysed only when someone
// has ingested its working tree, so most hops of a real route sit on a call site
// in a module with no served graph.
type DispatchAnnotator struct {
	reader ports.CallSiteReader
	logger *slog.Logger

	mu     sync.Mutex
	served map[coordinate.ModuleCoordinate]*servedGraph
}

// servedGraph memoises one module's answer for the life of the annotator,
// together with the caller node IDs that answer was asked for.
//
// Serving a graph is the expensive part — a blob decode, an edge reconstruction
// and a seal check — and a walk's records share their routes: measured on a
// 624-record walk scan, 4 records carried routes at all and they named 7 modules
// with a served graph between them. Memoising turns that into 7 reads for the
// run instead of one per record.
//
// asked is kept so a later record naming a caller this answer never covered
// re-reads the module rather than reporting the site absent. Reporting absence
// from a query that never asked is the failure this whole annotation is about,
// one level down.
type servedGraph struct {
	asked  map[string]bool
	answer ports.CallSiteAnswer
	err    error
}

// NewDispatchAnnotator returns an annotator reading through reader. A nil
// logger is replaced with a discarding one so the annotator is usable without
// wiring.
func NewDispatchAnnotator(reader ports.CallSiteReader, logger *slog.Logger) *DispatchAnnotator {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &DispatchAnnotator{
		reader: reader,
		logger: logger,
		served: make(map[coordinate.ModuleCoordinate]*servedGraph),
	}
}

// AnnotateRecord annotates every route on every finding of record, and returns
// the decomposition by dispatch kind.
//
// It is safe for concurrent use: the isolated scan path runs a worker per
// module, and they share one annotator so they share its memo.
func (a *DispatchAnnotator) AnnotateRecord(ctx context.Context, record *domain.VulnerabilityRecord) domain.DispatchTally {
	if a == nil || record == nil {
		return domain.DispatchTally{ByKind: map[domain.DispatchKind]int{}}
	}
	routes := recordRoutes(record)
	if len(routes) == 0 {
		return domain.DispatchTally{ByKind: map[domain.DispatchKind]int{}}
	}

	domain.AnnotateRouteEntries(routes)
	root := rootCoordinate(record)

	// Gathered first, then read, then written. One pass could read the same module
	// once per hop; the graphs are the expensive thing here and the routes are not.
	needed := make(map[coordinate.ModuleCoordinate][]string)
	for _, route := range routes {
		for i := 1; i < len(route); i++ {
			coord, ok := frameCoordinate(route[i-1], root)
			if !ok {
				continue
			}
			if id := route[i-1].NodeID(); id != "" {
				needed[coord] = append(needed[coord], id)
			}
		}
	}
	answers := make(map[coordinate.ModuleCoordinate]*servedGraph, len(needed))
	for coord, fromIDs := range needed {
		answers[coord] = a.serve(ctx, coord, fromIDs)
	}

	for _, route := range routes {
		for i := 1; i < len(route); i++ {
			if route[i].Dispatch.IsRecorded() {
				continue
			}
			route[i].Dispatch = annotateHop(route[i-1], route[i], root, answers)
		}
	}
	return domain.TallyDispatch(routes)
}

// serve returns the memoised answer for coord, reading the store when this run
// has not read it, or has not read it for one of these callers.
func (a *DispatchAnnotator) serve(ctx context.Context, coord coordinate.ModuleCoordinate, fromIDs []string) *servedGraph {
	a.mu.Lock()
	defer a.mu.Unlock()

	held, ok := a.served[coord]
	if ok && held.err == nil && coversAll(held.asked, fromIDs) {
		return held
	}
	// Re-read with the union, never only the new ids: the answer replaces the held
	// one, and an answer built from the new ids alone would lose the sites the
	// first read covered.
	asked := make(map[string]bool, len(fromIDs))
	if ok {
		for id := range held.asked {
			asked[id] = true
		}
	}
	for _, id := range fromIDs {
		asked[id] = true
	}
	all := make([]string, 0, len(asked))
	for id := range asked {
		all = append(all, id)
	}

	answer, err := a.reader.ReadCallSites(ctx, coord, all)
	if err != nil {
		// Recorded on every hop that wanted it, not only logged. A read that failed
		// is not a module with no graph, and the record has to carry the difference
		// or the reason a hop is unannotated is a guess made at read time.
		a.logger.Warn("could not read the call graph for a route's call sites",
			"coordinate", coord, "error", err)
	}
	fresh := &servedGraph{asked: asked, answer: answer, err: err}
	a.served[coord] = fresh
	return fresh
}

// coversAll reports whether every id was part of the read that produced the
// held answer.
func coversAll(asked map[string]bool, ids []string) bool {
	for _, id := range ids {
		if !asked[id] {
			return false
		}
	}
	return true
}

// annotateHop states how control reached callee from caller, or why it cannot
// be said.
//
// Every branch returns a stated kind. There is no path out of here that leaves
// a hop looking like a direct call because nothing was known about it — the
// refusals carry DispatchNotAnnotated and a reason, and the reader is told which
// graph was consulted in either case.
func annotateHop(
	caller, callee domain.ReachabilityFrame,
	root coordinate.ModuleCoordinate,
	answers map[coordinate.ModuleCoordinate]*servedGraph,
) domain.HopDispatch {
	coord, ok := frameCoordinate(caller, root)
	if !ok {
		return domain.HopDispatch{
			Kind: domain.DispatchNotAnnotated,
			Reason: "the hop above this one names no module version and is not the module the analysis was rooted at, " +
				"so the call site cannot be placed in any one module's call graph",
		}
	}
	fromID, toID := caller.NodeID(), callee.NodeID()
	if fromID == "" || toID == "" {
		return domain.HopDispatch{
			Kind:   domain.DispatchNotAnnotated,
			Graph:  coord.String(),
			Reason: "the route names this hop, or the hop above it, without the package and symbol a call-graph node is identified by",
		}
	}

	held, served := answers[coord]
	switch {
	case !served:
		return domain.HopDispatch{
			Kind:   domain.DispatchNotAnnotated,
			Graph:  coord.String(),
			Reason: "the call sites in " + coord.String() + " were not read for this record",
		}
	case held.err != nil:
		return domain.HopDispatch{
			Kind:   domain.DispatchNotAnnotated,
			Graph:  coord.String(),
			Reason: "the call graph for " + coord.String() + ", the module this call site is in, could not be read: " + held.err.Error(),
		}
	case !held.answer.Served:
		return domain.HopDispatch{
			Kind:  domain.DispatchNotAnnotated,
			Graph: coord.String(),
			Reason: "no call graph is held for " + coord.String() + ", the module this call site is in, " +
				"so there is no edge to read; the route stands as the analyser reported it",
		}
	}

	fact, found := held.answer.Edges[ports.CallSiteKey{FromID: fromID, ToID: toID}]
	if !found {
		return unreadableHop(coord, held.answer, fromID, toID)
	}
	out := domain.HopDispatch{
		Kind:                 domain.DispatchKindOfEdge(fact.Confidence, fact.ReflectDispatch, fact.Reference),
		Confidence:           fact.Confidence,
		Graph:                coord.String(),
		GraphCompleteness:    held.answer.Completeness,
		CallSite:             callSite(fact),
		ImplementationModule: fact.ImplementationModule,
	}
	if out.Kind == domain.DispatchInterface {
		out.Interface = fact.InterfaceID
		out.Implementers = fact.Implementers
		out.ImplementersQuery = ImplementersQuery(fact.InterfaceID)
		if out.Interface == "" {
			out.Reason = "the edge records an interface dispatch; the interface it crossed is not recoverable here, " +
				"because a module's implementation relation covers only the interfaces and types it declares itself"
		}
	} else {
		// Stated only where it answers something. On a direct call the caller named
		// the callee, so "which module supplied the implementation" is not a
		// question the hop raises.
		out.ImplementationModule = ""
	}
	return out
}

// unreadableHop states the two ways a served graph can fail to record a call
// site, which lead a reader to different places.
func unreadableHop(coord coordinate.ModuleCoordinate, answer ports.CallSiteAnswer, fromID, toID string) domain.HopDispatch {
	out := domain.HopDispatch{
		Kind:              domain.DispatchNotAnnotated,
		Graph:             coord.String(),
		GraphCompleteness: answer.Completeness,
	}
	if !answer.KnownCallers[fromID] {
		out.Reason = "the call graph for " + coord.String() + " does not name " + fromID +
			", so the site this hop was reached from is not in it"
		return out
	}
	out.Reason = "the call graph for " + coord.String() + " names " + fromID +
		" but records no edge from it to " + toID +
		"; the analyser that produced this route resolved a call this module's own graph does not hold"
	return out
}

// callSite renders "file:line", or nothing when the edge carries no position.
func callSite(fact ports.CallSiteFact) string {
	if fact.CallSiteFile == "" {
		return ""
	}
	if fact.CallSiteLine == 0 {
		return fact.CallSiteFile
	}
	return fact.CallSiteFile + ":" + strconv.Itoa(fact.CallSiteLine)
}

// recordRoutes returns every route the record carries, as the slices they are
// stored in, so annotating one annotates the record.
func recordRoutes(record *domain.VulnerabilityRecord) []domain.ReachabilityRoute {
	var routes []domain.ReachabilityRoute
	for i := range record.Findings {
		if r := record.Findings[i].Reachable; r != nil {
			routes = append(routes, r.Routes...)
		}
	}
	return routes
}

// rootCoordinate is the module the analysis was rooted at — the one module whose
// frames carry no version, because a main module has none in a Go build.
//
// The frame is read first and the record's own coordinate is the fallback. For
// an isolated scan they are the same module; for a target-rooted record they are
// not, and reading the coordinate there would place the target's versionless
// frames in the wrong module's graph.
func rootCoordinate(record *domain.VulnerabilityRecord) coordinate.ModuleCoordinate {
	if target := record.Rooting.RootTarget(); target != "" {
		if coord, err := coordinate.ParseModuleCoordinate(target); err == nil {
			return coord
		}
	}
	return record.Coordinate
}

// frameCoordinate is the module coordinate whose call graph holds the frame's
// code. It reports false when the frame names no module this store could serve a
// graph for.
//
// A frame with no version is the analysed root and only the analysed root: a
// main module has no version in a Go build, and every other hop govulncheck
// reports carries the version the build selected. A versionless frame naming
// some other module is therefore a frame this cannot place, and it says so
// rather than inventing a version.
func frameCoordinate(frame domain.ReachabilityFrame, root coordinate.ModuleCoordinate) (coordinate.ModuleCoordinate, bool) {
	if frame.ModulePath == "" {
		return coordinate.ModuleCoordinate{}, false
	}
	if frame.ModuleVersion == "" {
		if !root.IsZero() && frame.ModulePath == root.Path() {
			return root, true
		}
		return coordinate.ModuleCoordinate{}, false
	}
	coord, err := coordinate.NewModuleCoordinate(frame.ModulePath, frame.ModuleVersion)
	if err != nil {
		return coordinate.ModuleCoordinate{}, false
	}
	return coord, true
}

// Ensure DispatchAnnotator implements ports.RouteAnnotator.
var _ ports.RouteAnnotator = (*DispatchAnnotator)(nil)
