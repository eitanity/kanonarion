// Package rootclass classifies the root of a stored reachability route against
// the call graph the answer was computed over.
//
// It sits in the vuln context because the route and its classification belong to
// the vulnerability record, and it is the only place in that context that reads
// the call-graph domain — the same seam adapters/reachability occupies for the
// forward direction. The vuln domain stays free of call-graph types: this
// package projects a stored graph onto domain.RootFacts and lets the domain
// decide.
//
// It NEVER computes. Every fact it reports is read from a record the store
// already holds, so classifying a route cannot change what the store says or
// cost an analysis. Where the graph cannot answer, it says so and names the
// command that would let it.
package rootclass

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// GraphReader is the narrow read this package needs: the COMPOSED call-graph
// record a coordinate serves.
//
// It is deliberately GetCallGraphRecord rather than a direct edge query. The
// call-graph ledger is append-only and its edges are keyed on the parent
// record's content hash, so a coordinate names every generation at once; reading
// edges by coordinate would classify against a generation the reachability
// answer was never computed over — plausibly a METADATA_ONLY one with no nodes
// at all. GetCallGraphRecord resolves the served generation, which is the graph
// a reader of this answer would see.
type GraphReader interface {
	GetCallGraphRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (callgraphdomain.CallGraphRecord, bool, error)
}

// Classifier answers "what sits at the root of this route" from stored facts.
//
// It caches each graph it loads for the lifetime of one command: a record with
// forty findings asks the same question of the same module forty times, and a
// call graph is a large object to decode.
type Classifier struct {
	graphs          GraphReader
	pipelineVersion string
	cache           map[coordinate.ModuleCoordinate]*graph
}

// New returns a Classifier reading graphs at pipelineVersion.
func New(graphs GraphReader, pipelineVersion string) *Classifier {
	return &Classifier{
		graphs:          graphs,
		pipelineVersion: pipelineVersion,
		cache:           make(map[coordinate.ModuleCoordinate]*graph),
	}
}

// graph is one loaded record indexed for the two lookups a classification needs.
// A miss is cached as well as a hit: absence is an answer, and re-asking the
// store for a module it does not hold is the same answer at forty times the
// cost.
type graph struct {
	// unavailable is why this graph cannot classify anything, empty when it can.
	unavailable string
	// remedy is the command that would make it available. It is decided by the
	// coordinate rather than written here, because which command re-derives a
	// graph is a property of what the coordinate names: a project module carries
	// the synthetic "local" version, and "callgraph <path>@local" is an
	// instruction that cannot succeed.
	remedy string
	// nodes is keyed by (package, receiver, symbol) — what a route frame carries.
	// A node ID would be the obvious key, but the frame does not hold one and
	// reconstructing an ID from its parts encodes an ID convention this context
	// does not own.
	nodes map[frameKey]callgraphdomain.CallNode
	// callers counts the in-module edges into each node ID, and externalCallers
	// the edges into it from a node the module does not own. The two are counted
	// apart because they answer different questions: the first is whether the
	// project drives the root, the second whether something outside it does.
	callers         map[string]int
	externalCallers map[string]int
	// parents is the reverse adjacency the entry-point search walks: for each
	// node, the edges INTO it. It is built once with the rest of the index
	// because the search runs per finding and a record with forty findings would
	// otherwise rebuild it forty times.
	parents map[string][]parentEdge
	// entryReason names why a node is an entry point, for the nodes that are
	// one. A miss is not an entry point; the map is only over the witnesses.
	entryReason map[string]string
}

// parentEdge is one edge into a node, carrying what the upward search needs to
// weigh the path it is on.
type parentEdge struct {
	from       string
	confidence callgraphdomain.EdgeConfidence
	reference  bool
}

type frameKey struct{ pkg, receiver, symbol string }

// Classify returns the classification of route's root.
//
// It never returns an error. A route whose root cannot be resolved is a
// measurement — RootUnrooted with the reason named — and failing the read
// instead would take a whole vulnerability report down over a call graph that
// was never required to produce it.
func (c *Classifier) Classify(
	ctx context.Context,
	rooting vuldomain.Rooting,
	recordCoord coordinate.ModuleCoordinate,
	route vuldomain.ReachabilityRoute,
) vuldomain.RouteRoot {
	if len(route) == 0 {
		return vuldomain.RouteRoot{}
	}
	rootModule := rootedAtModule(rooting)
	coord, ok := c.rootCoordinate(rooting, recordCoord, route[0])
	if !ok {
		return vuldomain.ClassifyRouteRoot(route, rooting, rootModule, vuldomain.RootFacts{
			Unavailable: fmt.Sprintf(
				"the route's entry point is in %s, which names no version on the frame and is not the module the analysis frame identifies, so no call graph can be located for it",
				displayModule(route[0].ModulePath)),
		})
	}
	return vuldomain.ClassifyRouteRoot(route, rooting, rootModule, c.facts(ctx, coord, route[0]))
}

// facts resolves the root frame against the graph coord serves.
func (c *Classifier) facts(ctx context.Context, coord coordinate.ModuleCoordinate, frame vuldomain.ReachabilityFrame) vuldomain.RootFacts {
	g := c.load(ctx, coord)
	if g.unavailable != "" {
		return vuldomain.RootFacts{Unavailable: g.unavailable, UnavailableRemedy: g.remedy}
	}
	node, found := g.nodes[frameKey{pkg: frame.Package, receiver: frame.Receiver, symbol: frame.Symbol}]
	if !found {
		return vuldomain.RootFacts{
			Unavailable: fmt.Sprintf(
				"the route's entry point %s is not a node in %s's call graph, so the graph cannot say what enters it",
				frame, coord),
			UnavailableRemedy: callgraphdomain.ReanalysisCommand(coord, "") + ", to re-analyse the module the route starts in",
		}
	}
	return vuldomain.RootFacts{
		Resolved:           true,
		NodeID:             node.ID,
		IsTest:             node.IsTest,
		IsExportedAPI:      node.IsExportedAPI,
		ExternalInvocation: externalInvocation(g, node),
		InProjectCallers:   g.callers[node.ID],
		Ancestry:           g.entryPointAncestry(node.ID),
	}
}

// externalInvocation names what enters the node from outside the analysed
// module's own call structure, or returns empty when nothing does.
//
// It asks the node's identity first, through the call-graph domain's shared
// predicate, so vuln reachability and any other consumer of the graph cannot
// drift into different ideas of an entry point. The edge case it adds is one
// only a graph can witness: a dependency calling back into the analysed module.
func externalInvocation(g *graph, node callgraphdomain.CallNode) string {
	if reason := callgraphdomain.ExternalEntryPointReason(node.Symbol, node.Receiver); reason != "" {
		return reason
	}
	if g.externalCallers[node.ID] > 0 {
		return "called from outside the analysed module — a dependency invokes it"
	}
	return ""
}

// rootCoordinate decides which module's call graph holds the route's root.
//
// The order is from the most specific statement to the least. The analysis frame
// is preferred when it names a target the route actually starts in, because that
// coordinate is the one the graph was built for — a main module's frames carry
// no version at all, so the frame itself cannot supply one.
func (c *Classifier) rootCoordinate(
	rooting vuldomain.Rooting,
	recordCoord coordinate.ModuleCoordinate,
	frame vuldomain.ReachabilityFrame,
) (coordinate.ModuleCoordinate, bool) {
	if target, err := coordinate.ParseModuleCoordinate(rooting.RootTarget()); err == nil && target.Path() == frame.ModulePath {
		return target, true
	}
	if frame.ModuleVersion != "" {
		coord, err := coordinate.NewModuleCoordinate(frame.ModulePath, frame.ModuleVersion)
		if err == nil {
			return coord, true
		}
	}
	if recordCoord.Path() == frame.ModulePath && !recordCoord.IsZero() {
		return recordCoord, true
	}
	return coordinate.ModuleCoordinate{}, false
}

// load returns the indexed graph for coord, reading it once per command.
func (c *Classifier) load(ctx context.Context, coord coordinate.ModuleCoordinate) *graph {
	if g, ok := c.cache[coord]; ok {
		return g
	}
	g := c.read(ctx, coord)
	c.cache[coord] = g
	return g
}

// read fetches and indexes one record, turning every failure into a stated
// reason rather than an error: an unavailable graph is a fact about the answer's
// footing, and it belongs on the answer.
func (c *Classifier) read(ctx context.Context, coord coordinate.ModuleCoordinate) *graph {
	rec, found, err := c.graphs.GetCallGraphRecord(ctx, coord, c.pipelineVersion)
	switch {
	case err != nil:
		return &graph{
			unavailable: fmt.Sprintf("%s's call graph could not be read: %v", coord, err),
		}
	case !found:
		return &graph{
			unavailable: fmt.Sprintf("no call graph is stored for %s, so nothing can be said about what enters the route", coord),
			remedy:      callgraphdomain.ReanalysisCommand(coord, ""),
		}
	case len(rec.Nodes) == 0:
		// A record with no nodes is not an empty module. It is a module analysed at
		// a fidelity that records none — METADATA_ONLY holds package metadata and
		// nothing else — and reporting "not a node in the graph" for every frame
		// would blame the route for the analysis.
		return &graph{
			unavailable: fmt.Sprintf(
				"%s's call graph was analysed at %s and holds no nodes, so it cannot say what enters the route",
				coord, rec.Completeness),
			remedy: callgraphdomain.ReanalysisCommand(coord, ""),
		}
	}

	g := &graph{
		nodes:           make(map[frameKey]callgraphdomain.CallNode, len(rec.Nodes)),
		callers:         make(map[string]int),
		externalCallers: make(map[string]int),
		parents:         make(map[string][]parentEdge, len(rec.Nodes)),
		entryReason:     make(map[string]string),
	}
	external := make(map[string]bool, len(rec.Nodes))
	for _, n := range rec.Nodes {
		external[n.ID] = n.IsExternal
		if reason := callgraphdomain.ExternalEntryPointReason(n.Symbol, n.Receiver); reason != "" && !n.IsExternal {
			g.entryReason[n.ID] = reason
		}
		if n.IsExternal {
			// A route frame in the analysed module can only match a node the module
			// owns. Indexing external nodes too would let a dependency's identically
			// named method answer for the project's.
			continue
		}
		g.nodes[frameKey{pkg: n.Package, receiver: n.Receiver, symbol: n.Symbol}] = n
	}
	for _, e := range rec.Edges {
		g.parents[e.ToID] = append(g.parents[e.ToID], parentEdge{
			from:       e.FromID,
			confidence: e.Confidence,
			reference:  e.Kind.IsReference(),
		})
		if external[e.FromID] {
			g.externalCallers[e.ToID]++
			continue
		}
		g.callers[e.ToID]++
	}
	return g
}

// ancestrySearchBound is the hop limit of the upward entry-point search. Zero is
// unbounded, and unbounded is what the measurement chose.
//
// A bound was the obvious economy, and the graphs say it would lie. On a
// 21,713-node application graph the distances from an entry point down to owned
// code run out to 14 hops, and 8.9% of the owned nodes with an ancestor sit
// further than 6 hops from it. Stopping at 6 would report "nothing enters this"
// for one owned node in eleven that something demonstrably does. The search is
// one breadth-first walk over an index built once per command, so the honest
// answer is also the affordable one.
const ancestrySearchBound = 0

// entryPointAncestry measures how far nodeID sits below the nearest entry point,
// and how weak the path that reaches it is.
//
// The search is breadth-first over the reverse edges, so the first level holding
// an entry point is the nearest one. Among the paths of that same shortest
// length it keeps the STRONGEST — the one whose weakest hop ranks highest — so
// the caveat attached to a distance is the mildest one that distance actually
// earns, rather than the worst path that happens to share its length.
//
// A reference hop is carried separately from the confidence rather than folded
// into it. The analyser resolves a reference exactly, so it would otherwise
// report Direct and launder a registration into an all-calls chain; see
// domain.EntryPointAncestry.
func (g *graph) entryPointAncestry(nodeID string) vuldomain.EntryPointAncestry {
	out := vuldomain.EntryPointAncestry{Computed: true, SearchBound: ancestrySearchBound}
	if reason, ok := g.entryReason[nodeID]; ok {
		out.Found = true
		out.EntryPointID = nodeID
		out.EntryPointReason = reason
		return out
	}

	seen := map[string]bool{nodeID: true}
	frontier := map[string]pathState{nodeID: {weakest: callgraphdomain.ConfidenceDirect}}

	for hops := 1; len(frontier) > 0; hops++ {
		if ancestrySearchBound > 0 && hops > ancestrySearchBound {
			break
		}
		next := make(map[string]pathState, len(frontier))
		for id, st := range frontier {
			for _, p := range g.parents[id] {
				if seen[p.from] {
					continue
				}
				cand := pathState{
					weakest:   callgraphdomain.WeakestConfidence(st.weakest, p.confidence),
					reference: st.reference || p.reference,
				}
				if prev, ok := next[p.from]; ok && !stronger(cand, prev) {
					continue
				}
				next[p.from] = cand
			}
		}
		// This level is now complete, so any entry point in it is a nearest one.
		var bestID string
		var best pathState
		for id, st := range next {
			if _, ok := g.entryReason[id]; !ok {
				continue
			}
			if bestID == "" || stronger(st, best) {
				bestID, best = id, st
			}
		}
		if bestID != "" {
			out.Found = true
			out.Hops = hops
			out.EntryPointID = bestID
			out.EntryPointReason = g.entryReason[bestID]
			out.Weakest = string(best.weakest)
			out.ViaReference = best.reference
			return out
		}
		for id := range next {
			seen[id] = true
		}
		frontier = next
	}
	return out
}

// pathState is what an upward search carries about the path it took to reach a
// node: the weakest hop crossed, and whether any hop was a reference rather than
// a call.
type pathState struct {
	weakest   callgraphdomain.EdgeConfidence
	reference bool
}

// stronger reports whether a is the better path of two of equal length: a
// reference hop is a weakening no confidence rank makes up for, and otherwise
// the higher-ranked weakest hop wins.
func stronger(a, b pathState) bool {
	if a.reference != b.reference {
		return !a.reference
	}
	return callgraphdomain.ConfidenceRank(a.weakest) > callgraphdomain.ConfidenceRank(b.weakest)
}

// rootedAtModule returns the module path the analysis was rooted at, or empty
// when the frame does not name one.
func rootedAtModule(rooting vuldomain.Rooting) string {
	target, err := coordinate.ParseModuleCoordinate(rooting.RootTarget())
	if err != nil {
		return ""
	}
	return target.Path()
}

// displayModule names the unnamed module rather than leaving a blank in a
// sentence.
func displayModule(path string) string {
	if path == "" {
		return "a module the route does not name"
	}
	return path
}
