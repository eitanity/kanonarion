package reachability

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// Analyser implements ports.ReachabilityAnalyser using static call graph analysis.
type Analyser struct {
}

// New returns a new Analyser.
func New() *Analyser {
	return &Analyser{}
}

// Analyse determines if any of the target symbols are reachable from entry points
// of the target module, using the stored call graph.
//
// Returns ConfidenceUnknown when no call graph loader is provided or the graph
// cannot be loaded. Returns ConfidenceHigh when analysis succeeded (regardless of
// whether the symbol was found reachable).
func (a *Analyser) Analyse(
	ctx context.Context,
	targetCoord coordinate.ModuleCoordinate,
	targetSymbols []ports.SymbolReference,
	callGraphLoader ports.CallGraphLoader,
) (domain.ReachabilityResult, error) {
	unknown := domain.ReachabilityResult{IsReachable: false, Confidence: domain.ConfidenceUnknown}

	if callGraphLoader == nil || len(targetSymbols) == 0 {
		return unknown, nil
	}

	cg, err := callGraphLoader.Load(ctx, targetCoord)
	if err != nil {
		return unknown, fmt.Errorf("loading call graph for %s: %w", targetCoord, err)
	}

	graphDerived := domain.ReachabilityDerivation{
		Analyser: domain.AnalyserCallGraphBFS,
		Fidelity: cg.Completeness,
	}

	targetIDs := buildTargetSet(cg, targetSymbols)
	if len(targetIDs) == 0 {
		return domain.ReachabilityResult{IsReachable: false, Confidence: domain.ConfidenceHigh, DerivedBy: graphDerived}, nil
	}

	entryPoints := collectEntryPoints(cg)
	if len(entryPoints) == 0 {
		return domain.ReachabilityResult{IsReachable: false, Confidence: domain.ConfidenceHigh, DerivedBy: graphDerived}, nil
	}

	// The derivation is stamped on every answer this analyser returns, reachable
	// or not. "Not reachable" is exactly as dependent on the fidelity of the
	// graph as "reachable" is — a metadata-only graph reaches nothing and would
	// otherwise report a confident negative indistinguishable from a searched
	// one.
	derived := graphDerived

	path := bfsPath(cg, entryPoints, targetIDs)
	if path == nil {
		return domain.ReachabilityResult{IsReachable: false, Confidence: domain.ConfidenceHigh, DerivedBy: derived}, nil
	}

	return domain.ReachabilityResult{
		IsReachable: true,
		Confidence:  domain.ConfidenceHigh,
		Routes:      []domain.ReachabilityRoute{routeFrom(cg, path)},
		DerivedBy:   derived,
	}, nil
}

// routeFrom turns a path of call-graph node IDs into a route of frames.
//
// The frames carry NO module version, and that is a property of the input
// rather than an omission here: ports.CallGraphNode records a module path, a
// package, a receiver and a symbol, and no version at all. The route is
// therefore honestly unversioned — ReachabilityRoute.IsVersioned reports false
// for it — and a reader cannot check it against their own build the way a
// govulncheck route can. Filling the version in from the analysed coordinate
// would be a guess for every hop outside that one module.
func routeFrom(cg ports.CallGraphProjection, path []string) domain.ReachabilityRoute {
	byID := make(map[string]ports.CallGraphNode, len(cg.Nodes))
	for _, n := range cg.Nodes {
		byID[n.ID] = n
	}
	route := make(domain.ReachabilityRoute, 0, len(path))
	for _, id := range path {
		n, ok := byID[id]
		if !ok {
			// A path can only be built from edges between nodes, so this cannot
			// fire; the id is kept as the symbol rather than dropped, so a route
			// never silently loses a hop it traversed.
			route = append(route, domain.ReachabilityFrame{Symbol: id})
			continue
		}
		route = append(route, domain.ReachabilityFrame{
			ModulePath: n.Module,
			Package:    n.Package,
			Receiver:   n.Receiver,
			Symbol:     n.Symbol,
		})
	}
	return route
}

// buildTargetSet returns the set of node IDs that match any of the target symbols.
func buildTargetSet(cg ports.CallGraphProjection, targets []ports.SymbolReference) map[string]bool {
	ids := make(map[string]bool)
	for _, node := range cg.Nodes {
		if node.IsExternal {
			continue
		}
		nodeSymStr := node.Symbol
		if node.Receiver != "" {
			nodeSymStr = node.Receiver + "." + node.Symbol
		}
		for _, sym := range targets {
			if sym.Module != "" && node.Module != sym.Module {
				continue
			}
			if sym.Package != "" && node.Package != sym.Package {
				continue
			}
			if nodeSymStr == sym.Symbol {
				ids[node.ID] = true
				break
			}
		}
	}
	return ids
}

// collectEntryPoints returns the reachability roots for the projection,
// conditioned on the projection's artifact kind: all owned nodes for an
// application, the exported API plus package init for a library. It delegates to
// the shared callgraph-domain selector so vuln reachability and capability
// analysis root traversal identically and can never drift.
func collectEntryPoints(cg ports.CallGraphProjection) []string {
	candidates := make([]callgraphdomain.RootCandidate, 0, len(cg.Nodes))
	for _, node := range cg.Nodes {
		candidates = append(candidates, callgraphdomain.RootCandidate{
			ID:            node.ID,
			Symbol:        node.Symbol,
			IsExternal:    node.IsExternal,
			IsExportedAPI: node.IsExportedAPI,
		})
	}
	return callgraphdomain.SelectReachabilityRoots(candidates, callgraphdomain.ArtifactKind(cg.ArtifactKind))
}

// bfsPath performs a BFS from entryPoints following call edges and returns the
// first path that reaches a target node, or nil if none is reachable.
func bfsPath(cg ports.CallGraphProjection, entryPoints []string, targets map[string]bool) []string {
	adj := make(map[string][]string, len(cg.Edges))
	for _, e := range cg.Edges {
		adj[e.FromID] = append(adj[e.FromID], e.ToID)
	}

	prev := make(map[string]string)
	visited := make(map[string]bool, len(entryPoints))
	queue := make([]string, 0, len(entryPoints))

	for _, ep := range entryPoints {
		if !visited[ep] {
			visited[ep] = true
			prev[ep] = ""
			queue = append(queue, ep)
		}
	}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if targets[curr] {
			return reconstructPath(prev, curr)
		}

		for _, next := range adj[curr] {
			if !visited[next] {
				visited[next] = true
				prev[next] = curr
				queue = append(queue, next)
			}
		}
	}
	return nil
}

// reconstructPath walks prev pointers from end back to a root entry point.
func reconstructPath(prev map[string]string, end string) []string {
	var path []string
	for n := end; n != ""; n = prev[n] {
		path = append([]string{n}, path...)
	}
	return path
}

// Ensure Analyser implements ports.ReachabilityAnalyser.
var _ ports.ReachabilityAnalyser = (*Analyser)(nil)
