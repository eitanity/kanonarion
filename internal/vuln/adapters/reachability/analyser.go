package reachability

import (
	"context"
	"fmt"
	"strings"

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
		// Empty unless the graph does not say what the module is, in which case
		// the answer names the rooting it fell back to rather than presenting the
		// narrow root set as a measured choice.
		RootSelection: callgraphdomain.RootSelectionCaveat(callgraphdomain.ArtifactKind(cg.ArtifactKind)),
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

// advisorySymbolForm renders a node the way an ADVISORY names it: a bare
// function name, or "Receiver.Method" with the receiver's pointer star dropped.
//
// The star is dropped because the two sides spell the same method differently
// and neither is wrong. A call graph records the receiver as the Go type
// expression the method is declared on, so a pointer method is "*Renderer"; an
// advisory's ecosystem-specific symbol list never writes one, so the same method
// is "Renderer.renderAutoLink". Compared literally they never match, and the
// consequence is silent and one-directional: the target set comes up short, the
// search looks for less than the advisory named, and an absence it reports is an
// absence of the wrong thing.
//
// Measured on a working store, over the only two coordinates holding both a
// negative and a graph: every pointer-receiver symbol was missed — three of
// three on github.com/yuin/goldmark, four of eight on golang.org/x/crypto.
//
// Dropping the star cannot over-match. Go forbids declaring the same method name
// on both the value and the pointer receiver of one type, so at most one node
// answers to a given "Type.Method".
func advisorySymbolForm(receiver, symbol string) string {
	if receiver == "" {
		return symbol
	}
	return strings.TrimPrefix(strings.Trim(receiver, "()"), "*") + "." + symbol
}

// normaliseAdvisorySymbol puts an advisory's own symbol into the same form, so a
// database that does spell the receiver as a pointer — or parenthesises it —
// meets the node on equal terms. The receiver is everything before the LAST dot,
// which is what leaves a bare function name untouched.
func normaliseAdvisorySymbol(sym string) string {
	i := strings.LastIndex(sym, ".")
	if i < 0 {
		return sym
	}
	return advisorySymbolForm(sym[:i], sym[i+1:])
}

// buildTargetSet returns the set of node IDs that match any of the target symbols.
func buildTargetSet(cg ports.CallGraphProjection, targets []ports.SymbolReference) map[string]bool {
	ids := make(map[string]bool)
	for _, node := range cg.Nodes {
		if node.IsExternal {
			continue
		}
		nodeSymStr := advisorySymbolForm(node.Receiver, node.Symbol)
		for _, sym := range targets {
			if sym.Module != "" && node.Module != sym.Module {
				continue
			}
			if sym.Package != "" && node.Package != sym.Package {
				continue
			}
			if nodeSymStr == normaliseAdvisorySymbol(sym.Symbol) {
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
// analysis apply one root-selection rule and can never drift.
//
// Test declarations stay in the root set here, unlike capability analysis. A
// route names its own root and ClassifyRouteRoot marks a test-scope one RootTest
// with the reason printed beside the verdict, so the reader is told; dropping
// the root instead would turn a disclosed test-only reach into a silent "not
// reachable", which is the false-negative direction.
func collectEntryPoints(cg ports.CallGraphProjection) []string {
	return callgraphdomain.SelectReachabilityRoots(
		rootCandidates(cg), callgraphdomain.ArtifactKind(cg.ArtifactKind), callgraphdomain.RootScopeWithTests)
}

// collectNamedEntryPoints returns only the roots the analysis can NAME as
// entered from outside the module — the public API, package init, a command's
// main, an http.Handler — whatever the artifact kind says.
//
// It is the root set an ABSENCE is certified against, and it is separate from
// collectEntryPoints because the two answer different questions: that one roots
// an application at every owned node so a positive is not under-reported, which
// makes the vulnerable symbol its own root and every absence uncertifiable.
// This one is never used to reach a stored verdict — see NegativeSearcher,
// which runs both and reports them as the two claims they are.
//
// The scope is production: a consumer compiles none of a dependency's _test.go
// files, so a symbol only its tests reach is not one the consumer's build
// enters. Where a test DOES reach it, collectEntryPoints still finds the route
// and the answer states it.
func collectNamedEntryPoints(cg ports.CallGraphProjection) []string {
	return callgraphdomain.SelectEntryPointRoots(rootCandidates(cg), callgraphdomain.RootScopeProduction)
}

// rootCandidates projects the graph's nodes onto the shared selector's input, so
// both root sets are chosen from one projection and a field added to the
// candidate cannot reach one selector and not the other.
func rootCandidates(cg ports.CallGraphProjection) []callgraphdomain.RootCandidate {
	candidates := make([]callgraphdomain.RootCandidate, 0, len(cg.Nodes))
	for _, node := range cg.Nodes {
		candidates = append(candidates, callgraphdomain.RootCandidate{
			ID:            node.ID,
			Symbol:        node.Symbol,
			Package:       node.Package,
			Receiver:      node.Receiver,
			IsExternal:    node.IsExternal,
			IsExportedAPI: node.IsExportedAPI,
			IsTest:        node.IsTest,
		})
	}
	return candidates
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
