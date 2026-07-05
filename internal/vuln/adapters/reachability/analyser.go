package reachability

import (
	"context"
	"fmt"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
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
	targetCoord fetchdomain.ModuleCoordinate,
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

	targetIDs := buildTargetSet(cg, targetSymbols)
	if len(targetIDs) == 0 {
		return domain.ReachabilityResult{IsReachable: false, Confidence: domain.ConfidenceHigh}, nil
	}

	entryPoints := collectEntryPoints(cg)
	if len(entryPoints) == 0 {
		return domain.ReachabilityResult{IsReachable: false, Confidence: domain.ConfidenceHigh}, nil
	}

	path := bfsPath(cg, entryPoints, targetIDs)
	if path == nil {
		return domain.ReachabilityResult{IsReachable: false, Confidence: domain.ConfidenceHigh}, nil
	}

	return domain.ReachabilityResult{
		IsReachable:  true,
		Confidence:   domain.ConfidenceHigh,
		ExamplePaths: [][]string{path},
	}, nil
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

// collectEntryPoints returns IDs of exported, non-external nodes (the public API surface).
func collectEntryPoints(cg ports.CallGraphProjection) []string {
	var eps []string
	for _, node := range cg.Nodes {
		if node.IsExportedAPI && !node.IsExternal {
			eps = append(eps, node.ID)
		}
	}
	return eps
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
