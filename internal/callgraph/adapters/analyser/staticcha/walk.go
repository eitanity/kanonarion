package staticcha

import (
	"context"
	"go/token"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// recordedCallerNodes returns the callgraph nodes whose outgoing edges walkGraph
// records: every module function plus every dependency function whose real
// source body was built into SSA. Dependencies are registered type-only by
// default, so the dependency set is empty until the dependency-body tier builds
// their syntax; recording their internal edges then needs no further change
// here. A dependency-internal edge recovered this way belongs to the dependency
// module's own completeness accounting, not the target module's — the target's
// completeness is fixed by its own build fidelity and is unaffected by which
// caller nodes are recorded here.
func recordedCallerNodes(cg *callgraph.Graph, coord fetchdomain.ModuleCoordinate) map[*callgraph.Node]bool {
	recorded := make(map[*callgraph.Node]bool)
	for fn, node := range cg.Nodes {
		if fn == nil {
			continue
		}
		if fnInModule(fn, coord) || fnHasRealBody(fn) {
			recorded[node] = true
		}
	}
	return recorded
}

func (a *Analyser) walkGraph(
	ctx context.Context,
	cg *callgraph.Graph,
	recordedCallers map[*callgraph.Node]bool,
	coord fetchdomain.ModuleCoordinate,
	fset *token.FileSet,
	tempDir string,
) ([]domain.CallNode, []domain.CallEdge, domain.CallGraphStatus) {
	seenNodes := make(map[string]domain.CallNode)
	seenEdges := make(map[string]struct{})
	var edges []domain.CallEdge

	// Cache for built nodes to avoid redundant buildNode calls
	nodeCache := make(map[*ssa.Function]domain.CallNode)

	walkErr := callgraph.GraphVisitEdges(cg, func(edge *callgraph.Edge) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if edge.Caller.Func == nil || edge.Callee.Func == nil {
			return nil
		}

		// Record edges from module callers and from dependency callers whose
		// body was built into SSA; skip everything else.
		if !recordedCallers[edge.Caller] {
			return nil
		}

		callerFunc := edge.Caller.Func
		calleeFunc := edge.Callee.Func

		callerNode, ok := nodeCache[callerFunc]
		if !ok {
			callerNode = buildNode(callerFunc, coord, fset, tempDir)
			nodeCache[callerFunc] = callerNode
		}

		calleeNode, ok := nodeCache[calleeFunc]
		if !ok {
			calleeNode = buildNode(calleeFunc, coord, fset, tempDir)
			nodeCache[calleeFunc] = calleeNode
		}

		sitePosFile := ""
		sitePosLine := 0
		if edge.Site != nil {
			p := fset.Position(edge.Site.Pos())
			if p.IsValid() {
				sitePosFile = relativePath(p.Filename, tempDir)
				sitePosLine = p.Line
			}
		}

		ek := edgeKey(callerNode.ID, calleeNode.ID, sitePosFile, sitePosLine)

		if _, dup := seenEdges[ek]; !dup {
			seenEdges[ek] = struct{}{}
			confidence, reflectDispatch := classifyConfidence(edge)
			edges = append(edges, domain.CallEdge{
				FromID: callerNode.ID,
				ToID:   calleeNode.ID,
				CallSite: domain.SourcePosition{
					File: sitePosFile,
					Line: sitePosLine,
				},
				Confidence:      confidence,
				ReflectDispatch: reflectDispatch,
			})
		}

		if _, ok := seenNodes[callerNode.ID]; !ok {
			seenNodes[callerNode.ID] = callerNode
		}
		if _, ok := seenNodes[calleeNode.ID]; !ok {
			seenNodes[calleeNode.ID] = calleeNode
		}
		return nil
	})

	status := domain.CallGraphStatusExtracted
	if walkErr != nil && ctx.Err() != nil {
		status = domain.CallGraphStatusCancelled
	}

	nodes := make([]domain.CallNode, 0, len(seenNodes))
	for _, n := range seenNodes {
		nodes = append(nodes, n)
	}
	return nodes, edges, status
}
