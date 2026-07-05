package staticcha

import (
	"context"
	"fmt"
	"go/token"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

func (a *Analyser) walkGraph(
	ctx context.Context,
	cg *callgraph.Graph,
	moduleNodes map[*callgraph.Node]bool,
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

		// Only interested in edges originating from the current module
		if !moduleNodes[edge.Caller] {
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

		edgeKey := callerNode.ID + "\x00" + calleeNode.ID + "\x00" +
			sitePosFile + "\x00" + fmt.Sprintf("%d", sitePosLine)

		if _, dup := seenEdges[edgeKey]; !dup {
			seenEdges[edgeKey] = struct{}{}
			edges = append(edges, domain.CallEdge{
				FromID: callerNode.ID,
				ToID:   calleeNode.ID,
				CallSite: domain.SourcePosition{
					File: sitePosFile,
					Line: sitePosLine,
				},
				Confidence: classifyConfidence(edge),
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
