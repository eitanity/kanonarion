package staticcha

import (
	"context"
	"go/token"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"

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
//
// The set is then closed over the method wrappers those callers reach. A
// wrapper is not a caller either of those two tests admits — nobody wrote it and
// it belongs to no package — but it is the hop a method value goes through, and
// dropping its outgoing edge truncates the invocation path one short of the
// function that actually runs. See admitReachedWrappers.
func recordedCallerNodes(cg *callgraph.Graph, coord coordinate.ModuleCoordinate) map[*callgraph.Node]bool {
	recorded := make(map[*callgraph.Node]bool)
	for fn, node := range cg.Nodes {
		if fn == nil {
			continue
		}
		if fnInModule(fn, coord) || fnHasRealBody(fn) {
			recorded[node] = true
		}
	}
	admitReachedWrappers(cg, recorded)
	return recorded
}

// admitReachedWrappers grows recorded to include every method wrapper a
// recorded caller reaches, transitively, so the wrapper's own outgoing edges
// are recorded too.
//
// Why the caller filter needed splitting. walkGraph asked fnHasRealBody whether
// to record a node's outgoing edges, and fnHasRealBody answers a different
// question — whether the node is a real dispatch site worth devirtualizing,
// where excluding synthetic wrappers is deliberate and correct (see devirt.go,
// and the assertion that pins it). A wrapper has no body worth analysing and is
// still the only thing that knows which method a method value invokes. The two
// questions now have two predicates; fnHasRealBody keeps its meaning.
//
// Why it is a closure from the recorded set rather than every wrapper in the
// program. SSA materialises a wrapper for every method in every runtime type,
// most of which nothing in the analysed module goes near. Recording those would
// attach a floating subgraph of callees to nodes no recorded caller reaches.
// The wrappers that matter are the ones something reaches: by CALLING one — a
// dynamic call whose signature the wrapper matches — or by TAKING its value at
// a registration site AND having the reference land on the wrapper itself.
//
// That second qualification is the whole of it, and it is why the seed asks
// resolveWrapped the same question the reference edge asks. When a reference
// resolves THROUGH the wrapper, which is the concrete-method case, the graph
// already names the method and the wrapper never appears; giving it edges then
// would add a node with callees and no callers, reachable from nothing. When
// the reference cannot resolve through, which is the interface-method case, the
// wrapper IS in the graph as the reference's target, and without its own edges
// it is the dead end this exists to close.
//
// Nothing here decides confidence. The wrapper's outgoing edges are classified
// by the same rule as any other edge, which is what keeps the concrete and
// interface cases apart: a wrapper over a concrete method makes one static
// call and its edge is Direct, while a wrapper over an interface method makes
// an invoke and its edges are the class-hierarchy over-approximation, ranked as
// such. A path across both is only as good as its weakest hop, and composing
// that is the reader's side of the boundary, not this one's.
func admitReachedWrappers(cg *callgraph.Graph, recorded map[*callgraph.Node]bool) {
	frontier := make([]*callgraph.Node, 0, len(recorded))
	for node := range recorded {
		frontier = append(frontier, node)
	}

	admit := func(fn *ssa.Function) {
		if !fnIsMethodWrapper(fn) {
			return
		}
		node := cg.Nodes[fn]
		if node == nil || recorded[node] {
			return
		}
		recorded[node] = true
		frontier = append(frontier, node)
	}

	for len(frontier) > 0 {
		node := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]

		for _, edge := range node.Out {
			if edge.Callee != nil {
				admit(edge.Callee.Func)
			}
		}
		if node.Func == nil {
			continue
		}
		for _, blk := range node.Func.Blocks {
			for _, instr := range blk.Instrs {
				for _, target := range referencedFuncs(instr) {
					if resolveWrapped(target) != target {
						continue
					}
					admit(target)
				}
			}
		}
	}
}

// fnIsMethodWrapper reports whether fn is an SSA-materialised method wrapper
// with a built body: the "$bound" thunk for a method value, the "$thunk" for a
// method expression, and the promoted/indirected wrapper for a method reached
// through an embedded field or a pointer.
//
// The three tests are all needed and none is a proxy for the others. Synthetic
// excludes everything anybody wrote. A non-nil Object is what separates a
// wrapper, which records the declared method it stands for, from the other
// synthetic functions SSA builds — a package initialiser has none. And a
// non-empty block list separates a wrapper, whose body SSA actually built, from
// a function loaded from type information alone, which carries an object and a
// signature and no code: admitting those would silently promote the entire
// type-only dependency tier into the recorded caller set, which is a different
// decision than this one and not one to make by accident.
func fnIsMethodWrapper(fn *ssa.Function) bool {
	return fn != nil && fn.Synthetic != "" && fn.Object() != nil && len(fn.Blocks) > 0
}

func (a *Analyser) walkGraph(
	ctx context.Context,
	cg *callgraph.Graph,
	recordedCallers map[*callgraph.Node]bool,
	coord coordinate.ModuleCoordinate,
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
