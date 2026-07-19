package staticcha

import (
	"context"
	"fmt"
	"go/token"
	"go/types"
	"log/slog"
	"strings"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// devirtualizeSingleImplementer recovers interface-dispatch edges that CHA
// silently drops when the sole implementer's method body was never built into
// SSA (a type-only dependency or an unbuilt package). CHA binds an invoke
// i.M() only to implementer methods present in the built SSA set, so when the
// one type that implements an interface lives in a package that was registered
// type-only, CHA emits no edge at all.
//
// For each invoke site i.M() inside the analysed module, this pass computes the
// implementers of the interface over the full type-checked package set (whose
// types.Packages persist even for unbuilt packages). When exactly one concrete
// type implements it, an edge to that type's M is added: if M has a built SSA
// function the edge targets that node; otherwise a leaf node is synthesised so
// the edge — and the completeness signal it carries — still exists. Onward
// edges from an unbuilt body are out of scope (KN-425/KN-427).
//
// The pass is additive and sound: it only adds edges the type hierarchy permits
// and that CHA would itself have added had the body been built, so it cannot
// reduce soundness. Multi-implementer sites are left to CHA/VTA (KN-424). Because
// the interface site resolves to a single concrete implementer, the added edges
// name a unique callee and are tagged Direct — no over-approximation remains.
// Determinism comes from the caller's final Sort; the set of added edges is
// independent of traversal order.
func (a *Analyser) devirtualizeSingleImplementer(
	ctx context.Context,
	prog *ssa.Program,
	coord fetchdomain.ModuleCoordinate,
	fset *token.FileSet,
	tempDir string,
	nodes []domain.CallNode,
	edges []domain.CallEdge,
) ([]domain.CallNode, []domain.CallEdge) {
	universe := concreteNamedTypes(prog)
	if len(universe) == 0 {
		return nodes, edges
	}

	// soleCache memoises each interface's sole implementer (nil when the
	// implementer count is not exactly one). Many invoke sites share an
	// interface, so resolving implementers once per interface bounds the cost.
	soleCache := make(map[*types.Interface]*types.Named)
	resolved := make(map[*types.Interface]struct{})

	existingNodes := make(map[string]struct{}, len(nodes))
	for _, n := range nodes {
		existingNodes[n.ID] = struct{}{}
	}
	existingEdges := make(map[string]struct{}, len(edges))
	for _, e := range edges {
		existingEdges[edgeKey(e.FromID, e.ToID, e.CallSite.File, e.CallSite.Line)] = struct{}{}
	}

	var addedEdges, addedNodes, leafNodes int

	for fn := range ssautil.AllFunctions(prog) {
		if ctx.Err() != nil {
			break
		}
		if !fnInModule(fn, coord) {
			continue
		}

		var callerNode domain.CallNode
		callerBuilt := false

		for _, blk := range fn.Blocks {
			for _, instr := range blk.Instrs {
				ci, ok := instr.(ssa.CallInstruction)
				if !ok {
					continue
				}
				common := ci.Common()
				if !common.IsInvoke() {
					continue
				}
				ifaceT, ok := common.Value.Type().Underlying().(*types.Interface)
				if !ok || ifaceT.NumMethods() == 0 {
					continue
				}

				sole := soleImplementer(ifaceT, universe, soleCache, resolved)
				if sole == nil {
					continue
				}
				methodObj := implementerMethod(sole, common.Method)
				if methodObj == nil {
					continue
				}
				target := a.devirtTargetNode(prog, methodObj, coord, fset, tempDir)
				if target.ID == "" {
					continue
				}

				// Build the caller node lazily so functions with no
				// devirtualizable site cost nothing.
				if !callerBuilt {
					callerNode = buildNode(fn, coord, fset, tempDir)
					callerBuilt = true
				}

				siteFile, siteLine := sitePosition(instr, fset, tempDir)
				ek := edgeKey(callerNode.ID, target.ID, siteFile, siteLine)
				if _, dup := existingEdges[ek]; dup {
					continue
				}
				existingEdges[ek] = struct{}{}

				edges = append(edges, domain.CallEdge{
					FromID: callerNode.ID,
					ToID:   target.ID,
					CallSite: domain.SourcePosition{
						File: siteFile,
						Line: siteLine,
					},
					Confidence: domain.ConfidenceDirect,
				})
				addedEdges++
				a.logger.DebugContext(ctx, "callgraph_devirtualized_edge",
					slog.String("from", callerNode.ID),
					slog.String("to", target.ID),
					slog.String("site", fmt.Sprintf("%s:%d", siteFile, siteLine)),
				)

				if _, ok := existingNodes[callerNode.ID]; !ok {
					existingNodes[callerNode.ID] = struct{}{}
					nodes = append(nodes, callerNode)
					addedNodes++
				}
				if _, ok := existingNodes[target.ID]; !ok {
					existingNodes[target.ID] = struct{}{}
					nodes = append(nodes, target)
					addedNodes++
					if prog.FuncValue(methodObj) == nil {
						leafNodes++
					}
				}
			}
		}
	}

	if addedEdges > 0 {
		a.logger.InfoContext(ctx, "callgraph_devirtualized_single_implementer",
			slog.Int("added_edges", addedEdges),
			slog.Int("added_nodes", addedNodes),
			slog.Int("leaf_nodes", leafNodes),
		)
	}
	return nodes, edges
}

// concreteNamedTypes returns every package-scope concrete named type across the
// program's packages — the analysed module's own types plus every type-checked
// dependency (whose types.Package persists even when its SSA was never built).
// Interfaces and generic (uninstantiated) named types are excluded; they cannot
// be the concrete target of a devirtualized call.
func concreteNamedTypes(prog *ssa.Program) []*types.Named {
	var out []*types.Named
	for _, pkg := range prog.AllPackages() {
		if pkg == nil || pkg.Pkg == nil {
			continue
		}
		scope := pkg.Pkg.Scope()
		for _, name := range scope.Names() {
			tn, ok := scope.Lookup(name).(*types.TypeName)
			if !ok {
				continue
			}
			named, ok := tn.Type().(*types.Named)
			if !ok {
				continue
			}
			if named.TypeParams().Len() > 0 {
				continue
			}
			if _, isIface := named.Underlying().(*types.Interface); isIface {
				continue
			}
			out = append(out, named)
		}
	}
	return out
}

// soleImplementer returns the single concrete type in universe that implements
// ifaceT, or nil when zero or more than one type does. The interface's method
// set is honoured against both the value and pointer forms of each candidate,
// matching CHA's own value/pointer treatment. Results are memoised per
// interface.
func soleImplementer(
	ifaceT *types.Interface,
	universe []*types.Named,
	cache map[*types.Interface]*types.Named,
	resolved map[*types.Interface]struct{},
) *types.Named {
	if _, done := resolved[ifaceT]; done {
		return cache[ifaceT]
	}

	var found *types.Named
	count := 0
	for _, c := range universe {
		if implementsInterface(c, ifaceT) {
			found = c
			count++
			if count > 1 {
				break
			}
		}
	}

	var result *types.Named
	if count == 1 {
		result = found
	}
	cache[ifaceT] = result
	resolved[ifaceT] = struct{}{}
	return result
}

// implementsInterface reports whether the value or pointer form of named
// satisfies ifaceT.
func implementsInterface(named *types.Named, ifaceT *types.Interface) bool {
	if types.Implements(named, ifaceT) {
		return true
	}
	return types.Implements(types.NewPointer(named), ifaceT)
}

// implementerMethod resolves the concrete method on named that satisfies the
// interface method ifaceMethod, considering pointer-receiver methods.
func implementerMethod(named *types.Named, ifaceMethod *types.Func) *types.Func {
	name := ifaceMethod.Name()
	pkg := ifaceMethod.Pkg()
	if obj, _, _ := types.LookupFieldOrMethod(named, true, pkg, name); obj != nil {
		if f, ok := obj.(*types.Func); ok {
			return f
		}
	}
	if obj, _, _ := types.LookupFieldOrMethod(types.NewPointer(named), true, pkg, name); obj != nil {
		if f, ok := obj.(*types.Func); ok {
			return f
		}
	}
	return nil
}

// devirtTargetNode returns the graph node for methodObj: the existing SSA node
// when the method body was built, or a synthesised leaf node when it was not
// (type-only dependency / unbuilt package). The leaf carries no onward edges —
// that is the completeness/verdict concern (KN-425/KN-427).
func (a *Analyser) devirtTargetNode(
	prog *ssa.Program,
	methodObj *types.Func,
	coord fetchdomain.ModuleCoordinate,
	fset *token.FileSet,
	tempDir string,
) domain.CallNode {
	if fn := prog.FuncValue(methodObj); fn != nil {
		return buildNode(fn, coord, fset, tempDir)
	}
	return leafNodeFromFunc(methodObj, coord, fset, tempDir)
}

// leafNodeFromFunc builds a CallNode for a method whose SSA function was never
// built, deriving the ID and metadata from go/types so it matches the format
// buildNode would have produced for the same method.
func leafNodeFromFunc(
	methodObj *types.Func,
	coord fetchdomain.ModuleCoordinate,
	fset *token.FileSet,
	tempDir string,
) domain.CallNode {
	sig, ok := methodObj.Type().(*types.Signature)
	if !ok || sig.Recv() == nil || methodObj.Pkg() == nil {
		return domain.CallNode{}
	}
	pkgPath := methodObj.Pkg().Path()
	recv := recvTypeStr(sig.Recv().Type())
	symbol := methodObj.Name()

	isExternal := pkgPath != coord.Path && !strings.HasPrefix(pkgPath, coord.Path+"/")

	pos := domain.SourcePosition{}
	if methodObj.Pos() != token.NoPos && fset != nil {
		if p := fset.Position(methodObj.Pos()); p.IsValid() {
			pos = domain.SourcePosition{
				File: relativePath(p.Filename, tempDir),
				Line: p.Line,
			}
		}
	}

	module := ""
	if !isExternal {
		module = coord.Path
	}

	return domain.CallNode{
		ID:            pkgPath + ".(" + recv + ")." + symbol,
		Module:        module,
		Package:       pkgPath,
		Symbol:        symbol,
		Receiver:      recv,
		IsExternal:    isExternal,
		IsExportedAPI: !isExternal && token.IsExported(symbol) && !isInternalPkg(pkgPath),
		Position:      pos,
	}
}

// fnInModule reports whether fn belongs to a package in the analysed module.
func fnInModule(fn *ssa.Function, coord fetchdomain.ModuleCoordinate) bool {
	if fn.Package() == nil || fn.Package().Pkg == nil {
		return false
	}
	p := fn.Package().Pkg.Path()
	return p == coord.Path || strings.HasPrefix(p, coord.Path+"/")
}

// sitePosition returns the module-relative file and line of a call
// instruction's source position, empty/zero when it has none.
func sitePosition(instr ssa.Instruction, fset *token.FileSet, tempDir string) (string, int) {
	if fset == nil || instr.Pos() == token.NoPos {
		return "", 0
	}
	p := fset.Position(instr.Pos())
	if !p.IsValid() {
		return "", 0
	}
	return relativePath(p.Filename, tempDir), p.Line
}

// edgeKey is the deduplication key for a call edge: caller, callee, and call
// site. Shared with walkGraph so devirtualized edges collapse against the ones
// CHA already emitted for the same site.
func edgeKey(fromID, toID, siteFile string, siteLine int) string {
	return fromID + "\x00" + toID + "\x00" + siteFile + "\x00" + fmt.Sprintf("%d", siteLine)
}
