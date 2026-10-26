package staticcha

import (
	"context"
	"fmt"
	"go/token"
	"log/slog"
	"strings"

	"code.eitanity.com/kanonarion/internal/callgraph/adapters/analyser/staticcha/tinycgo"
	"code.eitanity.com/kanonarion/internal/callgraph/adapters/analyser/staticcha/tinylower"
	"code.eitanity.com/kanonarion/internal/callgraph/domain"

	"golang.org/x/tools/go/ssa"
)

// tinyGoGraph is the walked graph the TinyGo passes add to: new endpoints become
// nodes, and an edge at a key the graph already holds is not added again.
type tinyGoGraph struct {
	mem       moduleMembership
	fset      *token.FileSet
	roots     sourceRoots
	nodes     []domain.CallNode
	edges     []domain.CallEdge
	index     map[string]int
	seenEdges map[edgeKey]struct{}
	added     map[domain.EdgeKind]int
}

func newTinyGoGraph(mem moduleMembership, fset *token.FileSet, roots sourceRoots, nodes []domain.CallNode, edges []domain.CallEdge) *tinyGoGraph {
	g := &tinyGoGraph{
		mem: mem, fset: fset, roots: roots, nodes: nodes, edges: edges,
		index:     make(map[string]int, len(nodes)),
		seenEdges: make(map[edgeKey]struct{}, len(edges)),
		added:     make(map[domain.EdgeKind]int),
	}
	for i, n := range nodes {
		g.index[n.ID] = i
	}
	for _, e := range edges {
		g.seenEdges[newEdgeKey(e.FromID, e.ToID, e.CallSite.File, e.CallSite.Line)] = struct{}{}
	}
	return g
}

func (g *tinyGoGraph) node(fn *ssa.Function) int {
	id := nodeID(fn)
	if i, ok := g.index[id]; ok {
		return i
	}
	g.nodes = append(g.nodes, buildNode(fn, g.mem, g.fset, g.roots))
	g.index[id] = len(g.nodes) - 1
	return len(g.nodes) - 1
}

func (g *tinyGoGraph) position(pos token.Pos) domain.SourcePosition {
	if g.fset == nil || pos == token.NoPos {
		return domain.SourcePosition{}
	}
	p := g.fset.Position(pos)
	if !p.IsValid() {
		return domain.SourcePosition{}
	}
	return g.roots.position(p)
}

func (g *tinyGoGraph) edge(from, to *ssa.Function, pos token.Pos, kind domain.EdgeKind) {
	if from == to {
		return
	}
	fromID, toID := g.nodes[g.node(from)].ID, g.nodes[g.node(to)].ID
	site := g.position(pos)
	key := newEdgeKey(fromID, toID, site.File, site.Line)
	if _, dup := g.seenEdges[key]; dup {
		return
	}
	g.seenEdges[key] = struct{}{}
	g.edges = append(g.edges, domain.CallEdge{FromID: fromID, ToID: toID, CallSite: site, Confidence: domain.ConfidenceDirect, Kind: kind})
	g.added[kind]++
}

// addTinyGoEdges adds, under a TinyGo frame only, what TinyGo supplies beyond
// the source's calls: the runtime calls its compiler emits, the bodies
// //go:linkname supplies, and the interrupt handlers installed by value. It
// returns a sentence naming the edge class it could not add, or "".
func (a *Analyser) addTinyGoEdges(
	ctx context.Context,
	prog *ssa.Program,
	funcs []*ssa.Function,
	g *tinyGoGraph,
	links map[string]linknameDecl,
) string {
	if !a.tinygo.Declared() || prog == nil {
		return ""
	}
	gap := ""
	if table, ok := tinylower.ForVersion(a.tinygo.Version()); ok {
		addCompilerInserted(ctx, prog, funcs, g, table, a.lowerConfig())
		if a.tinygo.BuildsWasm() {
			attachNamedExports(prog, g, table.WasmExports())
		}
	} else {
		gap = fmt.Sprintf("compiler-inserted runtime calls and the entry points TinyGo exports by name are not recorded: TinyGo %s is outside kanonarion's lowering table, which covers TinyGo %s",
			a.tinygo.Version(), strings.Join(tinylower.Versions(), ", "))
	}
	addLinknameEdges(funcs, g, links)
	attachInterruptHandlers(funcs, g)
	a.logger.InfoContext(ctx, "callgraph_tinygo_edges",
		slog.Int("compiler_inserted", g.added[domain.EdgeKindCompilerInserted]),
		slog.Int("linkname", g.added[domain.EdgeKindLinkname]))
	return gap
}

// lowerConfig is what the lowering reads from the frame: the scheduler tag, and
// the target's sizes and recover support, both read off the LLVM triple.
func (a *Analyser) lowerConfig() tinylower.Config {
	cfg := tinylower.Config{Scheduler: "none", Recover: true}
	for _, t := range a.tinygo.Tags() {
		if s, ok := strings.CutPrefix(t, "scheduler."); ok {
			cfg.Scheduler = s
		}
	}
	triple := a.tinygo.LLVMTriple()
	if strings.HasPrefix(triple, "wasm32") || strings.HasPrefix(triple, "xtensa") {
		cfg.Recover = false
	}
	if sizes, err := tinycgo.SizesFor(triple); err == nil {
		cfg.Sizes = sizes
	}
	return cfg
}

// bodyRecorded is the caller set walkGraph records edges out of.
func bodyRecorded(fn *ssa.Function, mem moduleMembership) bool {
	return fnInModule(fn, mem) || fnHasRealBody(fn)
}

// programFunc is the package-level function pkg.name the program holds, nil when
// the closure has no such function.
func programFunc(prog *ssa.Program, pkg, name string) *ssa.Function {
	p := prog.ImportedPackage(pkg)
	if p == nil {
		return nil
	}
	return p.Func(name)
}

func addCompilerInserted(ctx context.Context, prog *ssa.Program, funcs []*ssa.Function, g *tinyGoGraph, table *tinylower.Table, cfg tinylower.Config) {
	for _, fn := range funcs {
		if ctx.Err() != nil {
			return
		}
		if !bodyRecorded(fn, g.mem) {
			continue
		}
		for _, site := range tinylower.Sites(fn, cfg) {
			for _, c := range table.Callees(site.Op) {
				if target := programFunc(prog, c.Pkg, c.Name); target != nil {
					g.edge(fn, target, site.Pos, domain.EdgeKindCompilerInserted)
				}
			}
		}
	}
}

// attachNamedExports stamps the functions the release exports to the
// WebAssembly host by name with the directive a source //go:wasmexport would
// give them, when the record holds them.
func attachNamedExports(prog *ssa.Program, g *tinyGoGraph, exports []tinylower.NamedExport) {
	for _, e := range exports {
		fn := programFunc(prog, e.Pkg, e.Name)
		if fn == nil {
			continue
		}
		if i, ok := g.index[nodeID(fn)]; ok {
			g.nodes[i].ExportDirective = domain.ExportDirective{Kind: domain.ExportWasm, Name: e.Symbol}
		}
	}
}

// addLinknameEdges joins each declaration without a body that the graph holds
// to the function linked under its symbol: push, where the implementing package
// names the declaration, and pull, where the declaration names its implementation.
func addLinknameEdges(funcs []*ssa.Function, g *tinyGoGraph, links map[string]linknameDecl) {
	defs := make(map[string]*ssa.Function)
	for _, fn := range funcs {
		if fnHasRealBody(fn) && isPackageFunc(fn) {
			defs[linkSymbol(fn, links)] = fn
		}
	}
	for _, fn := range funcs {
		if len(fn.Blocks) > 0 || !isPackageFunc(fn) {
			continue
		}
		if _, isNode := g.index[nodeID(fn)]; !isNode {
			continue
		}
		def := defs[linkSymbol(fn, links)]
		if def == nil {
			continue
		}
		site := fn.Pos()
		if _, pushed := links[nodeID(def)]; pushed {
			site = def.Pos()
		}
		g.edge(fn, def, site, domain.EdgeKindLinkname)
	}
}

func isPackageFunc(fn *ssa.Function) bool {
	return fn.Pkg != nil && fn.Parent() == nil && fn.Signature.Recv() == nil && fn.Synthetic == "" && fn.Origin() == nil
}

// linkSymbol is the symbol TinyGo links fn under: its //go:linkname target, or
// its package path and name, the main package being "main" (symbol.go:328).
func linkSymbol(fn *ssa.Function, links map[string]linknameDecl) string {
	if l, ok := links[nodeID(fn)]; ok {
		return l.symbol
	}
	pkg := fn.Pkg.Pkg
	prefix := pkg.Path()
	if pkg.Name() == "main" {
		prefix = "main"
	}
	return prefix + "." + fn.Name()
}

// attachInterruptHandlers stamps the handler of every runtime/interrupt.New call
// whose handler resolves statically: a named function, a method value (the
// method it binds) or a function literal.
func attachInterruptHandlers(funcs []*ssa.Function, g *tinyGoGraph) {
	found := make(map[*ssa.Function]domain.SourcePosition)
	for _, fn := range funcs {
		if !bodyRecorded(fn, g.mem) {
			continue
		}
		for _, b := range fn.Blocks {
			for _, in := range b.Instrs {
				call, ok := in.(*ssa.Call)
				if !ok || !isInterruptNew(call.Common().StaticCallee()) || len(call.Common().Args) != 2 {
					continue
				}
				h := handlerFunc(call.Common().Args[1])
				site := g.position(call.Pos())
				if h == nil || site.File == "" {
					continue
				}
				if prev, seen := found[h]; !seen || positionLess(site, prev) {
					found[h] = site
				}
			}
		}
	}
	for h, site := range found {
		g.nodes[g.node(h)].InterruptHandler = domain.InterruptHandler{Kind: domain.HandlerInterruptNew, Site: site}
	}
}

func positionLess(a, b domain.SourcePosition) bool {
	if a.File != b.File {
		return a.File < b.File
	}
	return a.Line < b.Line
}

func isInterruptNew(fn *ssa.Function) bool {
	return fn != nil && fn.Pkg != nil && fn.Pkg.Pkg.Path() == "runtime/interrupt" && fn.Name() == "New"
}

func handlerFunc(v ssa.Value) *ssa.Function {
	switch h := v.(type) {
	case *ssa.Function:
		return resolveWrapped(h)
	case *ssa.MakeClosure:
		if fn, ok := h.Fn.(*ssa.Function); ok {
			return resolveWrapped(fn)
		}
	case *ssa.ChangeType:
		return handlerFunc(h.X)
	}
	return nil
}
