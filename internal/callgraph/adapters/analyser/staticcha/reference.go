package staticcha

import (
	"context"
	"go/token"
	"log/slog"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// collectReferenceEdges records an edge for every function value TAKEN in the
// analysed code, as distinct from every function CALLED.
//
// The gap it closes. `r.Get("/confirm", h.confirmEmail)` transfers no control at
// that line: it stores a value. CHA builds edges from call instructions, so it
// records the call to r.Get and nothing about confirmEmail, and the handler ends
// up with no in-edge at all — which `callers` then reported as a measured
// absence for a function an HTTP request drives on every hit. The registration
// is the answer a reader wants, and it is visible in the SSA: the taking site
// materialises a value naming the function.
//
// Why this is a distinct kind and not a call edge. A reference says the value
// was taken, not that it was invoked. Recording it as a call would assert an
// invocation nothing witnessed, and would let a registration launder itself into
// an otherwise all-Direct call path — the exact over-approximation a
// distance-to-entry-point measurement must not inherit. Consumers read the kind;
// see domain.EdgeKind.
//
// What counts as taking a value:
//
//   - a method value, `h.Method`, which SSA materialises as a MakeClosure over a
//     synthetic "$bound" wrapper. The wrapper is resolved through to the method
//     it wraps, because the wrapper is an implementation detail and the reader
//     asked about the method;
//   - a method expression, `T.Method`, materialised as a synthetic thunk,
//     resolved the same way;
//   - a plain function used as a value — passed, stored, or returned — which SSA
//     represents as the *ssa.Function itself appearing as an operand;
//   - a closure, whose MakeClosure names the anonymous function.
//
// The callee position of a call instruction is deliberately NOT a reference: a
// static call already has a call edge, and recording the same fact twice under
// two kinds would double-count every call in the program.
func (a *Analyser) collectReferenceEdges(
	ctx context.Context,
	prog *ssa.Program,
	coord coordinate.ModuleCoordinate,
	fset *token.FileSet,
	tempDir string,
	nodes []domain.CallNode,
	edges []domain.CallEdge,
) ([]domain.CallNode, []domain.CallEdge) {
	if prog == nil {
		return nodes, edges
	}

	seenNodes := make(map[string]struct{}, len(nodes))
	for _, n := range nodes {
		seenNodes[n.ID] = struct{}{}
	}
	// Reference edges share the edge table's key with calls, so a reference at
	// the exact site of an existing call would collide with it. The call is the
	// stronger fact and keeps the key.
	seenEdges := make(map[string]struct{}, len(edges))
	for _, e := range edges {
		seenEdges[edgeKey(e.FromID, e.ToID, e.CallSite.File, e.CallSite.Line)] = struct{}{}
	}

	nodeCache := make(map[*ssa.Function]domain.CallNode)
	nodeFor := func(fn *ssa.Function) domain.CallNode {
		if n, ok := nodeCache[fn]; ok {
			return n
		}
		n := buildNode(fn, coord, fset, tempDir)
		nodeCache[fn] = n
		return n
	}

	added := 0
	for fn := range ssautil.AllFunctions(prog) {
		if ctx.Err() != nil {
			break
		}
		// The same caller set walkGraph records edges out of: the module's own
		// functions, plus any dependency whose real body was built into SSA.
		if !fnInModule(fn, coord) && !fnHasRealBody(fn) {
			continue
		}
		for _, blk := range fn.Blocks {
			for _, instr := range blk.Instrs {
				for _, target := range referencedFuncs(instr) {
					resolved := resolveWrapped(target)
					if resolved == nil || resolved == fn {
						continue
					}
					from := nodeFor(fn)
					to := nodeFor(resolved)
					file, line := sitePosition(instr, fset, tempDir)
					key := edgeKey(from.ID, to.ID, file, line)
					if _, dup := seenEdges[key]; dup {
						continue
					}
					seenEdges[key] = struct{}{}
					edges = append(edges, domain.CallEdge{
						FromID:     from.ID,
						ToID:       to.ID,
						CallSite:   domain.SourcePosition{File: file, Line: line},
						Confidence: domain.ConfidenceDirect,
						Kind:       domain.EdgeKindReference,
					})
					added++
					for _, n := range []domain.CallNode{from, to} {
						if _, ok := seenNodes[n.ID]; !ok {
							seenNodes[n.ID] = struct{}{}
							nodes = append(nodes, n)
						}
					}
				}
			}
		}
	}
	a.logger.InfoContext(ctx, "callgraph_reference_edges", slog.Int("count", added))
	return nodes, edges
}

// referencedFuncs returns the functions instr names as a VALUE rather than as a
// call target.
//
// A MakeClosure names its function directly. Every other instruction is scanned
// for *ssa.Function operands, which is how SSA represents a function used as a
// value anywhere else — an argument, a store, a return, a slice literal. The
// callee operand of a call instruction is excluded: that is a call, and it
// already has its own edge.
func referencedFuncs(instr ssa.Instruction) []*ssa.Function {
	if mc, ok := instr.(*ssa.MakeClosure); ok {
		if fn, isFunc := mc.Fn.(*ssa.Function); isFunc {
			return []*ssa.Function{fn}
		}
		return nil
	}

	var callee ssa.Value
	if call, ok := instr.(ssa.CallInstruction); ok {
		callee = call.Common().Value
	}

	var out []*ssa.Function
	for _, operand := range instr.Operands(nil) {
		if operand == nil || *operand == nil {
			continue
		}
		if callee != nil && *operand == callee {
			continue
		}
		if fn, ok := (*operand).(*ssa.Function); ok {
			out = append(out, fn)
		}
	}
	return out
}

// resolveWrapped follows a synthetic method-value or method-expression wrapper
// through to the method it wraps.
//
// SSA materialises `h.Method` as a "$bound" wrapper and `T.Method` as a thunk;
// both have a synthesised body whose only real work is one static call to the
// method. The wrapper is not the answer a reader asked for — nobody wrote it,
// and it is not addressable in source — so the reference names the method.
//
// A wrapper whose body does not resolve to exactly one static callee is returned
// unchanged rather than guessed at: naming the wrapper is honest, and inventing
// a target is not.
func resolveWrapped(fn *ssa.Function) *ssa.Function {
	if fn == nil || fn.Synthetic == "" {
		return fn
	}
	var found *ssa.Function
	for _, blk := range fn.Blocks {
		for _, instr := range blk.Instrs {
			call, ok := instr.(ssa.CallInstruction)
			if !ok {
				continue
			}
			callee := call.Common().StaticCallee()
			if callee == nil || callee == fn {
				continue
			}
			if found != nil && found != callee {
				return fn
			}
			found = callee
		}
	}
	if found == nil {
		return fn
	}
	return found
}
