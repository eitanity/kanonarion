package staticcha

import (
	"go/types"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/types/typeutil"
)

// chaCallGraph builds the class-hierarchy call graph of the given functions.
//
// It is the algorithm golang.org/x/tools/go/callgraph/cha implements — every
// concrete type is assumed to reach every interface it satisfies, so a dynamic
// call site resolves to every method that could satisfy it — with one
// difference: the function set is an argument rather than something the
// construction computes for itself. The library computes it by enumerating the
// program's runtime types, and that enumeration is not reproducible; see
// functionset.go. Taking the set as an argument is what lets one program yield
// one graph.
//
// Derived from golang.org/x/tools/go/callgraph/cha and its internal
// chautil.LazyCallees helper, Copyright 2014 The Go Authors, BSD-3-Clause.
func chaCallGraph(funcs map[*ssa.Function]bool) *callgraph.Graph {
	cg := callgraph.New(nil)
	calleesOf := chaCallees(funcs)

	for f := range funcs {
		fnode := cg.CreateNode(f)
		for _, b := range f.Blocks {
			for _, instr := range b.Instrs {
				site, ok := instr.(ssa.CallInstruction)
				if !ok {
					continue
				}
				if g := site.Common().StaticCallee(); g != nil {
					callgraph.AddEdge(fnode, site, cg.CreateNode(g))
					continue
				}
				for _, g := range calleesOf(site) {
					callgraph.AddEdge(fnode, site, cg.CreateNode(g))
				}
			}
		}
	}

	return cg
}

// chaCallees returns the resolver for dynamic call sites: for an interface
// dispatch, every method of that name whose receiver satisfies the interface;
// for any other dynamic call, every function of a matching signature.
func chaCallees(funcs map[*ssa.Function]bool) func(site ssa.CallInstruction) []*ssa.Function {
	// funcsBySig is the effective set of address-taken functions, used to
	// resolve a dynamic call of a given signature.
	var funcsBySig typeutil.Map // value is []*ssa.Function

	// methodsByID groups methods by identifier rather than by name, so an
	// interface call to a type with two unexported methods spelled the same in
	// different packages resolves to the one that satisfies the interface.
	methodsByID := make(map[string][]*ssa.Function)

	// imethod names an interface method I.m. The interface has to be carried
	// explicitly: interface embedding means one *types.Func may belong to many
	// interfaces, so the method alone does not say which one was called.
	type imethod struct {
		I  *types.Interface
		id string
	}
	memo := make(map[imethod][]*ssa.Function)
	lookupMethods := func(I *types.Interface, m *types.Func) []*ssa.Function {
		id := m.Id()
		key := imethod{I: I, id: id}
		methods, ok := memo[key]
		if !ok {
			for _, f := range methodsByID[id] {
				if types.Implements(f.Signature.Recv().Type(), I) {
					methods = append(methods, f)
				}
			}
			memo[key] = methods
		}
		return methods
	}

	for f := range funcs {
		if f.Signature.Recv() == nil {
			// A package initialiser can never be address-taken.
			if f.Name() == "init" && f.Synthetic == "package initializer" {
				continue
			}
			bySig, _ := funcsBySig.At(f.Signature).([]*ssa.Function)
			funcsBySig.Set(f.Signature, append(bySig, f))
			continue
		}
		if obj := f.Object(); obj != nil {
			id := obj.(*types.Func).Id()
			methodsByID[id] = append(methodsByID[id], f)
		}
	}

	return func(site ssa.CallInstruction) []*ssa.Function {
		call := site.Common()
		switch {
		case call.IsInvoke():
			iface, ok := call.Value.Type().Underlying().(*types.Interface)
			if !ok {
				return nil
			}
			return lookupMethods(iface, call.Method)
		case call.StaticCallee() != nil:
			return []*ssa.Function{call.StaticCallee()}
		default:
			if _, isBuiltin := call.Value.(*ssa.Builtin); isBuiltin {
				return nil
			}
			fns, _ := funcsBySig.At(call.Signature()).([]*ssa.Function)
			return fns
		}
	}
}
