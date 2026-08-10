package staticcha

import (
	"go/types"
	"sort"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/types/typeutil"
)

// The function set an analysis reads must be a function of the program alone.
// ssautil.AllFunctions is not: it derives most of the set from
// (*ssa.Program).RuntimeTypes, and that enumeration answers differently on
// successive calls to one unchanged program.
//
// The enumeration walks the element types reachable from the types the program
// converts to interfaces, de-duplicating as it goes on a map keyed by type
// identity. Aliases are identical to what they alias, so `os.FileMode` and
// `io/fs.FileMode` are one key. Reaching the alias spelling first takes the key
// and then stops the walk at the alias, so the pointer type `*io/fs.FileMode`
// — which is only ever derived by the named-type case — is never reached.
// Reaching the named spelling first derives it. Which arrives first is Go map
// iteration order over the program's interface conversions, so the answer
// changes from call to call.
//
// Measured on one unchanged tree: five consecutive enumerations of one program
// returned five different sets, differing in about seventy types. Downstream
// that decides whether a pointer-receiver method wrapper exists as a function
// at all, which decides whether the class hierarchy resolves interface call
// sites to it — so the same bytes analysed twice produced graphs that differed
// by a few nodes and a handful of edges.
//
// This file re-derives the closure instead, to a fixpoint and unaliasing before
// de-duplication, so the result depends on the program and not on the order a
// map was walked.

// visitState records which of the two visit modes a type has already had. A
// type reached only as a skipped intermediate is not part of the answer, but a
// later unskipped path still puts it there, so the two modes are tracked
// separately and neither prunes the other.
type visitState struct{ skipDone, keepDone bool }

// runtimeTypeClosure returns every type whose method set the program can reach
// through an interface, closed over element types.
//
// A type is in the answer when some path reaches it as a value in its own
// right. Paths that only pass through it — a method signature's parameter
// tuple, the unnamed type underlying a named one — recurse without putting it
// in the answer, because reflection offers no way to arrive at those and their
// method sets are not reachable. That is the rule the SSA library's own
// enumeration states; what differs here is that it is applied to a fixpoint
// over unaliased types, so the answer does not depend on which spelling of a
// type the walk met first.
func runtimeTypeClosure(prog *ssa.Program) []types.Type {
	var seen typeutil.Map
	var msets typeutil.MethodSetCache
	var out []types.Type

	var visit func(T types.Type, skip bool)
	visit = func(T types.Type, skip bool) {
		u := types.Unalias(T)
		st, _ := seen.At(u).(*visitState)
		if st == nil {
			st = &visitState{}
			seen.Set(u, st)
		}
		if skip {
			if st.skipDone {
				return
			}
			st.skipDone = true
		} else {
			if st.keepDone {
				return
			}
			st.keepDone = true
			out = append(out, u)
		}

		// Recursion over the signatures of each method: the parameter and result
		// types are reachable by reflection from the method, the tuples holding
		// them are not.
		mset := msets.MethodSet(u)
		for i := range mset.Len() {
			sig, ok := mset.At(i).Type().(*types.Signature)
			if !ok || sig.TypeParams() != nil {
				continue
			}
			visit(sig.Params(), true)
			visit(sig.Results(), true)
		}

		switch t := u.(type) {
		case *types.Basic, *types.Interface, *types.TypeParam, *types.Union:
			// No elements to reach: a basic type has none, an interface's methods
			// are handled by the method-set recursion above, and a parameterised
			// type has no runtime type of its own.
		case *types.Pointer:
			visit(t.Elem(), false)
		case *types.Slice:
			visit(t.Elem(), false)
		case *types.Array:
			visit(t.Elem(), false)
		case *types.Chan:
			visit(t.Elem(), false)
		case *types.Map:
			visit(t.Key(), false)
			visit(t.Elem(), false)
		case *types.Signature:
			visit(t.Params(), true)
			visit(t.Results(), true)
		case *types.Struct:
			for i := range t.NumFields() {
				visit(t.Field(i).Type(), false)
			}
		case *types.Tuple:
			for i := range t.Len() {
				visit(t.At(i).Type(), false)
			}
		case *types.Named:
			if t.TypeParams() != nil {
				// A generic type has no runtime type; its instantiations do, and they
				// arrive here on their own.
				return
			}
			// A pointer to a named type is reachable from the named type by
			// reflection and carries its own method set. This is the derivation the
			// alias collision loses.
			visit(types.NewPointer(t), false)
			// The unnamed type underlying a named one is passed through: reflection
			// reaches the fields of an embedded type but not the anonymous struct
			// itself, so its method set is not wanted.
			visit(t.Underlying(), true)
		}
	}

	for _, T := range prog.RuntimeTypes() {
		visit(T, false)
	}
	return out
}

// closedFunctionSet returns the functions of prog an analysis may see: every
// package-level function, everything those bodies name, and the method values
// of every type reachable through an interface.
//
// Materialising a method value creates the wrapper as a side effect, so this
// both computes the set and fixes it. Nothing after this point can grow the
// program's function population, which is what makes the graph built from it
// reproducible.
func closedFunctionSet(prog *ssa.Program) map[*ssa.Function]bool {
	seen := make(map[*ssa.Function]bool)

	var function func(fn *ssa.Function)
	function = func(fn *ssa.Function) {
		if fn == nil || seen[fn] {
			return
		}
		seen[fn] = true
		var buf [10]*ssa.Value // avoid alloc in the common case
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				for _, op := range instr.Operands(buf[:0]) {
					if callee, ok := (*op).(*ssa.Function); ok {
						function(callee)
					}
				}
			}
		}
	}

	methodsOf := func(T types.Type) {
		if types.IsInterface(T) {
			return
		}
		mset := prog.MethodSets.MethodSet(T)
		for i := range mset.Len() {
			sel := mset.At(i)
			if sel.Obj().(*types.Func).Signature().TypeParams() != nil {
				continue // a generic method has no single function
			}
			function(prog.MethodValue(sel))
		}
	}

	for _, pkg := range prog.AllPackages() {
		syntactic := pkgBuiltFromSyntax(pkg)
		for _, mem := range pkg.Members {
			switch mem := mem.(type) {
			case *ssa.Function:
				function(mem)
			case *ssa.Type:
				// The methods of an exported named type are treated as roots even
				// where no body names them: a client of the package can call them,
				// and a library analysed on its own has no other entry point. This
				// applies only to packages built from syntax — the same restriction
				// the SSA library's own enumeration makes — so a dependency present
				// as type information alone does not drag its whole method surface
				// in. Aliases and interfaces name no method set of their own.
				if !syntactic {
					continue
				}
				named, ok := types.Unalias(mem.Type()).(*types.Named)
				if !ok || named.TypeParams() != nil || !mem.Object().Exported() {
					continue
				}
				if types.IsInterface(named) {
					continue
				}
				methodsOf(named)
				methodsOf(types.NewPointer(named))
			}
		}
	}

	for _, T := range runtimeTypeClosure(prog) {
		methodsOf(T)
	}

	return seen
}

// pkgBuiltFromSyntax reports whether pkg was built from source rather than
// registered from type information alone. A package built from syntax has at
// least one function with a body; a type-only package has none.
func pkgBuiltFromSyntax(pkg *ssa.Package) bool {
	for _, mem := range pkg.Members {
		if fn, ok := mem.(*ssa.Function); ok && len(fn.Blocks) > 0 {
			return true
		}
	}
	return false
}

// orderedFunctions puts a closed function set into a fixed order, so a pass
// that sweeps it visits the same functions in the same sequence on every run.
// The set alone is not enough: a sweep that records the first fact it meets for
// a given key would otherwise let map order pick which fact that is.
func orderedFunctions(funcs map[*ssa.Function]bool) []*ssa.Function {
	out := make([]*ssa.Function, 0, len(funcs))
	for fn := range funcs {
		out = append(out, fn)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if as, bs := a.String(), b.String(); as != bs {
			return as < bs
		}
		// Two functions can print the same — an anonymous function inside two
		// instantiations of a generic, say — so position breaks the tie.
		ap, bp := a.Prog.Fset.Position(a.Pos()), b.Prog.Fset.Position(b.Pos())
		if ap.Filename != bp.Filename {
			return ap.Filename < bp.Filename
		}
		return ap.Offset < bp.Offset
	})
	return out
}
