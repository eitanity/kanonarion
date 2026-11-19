package staticcha

import (
	"go/types"

	"code.eitanity.com/kanonarion/internal/callgraph/domain"

	"golang.org/x/tools/go/ssa"
)

// SSA is built without InstantiateGenerics, so an owned generic's body converts
// its type parameter, never the module type it is instantiated with. Rather
// than build a body per instantiation, each owned generic records which of its
// type parameters it hands on, and each instantiation hands on its arguments.

// paramShape is one way a generic hands on type parameter index: the parameter
// itself, or a pointer to it. Any other type mentioning it counts as the
// parameter, as a []T or struct{ v T } converted carries T inside it.
type paramShape struct {
	index int
	ptr   bool
}

// apply is the shape with targs substituted.
func (s paramShape) apply(targs []types.Type) types.Type {
	t := targs[s.index]
	if s.ptr {
		return types.NewPointer(t)
	}
	return t
}

// shapeCause is the first hand-off of a shape inside the generic's body: a
// conversion to iface, or, when iface is nil, a type argument handed on.
type shapeCause struct {
	iface types.Type
}

// ownedGeneric is one generic function or method the module declares and
// builds, with the shapes of its type parameters it hands on.
type ownedGeneric struct {
	fn      *ssa.Function
	obj     *types.Func
	tparams map[*types.TypeParam]int
	shapes  map[paramShape]shapeCause
}

// handOn records that the body hands on t, whose type mentions its type
// parameters, and reports whether that added a shape.
func (g *ownedGeneric) handOn(t types.Type, cause shapeCause) bool {
	added := false
	add := func(s paramShape) {
		if _, ok := g.shapes[s]; !ok {
			g.shapes[s] = cause
			added = true
		}
	}
	if s, ok := g.shapeOf(t); ok {
		add(s)
		return added
	}
	forEachTypeParam(t, func(tp *types.TypeParam) {
		if i, ok := g.tparams[tp]; ok {
			add(paramShape{index: i})
		}
	})
	return added
}

// shapeOf is t as a shape when t is one of the generic's parameters or a
// pointer to one.
func (g *ownedGeneric) shapeOf(t types.Type) (paramShape, bool) {
	ptr := false
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		t, ptr = p.Elem(), true
	}
	tp, ok := types.Unalias(t).(*types.TypeParam)
	if !ok {
		return paramShape{}, false
	}
	i, ok := g.tparams[tp]
	return paramShape{index: i, ptr: ptr}, ok
}

// via names what an instantiation with targs hands its argument to: the
// interface the body converts to, substituted where it can be, and otherwise
// the generic itself.
func (g *ownedGeneric) via(cause shapeCause, targs []types.Type) (domain.EscapeKind, string) {
	if cause.iface != nil {
		if iface, ok := substitute(cause.iface, g.tparams, targs); ok {
			return domain.EscapeConversion, interfaceName(iface)
		}
	}
	return domain.EscapeTypeArgument, genericName(g.obj)
}

// ownedGenerics indexes the module's generic bodies by their declared object.
type ownedGenerics struct {
	byObj map[*types.Func]*ownedGeneric
	byFn  map[*ssa.Function]*ownedGeneric
}

func indexOwnedGenerics(funcs []*ssa.Function, mem moduleMembership) *ownedGenerics {
	g := &ownedGenerics{byObj: map[*types.Func]*ownedGeneric{}, byFn: map[*ssa.Function]*ownedGeneric{}}
	for _, fn := range funcs {
		if fn.Parent() != nil || fn.Origin() != nil || fn.TypeParams().Len() == 0 ||
			len(fn.Blocks) == 0 || !fnInModule(fn, mem) {
			continue
		}
		obj, ok := fn.Object().(*types.Func)
		if !ok {
			continue
		}
		og := &ownedGeneric{fn: fn, obj: obj, tparams: map[*types.TypeParam]int{}, shapes: map[paramShape]shapeCause{}}
		for i := range fn.TypeParams().Len() {
			og.tparams[fn.TypeParams().At(i)] = i
		}
		g.byObj[obj] = og
		g.byFn[fn] = og
	}
	return g
}

// enclosing is the owned generic whose body holds fn, a closure in it
// included, or nil.
func (g *ownedGenerics) enclosing(fn *ssa.Function) *ownedGeneric {
	for fn.Parent() != nil {
		fn = fn.Parent()
	}
	return g.byFn[fn]
}

// ownedSite is one place the module instantiates an owned generic: a call or
// value of it, or a conversion of a generic type whose method it is.
type ownedSite struct {
	callee *ownedGeneric
	targs  []types.Type
	// in is the generic the site sits in, nil outside one.
	in   *ownedGeneric
	cand escapeSite
	test bool
}

// instancesIn is every owned generic instance instr names, called or taken as
// a value.
func (g *ownedGenerics) instancesIn(instr ssa.Instruction) []ownedSite {
	var out []ownedSite
	for _, op := range instr.Operands(nil) {
		inst, ok := (*op).(*ssa.Function)
		if !ok || len(inst.TypeArgs()) == 0 {
			continue
		}
		obj, ok := inst.Object().(*types.Func)
		if !ok {
			continue
		}
		if callee := g.byObj[obj.Origin()]; callee != nil {
			out = append(out, ownedSite{callee: callee, targs: inst.TypeArgs()})
		}
	}
	return out
}

// methodsOf is every method of a concrete instance of an owned generic type in
// t's method set: converting t to an interface makes each callable.
func (g *ownedGenerics) methodsOf(prog *ssa.Program, t types.Type) []ownedSite {
	if len(g.byObj) == 0 {
		return nil
	}
	var out []ownedSite
	for sel := range prog.MethodSets.MethodSet(t).Methods() {
		obj, ok := sel.Obj().(*types.Func)
		if !ok {
			continue
		}
		callee := g.byObj[obj.Origin()]
		if callee == nil {
			continue
		}
		recv := obj.Signature().Recv().Type()
		if p, isPtr := recv.(*types.Pointer); isPtr {
			recv = p.Elem()
		}
		named, ok := types.Unalias(recv).(*types.Named)
		if !ok || named.TypeArgs().Len() != callee.fn.TypeParams().Len() {
			continue
		}
		out = append(out, ownedSite{callee: callee, targs: typeListSlice(named.TypeArgs())})
	}
	return out
}

func typeListSlice(l *types.TypeList) []types.Type {
	out := make([]types.Type, l.Len())
	for i := range out {
		out[i] = l.At(i)
	}
	return out
}

// propagate closes the shapes over generics instantiating each other: a site
// inside a generic, handing on its own parameter to a callee that hands it
// on, makes the enclosing generic hand it on too. Each round adds a shape, and
// there are at most two per type parameter, so it ends.
func propagate(sites []ownedSite) {
	for changed := true; changed; {
		changed = false
		for _, s := range sites {
			if s.in == nil {
				continue
			}
			for shape := range s.callee.shapes {
				if t := shape.apply(s.targs); mentionsTypeParam(t) && s.in.handOn(t, shapeCause{}) {
					changed = true
				}
			}
		}
	}
}

// mentionsTypeParam reports whether t is, or is built from, a type parameter.
func mentionsTypeParam(t types.Type) bool {
	found := false
	forEachTypeParam(t, func(*types.TypeParam) { found = true })
	return found
}

// forEachTypeParam calls visit for each type parameter t is built from. A
// named type's arguments are walked, not its declaration, which is shared by
// every instance and so mentions none of the caller's parameters.
func forEachTypeParam(t types.Type, visit func(*types.TypeParam)) {
	switch t := types.Unalias(t).(type) {
	case *types.TypeParam:
		visit(t)
	case *types.Pointer:
		forEachTypeParam(t.Elem(), visit)
	case *types.Slice:
		forEachTypeParam(t.Elem(), visit)
	case *types.Array:
		forEachTypeParam(t.Elem(), visit)
	case *types.Chan:
		forEachTypeParam(t.Elem(), visit)
	case *types.Map:
		forEachTypeParam(t.Key(), visit)
		forEachTypeParam(t.Elem(), visit)
	case *types.Struct:
		for f := range t.Fields() {
			forEachTypeParam(f.Type(), visit)
		}
	case *types.Tuple:
		for v := range t.Variables() {
			forEachTypeParam(v.Type(), visit)
		}
	case *types.Signature:
		forEachTypeParam(t.Params(), visit)
		forEachTypeParam(t.Results(), visit)
	case *types.Named:
		for a := range t.TypeArgs().Types() {
			forEachTypeParam(a, visit)
		}
	}
}

// substitute is t with each of tparams replaced by its argument, for the
// shapes an interface converted to takes: a named instance and the types its
// arguments are built of. Any other shape mentioning a parameter is refused.
func substitute(t types.Type, tparams map[*types.TypeParam]int, targs []types.Type) (types.Type, bool) {
	if !mentionsTypeParam(t) {
		return t, true
	}
	switch t := types.Unalias(t).(type) {
	case *types.TypeParam:
		i, ok := tparams[t]
		if !ok {
			return nil, false
		}
		return targs[i], true
	case *types.Pointer:
		e, ok := substitute(t.Elem(), tparams, targs)
		if !ok {
			return nil, false
		}
		return types.NewPointer(e), true
	case *types.Slice:
		e, ok := substitute(t.Elem(), tparams, targs)
		if !ok {
			return nil, false
		}
		return types.NewSlice(e), true
	case *types.Named:
		args := make([]types.Type, 0, t.TypeArgs().Len())
		for a := range t.TypeArgs().Types() {
			s, ok := substitute(a, tparams, targs)
			if !ok {
				return nil, false
			}
			args = append(args, s)
		}
		inst, err := types.Instantiate(nil, t.Origin(), args, false)
		if err != nil {
			return nil, false
		}
		return inst, true
	}
	return nil, false
}

// convertsTypeParam is the interface instr converts a value built from a type
// parameter to, and that value's type. SSA writes a type parameter's own
// conversion as a ChangeType, and any other type built from one as a
// MakeInterface.
func convertsTypeParam(instr ssa.Instruction) (from, to types.Type, ok bool) {
	switch c := instr.(type) {
	case *ssa.MakeInterface:
		from, to = c.X.Type(), c.Type()
	case *ssa.ChangeType:
		from, to = c.X.Type(), c.Type()
		if _, isParam := types.Unalias(to).(*types.TypeParam); isParam || !types.IsInterface(to) {
			return nil, nil, false
		}
	default:
		return nil, nil, false
	}
	return from, to, mentionsTypeParam(from)
}
