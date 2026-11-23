package staticcha

import (
	"context"
	"go/token"
	"go/types"
	"log/slog"
	"sort"

	"code.eitanity.com/kanonarion/internal/callgraph/domain"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/types/typeutil"
)

// attachDependencyDispatch records, on each exported method of a module type,
// how a dependency can call it without an edge in this graph.
//
// A dependency does not import the module, so it can only call a module method
// through a value it was handed: an interface value, or a type argument to one
// of its generics. Dependencies are loaded type-only, so the call itself — in
// errors.Is, io.Copy, log/slog — is in no body this graph holds, and the empty
// in-edge set it leaves is not a measured absence. What the module's own code
// does show is the hand-off, and that is what is recorded: every conversion of a
// module type to an interface and every type argument to an outside generic, in
// the module's built functions. Unexported methods are left out, because an
// interface naming one is satisfiable only inside its own, owned, package.
//
// Beside the first hand-off, each method names the package-level interfaces
// declared outside the module that contain it and that the escaping type
// satisfies, which is what a reader can act on. The universe's error and the
// inline interfaces a dependency asserts inside its body are not declared at
// package level, so a method reached only through those names the hand-off.
func (a *Analyser) attachDependencyDispatch(
	ctx context.Context,
	prog *ssa.Program,
	funcs []*ssa.Function,
	mem moduleMembership,
	fset *token.FileSet,
	roots sourceRoots,
	nodes []domain.CallNode,
) {
	if prog == nil {
		return
	}
	escapes := collectEscapes(prog, funcs, mem, fset, roots)
	if escapes.Len() == 0 {
		return
	}
	facts := methodFacts(prog, escapes, indexDeclaredInterfaces(prog, mem), mem)

	stamped := 0
	for i := range nodes {
		f, ok := facts[nodes[i].ID]
		if !ok || nodes[i].IsExternal {
			continue
		}
		fact, err := domain.NewDependencyDispatch(f.all.fact(), f.prod.fact())
		if err != nil {
			// A fact this build would refuse to store is a defect here, not a reason
			// to fail the record: the node keeps no fact and the log names it.
			a.logger.WarnContext(ctx, "callgraph_dependency_dispatch_refused", slog.String("node", nodes[i].ID), slog.Any("error", err))
			continue
		}
		nodes[i].DependencyDispatch = fact
		stamped++
	}
	a.logger.InfoContext(ctx, "callgraph_dependency_dispatch",
		slog.Int("escaping_types", escapes.Len()), slog.Int("methods", stamped))
}

// methodFacts folds every escaping type's exported module methods into one fact
// per method node ID.
func methodFacts(prog *ssa.Program, escapes *typeutil.Map, declared *declaredInterfaces, mem moduleMembership) map[string]*dispatchFact {
	facts := make(map[string]*dispatchFact)
	escapes.Iterate(func(t types.Type, v any) {
		e, ok := v.(*typeEscapes)
		if !ok {
			return
		}
		for sel := range prog.MethodSets.MethodSet(t).Methods() {
			obj, ok := sel.Obj().(*types.Func)
			if !ok {
				continue
			}
			obj = obj.Origin()
			id := methodNodeID(obj)
			if !obj.Exported() || id == "" || !mem.contains(obj.Pkg().Path()) {
				continue
			}
			f := facts[id]
			if f == nil {
				f = &dispatchFact{}
				facts[id] = f
			}
			ifaces := declared.satisfiedBy(t, obj.Name())
			f.all.add(e.all.escape(t, obj.Pkg()), ifaces)
			if e.prod != nil {
				f.prod.add(e.prod.escape(t, obj.Pkg()), ifaces)
			}
		}
	})
	return facts
}

// dispatchFact accumulates one method's fact across every type it escapes in:
// over every hand-off, and over the production ones.
type dispatchFact struct {
	all, prod handOffs
}

// handOffs is the first hand-off seen and the union of the interfaces.
type handOffs struct {
	escape     domain.DispatchEscape
	interfaces map[string]struct{}
}

func (h *handOffs) add(esc domain.DispatchEscape, ifaces []string) {
	if h.escape.Kind == "" || escapeLess(esc, h.escape) {
		h.escape = esc
	}
	if h.interfaces == nil {
		h.interfaces = map[string]struct{}{}
	}
	for _, iface := range ifaces {
		h.interfaces[iface] = struct{}{}
	}
}

func (h *handOffs) fact() domain.DependencyDispatch {
	ifaces := make([]string, 0, len(h.interfaces))
	for name := range h.interfaces {
		ifaces = append(ifaces, name)
	}
	sort.Strings(ifaces)
	if len(ifaces) == 0 {
		ifaces = nil
	}
	return domain.DependencyDispatch{Escape: h.escape, Interfaces: ifaces}
}

// typeEscapes is one type's first hand-off, and its first in production code;
// prod is nil when every hand-off is in a test.
type typeEscapes struct {
	all, prod *escapeSite
}

// escapeSite is the first hand-off of one type, in escapeLess order.
type escapeSite struct {
	kind     domain.EscapeKind
	via      string
	function string
	site     domain.SourcePosition
	// typeKey is the type in full-path form; it orders sites with the type
	// written relative to the method, which differs per method.
	typeKey string
}

func (e *escapeSite) escape(t types.Type, pkg *types.Package) domain.DispatchEscape {
	return domain.DispatchEscape{
		Kind:     e.kind,
		Type:     types.TypeString(t, types.RelativeTo(pkg)),
		Via:      e.via,
		Function: e.function,
		Site:     e.site,
	}
}

func (e *escapeSite) less(o *escapeSite) bool {
	return escapeKeyLess(e.site, e.kind, e.via, e.typeKey, e.function, o.site, o.kind, o.via, o.typeKey, o.function)
}

func escapeLess(a, b domain.DispatchEscape) bool {
	return escapeKeyLess(a.Site, a.Kind, a.Via, a.Type, a.Function, b.Site, b.Kind, b.Via, b.Type, b.Function)
}

// escapeKeyLess orders hand-offs by site first, so the one a reader is shown is
// the earliest in the source, and by every other field after it so the order is
// total.
func escapeKeyLess(as domain.SourcePosition, ak domain.EscapeKind, av, at, af string,
	bs domain.SourcePosition, bk domain.EscapeKind, bv, bt, bf string) bool {
	switch {
	case as.File != bs.File:
		return as.File < bs.File
	case as.Line != bs.Line:
		return as.Line < bs.Line
	case ak != bk:
		return ak < bk
	case av != bv:
		return av < bv
	case at != bt:
		return at < bt
	}
	return af < bf
}

// collectEscapes maps every type the module's built functions hand outside
// their static view to its first hand-off, an instantiation of an owned
// generic that hands on its type argument included.
func collectEscapes(prog *ssa.Program, funcs []*ssa.Function, mem moduleMembership, fset *token.FileSet, roots sourceRoots) *typeutil.Map {
	c := &escapeCollector{
		prog: prog, mem: mem, fset: fset, roots: roots,
		escapes: new(typeutil.Map), generics: indexOwnedGenerics(funcs, mem),
	}
	for _, fn := range funcs {
		if fnInModule(fn, mem) && len(fn.Blocks) > 0 {
			c.scan(fn)
		}
	}
	propagate(c.sites)
	// Each instantiation with a concrete argument hands it on at its own site,
	// in its own scope.
	for _, s := range c.sites {
		for shape, cause := range s.callee.shapes {
			cand := s.cand
			cand.kind, cand.via = s.callee.via(cause, s.targs)
			c.note(shape.apply(s.targs), &cand, s.test)
		}
	}
	return c.escapes
}

// escapeCollector is collectEscapes' state across the functions it scans.
type escapeCollector struct {
	prog     *ssa.Program
	mem      moduleMembership
	fset     *token.FileSet
	roots    sourceRoots
	escapes  *typeutil.Map
	generics *ownedGenerics
	sites    []ownedSite
}

func (c *escapeCollector) note(t types.Type, cand *escapeSite, inTest bool) {
	if canEscape(t) && !mentionsTypeParam(t) {
		noteEscape(c.escapes, t, cand, inTest)
	}
}

// scan records fn's hand-offs, and its instantiations of owned generics for
// after their shapes are known.
func (c *escapeCollector) scan(fn *ssa.Function) {
	fnID := nodeID(fn)
	// The node's own test rule, so a hand-off is test code exactly when the
	// function holding it is a test node.
	inTest := isTestFunc(fn, c.fset, funcPackagePath(fn))
	in := c.generics.enclosing(fn)
	for _, blk := range fn.Blocks {
		for _, instr := range blk.Instrs {
			site := func(kind domain.EscapeKind, via string) *escapeSite {
				return &escapeSite{kind: kind, via: via, function: fnID, site: escapePosition(instr, fn, c.fset, c.roots)}
			}
			owned := c.generics.instancesIn(instr)
			if from, to, ok := convertsTypeParam(instr); ok && in != nil {
				in.handOn(from, shapeCause{iface: to})
			}
			if mi, ok := instr.(*ssa.MakeInterface); ok {
				c.note(mi.X.Type(), site(domain.EscapeConversion, interfaceName(mi.Type())), inTest)
				owned = append(owned, c.generics.methodsOf(c.prog, mi.X.Type())...)
			}
			for _, g := range outsideGenerics(instr, c.mem) {
				for _, targ := range g.instance.TypeArgs() {
					if in != nil && mentionsTypeParam(targ) {
						in.handOn(targ, shapeCause{})
					}
					c.note(targ, site(domain.EscapeTypeArgument, genericName(g.origin)), inTest)
				}
			}
			for _, s := range owned {
				s.in, s.cand, s.test = in, *site("", ""), inTest
				c.sites = append(c.sites, s)
			}
		}
	}
}

// noteEscape keeps cand as t's first hand-off, and as its first production one
// when cand is not in a test, where it precedes the one held.
func noteEscape(escapes *typeutil.Map, t types.Type, cand *escapeSite, inTest bool) {
	cand.typeKey = types.TypeString(t, nil)
	e, ok := escapes.At(t).(*typeEscapes)
	if !ok {
		e = &typeEscapes{}
		escapes.Set(t, e)
	}
	if e.all == nil || cand.less(e.all) {
		e.all = cand
	}
	if !inTest && (e.prod == nil || cand.less(e.prod)) {
		e.prod = cand
	}
}

// outsideGeneric is an instance of a generic declared outside the module.
type outsideGeneric struct {
	instance *ssa.Function
	origin   *types.Func
}

// outsideGenerics is every instance of a generic declared outside the module
// that instr names, called or taken as a value.
func outsideGenerics(instr ssa.Instruction, mem moduleMembership) []outsideGeneric {
	var out []outsideGeneric
	for _, op := range instr.Operands(nil) {
		generic, ok := (*op).(*ssa.Function)
		if !ok || len(generic.TypeArgs()) == 0 {
			continue
		}
		if obj, ok := generic.Object().(*types.Func); ok && obj.Pkg() != nil && !mem.contains(obj.Pkg().Path()) {
			out = append(out, outsideGeneric{instance: generic, origin: obj.Origin()})
		}
	}
	return out
}

// canEscape reports whether t is a concrete type with methods to escape. An
// interface's or a type parameter's methods are abstract, and belong to
// whichever concrete type is converted.
func canEscape(t types.Type) bool {
	switch types.Unalias(t).(type) {
	case *types.TypeParam, *types.Interface:
		return false
	}
	return !types.IsInterface(t)
}

// escapePosition is the instruction's position. An implicit conversion has
// none, so it takes the first instruction using its value that does, and then
// the function's own declaration.
func escapePosition(instr ssa.Instruction, fn *ssa.Function, fset *token.FileSet, roots sourceRoots) domain.SourcePosition {
	pos := instr.Pos()
	if v, ok := instr.(ssa.Value); ok && pos == token.NoPos {
		for _, ref := range *v.Referrers() {
			if ref.Pos() != token.NoPos {
				pos = ref.Pos()
				break
			}
		}
	}
	if pos == token.NoPos {
		pos = fn.Pos()
	}
	return declPosition(pos, fset, roots)
}

// interfaceName renders an interface type with full package paths, and "any"
// for the empty interface.
func interfaceName(t types.Type) string {
	if iface, ok := types.Unalias(t).(*types.Interface); ok && iface.Empty() {
		return "any"
	}
	return types.TypeString(t, nil)
}

// genericName renders a generic function or method as a node ID would.
func genericName(obj *types.Func) string {
	if id := methodNodeID(obj); id != "" {
		return id
	}
	return obj.Pkg().Path() + "." + obj.Name()
}

// methodNodeID is the node ID of a concrete method, or "" for a function or an
// interface's abstract method.
func methodNodeID(obj *types.Func) string {
	sig, ok := obj.Type().(*types.Signature)
	if !ok || sig.Recv() == nil || obj.Pkg() == nil {
		return ""
	}
	recv := sig.Recv().Type()
	if types.IsInterface(recv) {
		return ""
	}
	return obj.Pkg().Path() + ".(" + recvTypeStr(recv) + ")." + obj.Name()
}

// declaredInterfaces indexes the package-level interfaces declared outside the
// module by method name, as extractInterfaces indexes concrete types, so the
// satisfaction check is asked of a handful of candidates rather than of every
// interface in the build.
type declaredInterfaces struct {
	byMethod map[string][]declaredInterface
	// satisfies memoises one (type, interface) answer; a type escapes once but
	// is asked about once per method it carries.
	satisfies map[satisfiesKey]bool
}

type declaredInterface struct {
	name  string
	iface *types.Interface
}

type satisfiesKey struct {
	t     types.Type
	iface *types.Interface
}

func indexDeclaredInterfaces(prog *ssa.Program, mem moduleMembership) *declaredInterfaces {
	d := &declaredInterfaces{byMethod: map[string][]declaredInterface{}, satisfies: map[satisfiesKey]bool{}}
	for _, pkg := range prog.AllPackages() {
		if pkg == nil || pkg.Pkg == nil || mem.contains(pkg.Pkg.Path()) {
			continue
		}
		scope := pkg.Pkg.Scope()
		for _, name := range scope.Names() {
			tn, ok := scope.Lookup(name).(*types.TypeName)
			if !ok || tn.IsAlias() {
				continue
			}
			named, ok := tn.Type().(*types.Named)
			if !ok || named.TypeParams().Len() > 0 {
				continue
			}
			iface, ok := named.Underlying().(*types.Interface)
			if !ok || iface.NumMethods() == 0 {
				continue
			}
			entry := declaredInterface{name: pkg.Pkg.Path() + "." + name, iface: iface}
			for m := range iface.Methods() {
				d.byMethod[m.Name()] = append(d.byMethod[m.Name()], entry)
			}
		}
	}
	return d
}

// satisfiedBy names the declared interfaces holding a method called method
// that t satisfies.
func (d *declaredInterfaces) satisfiedBy(t types.Type, method string) []string {
	var out []string
	for _, cand := range d.byMethod[method] {
		key := satisfiesKey{t: t, iface: cand.iface}
		ok, seen := d.satisfies[key]
		if !seen {
			ok = types.Implements(t, cand.iface)
			d.satisfies[key] = ok
		}
		if ok {
			out = append(out, cand.name)
		}
	}
	return out
}
