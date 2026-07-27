package staticcha

import (
	"context"
	"go/token"
	"go/types"
	"log/slog"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"

	"golang.org/x/tools/go/ssa"
)

// extractInterfaces records the type-level relation the call graph cannot
// express: which concrete types in the analysed module satisfy which of the
// interfaces it declares.
//
// The edge collections answer "who calls this". A port-signature change asks a
// different question — which method sets must change together — and an
// interface method is not a node at all, because nothing calls it: calls go to
// implementations. go/types already resolves satisfaction exactly, so this
// records that answer rather than leaving callers to grep for a method name,
// which cannot tell an implementation from a call and misses embedded and
// wrapper implementations entirely.
//
// Both sides of the relation are the analysed module's own declarations. A type
// in a different module that satisfies one of these interfaces is not recorded:
// computing satisfaction against every type in the dependency graph is a much
// larger measurement, and one this module's analysis has no mandate to make.
// Query output states that scope so the omission is named rather than read as
// an empty set.
func (a *Analyser) extractInterfaces(
	ctx context.Context,
	prog *ssa.Program,
	coord coordinate.ModuleCoordinate,
	fset *token.FileSet,
	tempDir string,
) ([]domain.InterfaceType, []domain.InterfaceImplementation) {
	ifaces := collectModuleInterfaces(prog, coord, fset, tempDir)
	if len(ifaces) == 0 {
		return nil, nil
	}
	concretes := collectModuleConcreteTypes(prog, coord, fset, tempDir)
	if len(concretes) == 0 {
		return interfaceTypes(ifaces), nil
	}

	// Index the concrete types by method name. An implementer must declare every
	// method the interface names, so one lookup on the interface's first method
	// bounds the candidate set to a handful — without it this is a product of
	// every interface with every type in the module.
	byMethod := make(map[string][]*concreteType, len(concretes))
	for _, c := range concretes {
		for name := range c.methodNames {
			byMethod[name] = append(byMethod[name], c)
		}
	}

	var impls []domain.InterfaceImplementation
	for _, it := range ifaces {
		if ctx.Err() != nil {
			break
		}
		if len(it.methods) == 0 {
			continue
		}
		seen := make(map[string]struct{})
		for _, cand := range byMethod[it.methods[0]] {
			if _, dup := seen[cand.id]; dup {
				continue
			}
			if !cand.declaresAll(it.methods) {
				continue
			}
			impl, ok := buildImplementation(it, cand, fset, tempDir)
			if !ok {
				continue
			}
			seen[cand.id] = struct{}{}
			impls = append(impls, impl)
		}
	}

	a.logger.DebugContext(ctx, "callgraph_interface_relation",
		slog.Int("interfaces", len(ifaces)),
		slog.Int("concrete_types", len(concretes)),
		slog.Int("implementations", len(impls)),
	)
	return interfaceTypes(ifaces), impls
}

// moduleInterface is an interface declaration plus every *types.Interface
// instance of it in the program. A package with test files is type-checked
// twice — once as itself and once as the test variant — and go/types compares
// types by pointer, so satisfaction has to be tried against each instance or a
// fake declared in a test file would silently fail to match its own port.
type moduleInterface struct {
	id        string
	pkg       string
	name      string
	methods   []string
	pos       domain.SourcePosition
	isTest    bool
	instances []*types.Interface
}

// concreteType is a named non-interface declaration plus its instances and the
// set of method names it declares (value and pointer receivers together).
type concreteType struct {
	id          string
	pkg         string
	name        string
	pos         domain.SourcePosition
	isTest      bool
	methodNames map[string]struct{}
	instances   []*types.Named
}

// declaresAll reports whether the type declares every named method — the cheap
// necessary condition checked before go/types is asked the exact question.
func (c *concreteType) declaresAll(methods []string) bool {
	for _, m := range methods {
		if _, ok := c.methodNames[m]; !ok {
			return false
		}
	}
	return true
}

func interfaceTypes(ifaces []*moduleInterface) []domain.InterfaceType {
	out := make([]domain.InterfaceType, 0, len(ifaces))
	for _, it := range ifaces {
		out = append(out, domain.InterfaceType{
			ID:       it.id,
			Package:  it.pkg,
			Name:     it.name,
			Methods:  it.methods,
			Position: it.pos,
			IsTest:   it.isTest,
		})
	}
	return out
}

// collectModuleInterfaces returns the module's declared interfaces, keyed by ID
// so the production package and its test variant contribute instances of the
// same declaration rather than two entries.
//
// The empty interface and its aliases are skipped: every type satisfies them,
// so recording their implementers would answer "which types exist", not "what
// must change together".
func collectModuleInterfaces(prog *ssa.Program, coord coordinate.ModuleCoordinate, fset *token.FileSet, tempDir string) []*moduleInterface {
	byID := make(map[string]*moduleInterface)
	var order []string
	forEachModuleTypeName(prog, coord, func(pkgPath string, tn *types.TypeName, named *types.Named) {
		iface, ok := named.Underlying().(*types.Interface)
		if !ok || iface.NumMethods() == 0 {
			return
		}
		id := pkgPath + "." + tn.Name()
		entry, exists := byID[id]
		if !exists {
			methods := make([]string, 0, iface.NumMethods())
			for i := 0; i < iface.NumMethods(); i++ {
				methods = append(methods, iface.Method(i).Name())
			}
			sort.Strings(methods)
			entry = &moduleInterface{
				id:      id,
				pkg:     pkgPath,
				name:    tn.Name(),
				methods: methods,
				pos:     declPosition(tn.Pos(), fset, tempDir),
				isTest:  isTestDeclaration(tn.Pos(), fset, pkgPath),
			}
			byID[id] = entry
			order = append(order, id)
		}
		entry.instances = append(entry.instances, iface)
	})
	out := make([]*moduleInterface, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out
}

// collectModuleConcreteTypes returns the module's named non-interface types,
// keyed by ID for the same reason collectModuleInterfaces is.
func collectModuleConcreteTypes(prog *ssa.Program, coord coordinate.ModuleCoordinate, fset *token.FileSet, tempDir string) []*concreteType {
	byID := make(map[string]*concreteType)
	var order []string
	forEachModuleTypeName(prog, coord, func(pkgPath string, tn *types.TypeName, named *types.Named) {
		if _, isIface := named.Underlying().(*types.Interface); isIface {
			return
		}
		id := pkgPath + "." + tn.Name()
		entry, exists := byID[id]
		if !exists {
			entry = &concreteType{
				id:          id,
				pkg:         pkgPath,
				name:        tn.Name(),
				pos:         declPosition(tn.Pos(), fset, tempDir),
				isTest:      isTestDeclaration(tn.Pos(), fset, pkgPath),
				methodNames: map[string]struct{}{},
			}
			byID[id] = entry
			order = append(order, id)
		}
		entry.instances = append(entry.instances, named)
		// The pointer method set is the superset: it contains every method
		// declared on either receiver form.
		mset := types.NewMethodSet(types.NewPointer(named))
		for i := 0; i < mset.Len(); i++ {
			entry.methodNames[mset.At(i).Obj().Name()] = struct{}{}
		}
	})
	out := make([]*concreteType, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out
}

// forEachModuleTypeName visits every package-scope named type the analysed
// module declares, across every package instance in the program. Generic types
// are skipped: an uninstantiated type parameter has no method set to satisfy an
// interface with.
func forEachModuleTypeName(prog *ssa.Program, coord coordinate.ModuleCoordinate, fn func(pkgPath string, tn *types.TypeName, named *types.Named)) {
	for _, pkg := range prog.AllPackages() {
		if pkg == nil || pkg.Pkg == nil {
			continue
		}
		pkgPath := pkg.Pkg.Path()
		if !pathInModule(pkgPath, coord) {
			continue
		}
		scope := pkg.Pkg.Scope()
		for _, name := range scope.Names() {
			tn, ok := scope.Lookup(name).(*types.TypeName)
			if !ok {
				continue
			}
			named, ok := tn.Type().(*types.Named)
			if !ok || named.TypeParams().Len() > 0 {
				continue
			}
			fn(pkgPath, tn, named)
		}
	}
}

// buildImplementation confirms satisfaction with go/types and resolves each
// interface method to the concrete node that implements it. It reports false
// when no instance pair satisfies the interface, which is the common case after
// the method-name prefilter admits a candidate by coincidence of naming.
func buildImplementation(it *moduleInterface, c *concreteType, fset *token.FileSet, tempDir string) (domain.InterfaceImplementation, bool) {
	var matched *types.Named
	pointerOnly := false
	for _, named := range c.instances {
		for _, iface := range it.instances {
			if types.Implements(named, iface) {
				matched, pointerOnly = named, false
				break
			}
			if types.Implements(types.NewPointer(named), iface) {
				matched, pointerOnly = named, true
				break
			}
		}
		if matched != nil {
			break
		}
	}
	if matched == nil {
		return domain.InterfaceImplementation{}, false
	}

	recv := c.name
	if pointerOnly {
		recv = "*" + c.name
	}

	methods := make([]domain.ImplementedMethod, 0, len(it.methods))
	for _, m := range it.methods {
		obj := lookupConcreteMethod(matched, m)
		if obj == nil {
			continue
		}
		// The node ID must name the declaration to change, so both halves come
		// from the method object rather than from the implementing type: a
		// value-receiver method on a type satisfying the interface only through
		// its pointer is still declared on the value, and a promoted method is
		// declared in the embedded type's package, not the embedder's. Getting
		// the package from the implementer would point a reader at a file with
		// nothing in it to edit.
		methodRecv := recv
		methodPkg := c.pkg
		if sig, ok := obj.Type().(*types.Signature); ok && sig.Recv() != nil {
			methodRecv = recvTypeStr(sig.Recv().Type())
		}
		if obj.Pkg() != nil {
			methodPkg = obj.Pkg().Path()
		}
		methods = append(methods, domain.ImplementedMethod{
			Method: m,
			NodeID: methodPkg + ".(" + methodRecv + ")." + m,
		})
	}

	return domain.InterfaceImplementation{
		InterfaceID: it.id,
		TypeID:      c.pkg + ".(" + recv + ")",
		Package:     c.pkg,
		Position:    c.pos,
		IsTest:      c.isTest,
		Methods:     methods,
	}, true
}

// lookupConcreteMethod resolves a method by name on the named type, honouring
// pointer-receiver declarations and embedding.
func lookupConcreteMethod(named *types.Named, method string) *types.Func {
	for _, t := range []types.Type{named, types.NewPointer(named)} {
		if obj, _, _ := types.LookupFieldOrMethod(t, true, nil, method); obj != nil {
			if f, ok := obj.(*types.Func); ok {
				return f
			}
		}
	}
	return nil
}

// pathInModule reports whether an import path belongs to the analysed module.
// The external test package of a module package ("<pkg>_test") is inside it:
// its declarations are the module's own test code.
func pathInModule(pkgPath string, coord coordinate.ModuleCoordinate) bool {
	return pkgPath == coord.Path() || strings.HasPrefix(pkgPath, coord.Path()+"/")
}

// declPosition renders a declaration's module-relative source position.
func declPosition(pos token.Pos, fset *token.FileSet, tempDir string) domain.SourcePosition {
	if pos == token.NoPos || fset == nil {
		return domain.SourcePosition{}
	}
	p := fset.Position(pos)
	if !p.IsValid() {
		return domain.SourcePosition{}
	}
	return domain.SourcePosition{File: relativePath(p.Filename, tempDir), Line: p.Line}
}
