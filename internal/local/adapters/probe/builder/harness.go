package builder

import (
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/scanner"
	"go/token"
	"go/types"
	"io"
	"os"
	"sort"
	"strings"

	localdomain "github.com/eitanity/kanonarion/internal/local/domain"
)

// exportedFunc records one exported function or method reference for the harness.
type exportedFunc struct {
	receiver string // empty for top-level funcs; "*Type" or "Type" for methods
	name     string
	recvArgs []types.Type // the receiver type's arguments; nil when it is not generic
	ownArgs  []types.Type // the function's or method's own type arguments
}

// symbol names the declaration as govulncheck does, without type arguments.
func (ef exportedFunc) symbol(pkgPath string) string {
	switch {
	case ef.receiver == "":
		return pkgPath + "." + ef.name
	case strings.HasPrefix(ef.receiver, "*"):
		return pkgPath + ".(" + ef.receiver + ")." + ef.name
	default:
		return pkgPath + "." + ef.receiver + "." + ef.name
	}
}

// exportImporter reads package types from the export data `go list -export`
// wrote, so the harness is checked against what the build compiles.
func exportImporter(pkgs []goListPackage) types.Importer {
	files := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		files[p.ImportPath] = p.Export
	}
	lookup := func(path string) (io.ReadCloser, error) {
		file := files[path]
		if file == "" {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		f, err := os.Open(file) // #nosec G304 -- a build-cache file the go command named
		if err != nil {
			return nil, fmt.Errorf("opening export data for %s: %w", path, err)
		}
		return f, nil
	}
	return importer.ForCompiler(token.NewFileSet(), "gc", lookup)
}

// enumerateExportedFuncs collects every exported function of each workspace
// package and the exported methods in the method sets of T and *T for each
// exported named type, instantiating type parameters. A declaration no type
// argument can instantiate is returned as an omission, never dropped silently.
func enumerateExportedFuncs(work []goListPackage, imp types.Importer) (map[string][]exportedFunc, []localdomain.HarnessOmission, error) {
	result := make(map[string][]exportedFunc)
	var omitted []localdomain.HarnessOmission
	for _, pkg := range work {
		tpkg, err := imp.Import(pkg.ImportPath)
		if err != nil {
			return nil, nil, fmt.Errorf("reading the types of %s: %w", pkg.ImportPath, err)
		}
		scope := tpkg.Scope()
		for _, name := range scope.Names() {
			refs, omits := exportsOf(scope.Lookup(name), pkg.ImportPath)
			if len(refs) > 0 {
				result[pkg.ImportPath] = append(result[pkg.ImportPath], refs...)
			}
			omitted = append(omitted, omits...)
		}
	}
	return result, omitted, nil
}

func exportsOf(obj types.Object, pkgPath string) ([]exportedFunc, []localdomain.HarnessOmission) {
	if !obj.Exported() {
		return nil, nil
	}
	switch o := obj.(type) {
	case *types.Func:
		return funcExport(o, pkgPath)
	case *types.TypeName:
		return methodExports(o, pkgPath)
	}
	return nil, nil
}

func funcExport(fn *types.Func, pkgPath string) ([]exportedFunc, []localdomain.HarnessOmission) {
	ef := exportedFunc{name: fn.Name()}
	sig := fn.Signature()
	args, err := chooseTypeArgs(sig.TypeParams(), instantiator(sig))
	if err != nil {
		return nil, []localdomain.HarnessOmission{{Symbol: ef.symbol(pkgPath), Reason: err.Error()}}
	}
	ef.ownArgs = args
	return []exportedFunc{ef}, nil
}

// methodExports walks the method sets of T and *T. An alias is skipped because
// its type is enumerated where it is declared, and an interface because its
// methods have no body for the harness to keep.
func methodExports(tn *types.TypeName, pkgPath string) ([]exportedFunc, []localdomain.HarnessOmission) {
	named, ok := tn.Type().(*types.Named)
	if tn.IsAlias() || !ok || types.IsInterface(named) {
		return nil, nil
	}
	var inst types.Type = named
	recvArgs, err := chooseTypeArgs(named.TypeParams(), func(args []types.Type) error {
		var ierr error
		inst, ierr = types.Instantiate(nil, named, args, true)
		return ierr //nolint:wrapcheck // as in instantiator
	})
	if err != nil {
		return nil, declaredMethodOmissions(named, pkgPath, err)
	}
	values := types.NewMethodSet(inst)
	all := types.NewMethodSet(types.NewPointer(inst))
	var refs []exportedFunc
	var omitted []localdomain.HarnessOmission
	for sel := range all.Methods() {
		m, isFunc := sel.Obj().(*types.Func)
		if !isFunc || !m.Exported() {
			continue
		}
		ef := exportedFunc{receiver: tn.Name(), name: m.Name(), recvArgs: recvArgs}
		if values.Lookup(m.Pkg(), m.Name()) == nil {
			ef.receiver = "*" + tn.Name()
		}
		sig := m.Signature()
		own, err := chooseTypeArgs(sig.TypeParams(), instantiator(sig))
		if err != nil {
			omitted = append(omitted, localdomain.HarnessOmission{Symbol: ef.symbol(pkgPath), Reason: err.Error()})
			continue
		}
		ef.ownArgs = own
		refs = append(refs, ef)
	}
	return refs, omitted
}

// declaredMethodOmissions names each exported method declared on a generic type
// no candidate instantiates.
func declaredMethodOmissions(named *types.Named, pkgPath string, cause error) []localdomain.HarnessOmission {
	var omitted []localdomain.HarnessOmission
	for m := range named.Methods() {
		if !m.Exported() {
			continue
		}
		ef := exportedFunc{receiver: named.Obj().Name(), name: m.Name()}
		if _, ptr := m.Signature().Recv().Type().(*types.Pointer); ptr {
			ef.receiver = "*" + ef.receiver
		}
		omitted = append(omitted, localdomain.HarnessOmission{
			Symbol: ef.symbol(pkgPath),
			Reason: "the receiver type cannot be instantiated: " + cause.Error(),
		})
	}
	return omitted
}

func instantiator(generic types.Type) func([]types.Type) error {
	return func(args []types.Type) error {
		_, err := types.Instantiate(nil, generic, args, true)
		return err //nolint:wrapcheck // chooseTypeArgs reads the ArgumentError and names the parameter itself
	}
}

// fallbackTypeArgs are tried, in order, after a type parameter's core type and
// its constraint's terms.
var fallbackTypeArgs = []types.Type{types.Typ[types.Int], types.Typ[types.String], types.NewStruct(nil, nil)}

// chooseTypeArgs picks one argument per type parameter: its constraint's core
// type, then each term type in declaration order (~T gives T), then int, string,
// struct{}. Each choice is validated by types.Instantiate; a rejected argument
// moves its parameter on to the next candidate.
func chooseTypeArgs(tparams *types.TypeParamList, valid func([]types.Type) error) ([]types.Type, error) {
	n := tparams.Len()
	if n == 0 {
		return nil, nil
	}
	next := make([]int, n)
	for {
		args, cands := candidateArgs(tparams, next)
		err := valid(args)
		if err == nil {
			return args, nil
		}
		var ae *types.ArgumentError
		if !errors.As(err, &ae) || ae.Index < 0 || ae.Index >= n {
			return nil, fmt.Errorf("cannot instantiate: %w", err)
		}
		next[ae.Index]++
		if next[ae.Index] >= len(cands[ae.Index]) {
			tp := tparams.At(ae.Index)
			return nil, fmt.Errorf("no type argument satisfies %s %s (tried %s)",
				tp.Obj().Name(), types.TypeString(tp.Constraint(), nil), typeList(cands[ae.Index]))
		}
	}
}

// candidateArgs resolves the parameters in passes, because a core type such as
// ~[]E can name a parameter that comes later; a cycle takes the fallbacks.
func candidateArgs(tparams *types.TypeParamList, next []int) ([]types.Type, [][]types.Type) {
	n := tparams.Len()
	args := make([]types.Type, n)
	cands := make([][]types.Type, n)
	chosen := make(map[*types.TypeParam]types.Type, n)
	for progress := true; progress; {
		progress = false
		for i := range n {
			if args[i] != nil {
				continue
			}
			core, ready := coreTypeArg(tparams.At(i), chosen)
			if !ready {
				continue
			}
			cands[i] = candidates(tparams.At(i), core, chosen)
			args[i] = pick(cands[i], next[i])
			chosen[tparams.At(i)] = args[i]
			progress = true
		}
	}
	for i := range n {
		if args[i] == nil {
			cands[i] = candidates(tparams.At(i), nil, chosen)
			args[i] = pick(cands[i], next[i])
		}
	}
	return args, cands
}

// candidates lists tp's arguments in the order they are tried, without
// duplicates. A term naming a parameter not chosen yet is left out.
func candidates(tp *types.TypeParam, core types.Type, chosen map[*types.TypeParam]types.Type) []types.Type {
	var out []types.Type
	add := func(t types.Type) {
		for _, have := range out {
			if types.Identical(have, t) {
				return
			}
		}
		out = append(out, t)
	}
	if core != nil {
		add(core)
	}
	if iface, ok := tp.Constraint().Underlying().(*types.Interface); ok {
		for _, term := range typeTerms(iface) {
			if t, ok := subst(term.Type(), chosen); ok {
				add(t)
			}
		}
	}
	for _, f := range fallbackTypeArgs {
		add(f)
	}
	return out
}

func pick(cands []types.Type, i int) types.Type {
	if i < len(cands) {
		return cands[i]
	}
	return cands[len(cands)-1]
}

func typeList(ts []types.Type) string {
	names := make([]string, len(ts))
	for i, t := range ts {
		names[i] = types.TypeString(t, nil)
	}
	return strings.Join(names, ", ")
}

// coreTypeArg is tp's core type with the chosen arguments substituted. ready
// is false while the core type names a parameter not chosen yet.
func coreTypeArg(tp *types.TypeParam, chosen map[*types.TypeParam]types.Type) (core types.Type, ready bool) {
	c, ok := coreType(tp.Constraint())
	if !ok {
		return nil, true
	}
	return subst(c, chosen)
}

// coreType is the single type a constraint's terms share: the underlying type
// when any term is ~T, or the first term itself when none is.
func coreType(constraint types.Type) (types.Type, bool) {
	iface, ok := constraint.Underlying().(*types.Interface)
	if !ok {
		return nil, false
	}
	terms := typeTerms(iface)
	if len(terms) == 0 {
		return nil, false
	}
	under := terms[0].Type().Underlying()
	tilde := false
	for _, t := range terms {
		if !types.Identical(t.Type().Underlying(), under) {
			return nil, false
		}
		tilde = tilde || t.Tilde()
	}
	if tilde {
		return under, true
	}
	return terms[0].Type(), true
}

// typeTerms lists the terms of iface's type set. Go intersects embedded
// constraints and this concatenates them: a wrong core type only fails
// validation and moves on to the fallbacks.
func typeTerms(iface *types.Interface) []*types.Term {
	var terms []*types.Term
	for e := range iface.EmbeddedTypes() {
		if u, ok := e.(*types.Union); ok {
			for i := range u.Len() {
				terms = append(terms, u.Term(i))
			}
			continue
		}
		if inner, ok := e.Underlying().(*types.Interface); ok {
			terms = append(terms, typeTerms(inner)...)
			continue
		}
		terms = append(terms, types.NewTerm(false, e))
	}
	return terms
}

// subst replaces each type parameter in t by its chosen argument. It returns
// false for a parameter not chosen yet or a shape it does not rebuild.
func subst(t types.Type, chosen map[*types.TypeParam]types.Type) (types.Type, bool) {
	switch t := types.Unalias(t).(type) {
	case *types.TypeParam:
		arg, ok := chosen[t]
		return arg, ok
	case *types.Basic:
		return t, true
	case *types.Named:
		return substNamed(t, chosen)
	case *types.Map:
		k, okK := subst(t.Key(), chosen)
		v, okV := subst(t.Elem(), chosen)
		if !okK || !okV {
			return nil, false
		}
		return types.NewMap(k, v), true
	case *types.Pointer:
		return substElem(t.Elem(), chosen, func(e types.Type) types.Type { return types.NewPointer(e) })
	case *types.Slice:
		return substElem(t.Elem(), chosen, func(e types.Type) types.Type { return types.NewSlice(e) })
	case *types.Array:
		return substElem(t.Elem(), chosen, func(e types.Type) types.Type { return types.NewArray(e, t.Len()) })
	case *types.Chan:
		return substElem(t.Elem(), chosen, func(e types.Type) types.Type { return types.NewChan(t.Dir(), e) })
	}
	return nil, false
}

func substElem(elem types.Type, chosen map[*types.TypeParam]types.Type, wrap func(types.Type) types.Type) (types.Type, bool) {
	e, ok := subst(elem, chosen)
	if !ok {
		return nil, false
	}
	return wrap(e), true
}

func substNamed(t *types.Named, chosen map[*types.TypeParam]types.Type) (types.Type, bool) {
	targs := t.TypeArgs()
	if targs.Len() == 0 {
		return t, true
	}
	args := make([]types.Type, targs.Len())
	for i := range targs.Len() {
		a, ok := subst(targs.At(i), chosen)
		if !ok {
			return nil, false
		}
		args[i] = a
	}
	inst, err := types.Instantiate(nil, t.Origin(), args, false)
	return inst, err == nil
}

// harnessRef locates one reference in the rendered harness.
type harnessRef struct {
	pkgPath string
	index   int
}

// renderHarness writes the harness and maps each reference line to its export.
// Imports are derived from the references written, so dropping one never
// leaves an unused import behind.
func renderHarness(pkgs []goListPackage, exports map[string][]exportedFunc) (string, map[int]harnessRef) {
	sorted := make([]goListPackage, len(pkgs))
	copy(sorted, pkgs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ImportPath < sorted[j].ImportPath })

	aliases := make(map[string]string, len(sorted))
	paths := make([]string, 0, len(sorted))
	for i, pkg := range sorted {
		aliases[pkg.ImportPath] = fmt.Sprintf("p%d", i)
		paths = append(paths, pkg.ImportPath)
	}
	used := make(map[string]bool)
	qualify := func(p *types.Package) string {
		if _, ok := aliases[p.Path()]; !ok {
			aliases[p.Path()] = fmt.Sprintf("t%d", len(paths)-len(sorted))
			paths = append(paths, p.Path())
		}
		used[p.Path()] = true
		return aliases[p.Path()]
	}

	var body []string
	var order []harnessRef
	for _, pkg := range sorted {
		for i, ef := range exports[pkg.ImportPath] {
			used[pkg.ImportPath] = true
			order = append(order, harnessRef{pkgPath: pkg.ImportPath, index: i})
			body = append(body, "\t_sinks = append(_sinks, "+refExpr(aliases[pkg.ImportPath], ef, qualify)+")\n")
		}
	}

	var sb strings.Builder
	sb.WriteString("package main\n\nimport (\n")
	line := 4 // the first import's line
	for _, path := range paths {
		if used[path] {
			fmt.Fprintf(&sb, "\t%s %q\n", aliases[path], path)
			line++
		}
	}
	sb.WriteString(")\n\nvar _sinks []interface{}\n\nfunc init() {\n")
	line += 5 // ")", blank, the declaration, blank, "func init() {"
	lines := make(map[int]harnessRef, len(order))
	for i, ref := range body {
		sb.WriteString(ref)
		lines[line+i] = order[i]
	}
	sb.WriteString("}\n\nfunc main() { _ = _sinks }\n")
	return sb.String(), lines
}

// refExpr spells one reference: p0.F[A], (p0.T[A]).M, (*p0.T[A]).M or (p0.T).M[A].
func refExpr(alias string, ef exportedFunc, q types.Qualifier) string {
	own := typeArgList(ef.ownArgs, q)
	if ef.receiver == "" {
		return alias + "." + ef.name + own
	}
	recv := alias + "." + strings.TrimPrefix(ef.receiver, "*") + typeArgList(ef.recvArgs, q)
	if strings.HasPrefix(ef.receiver, "*") {
		// A pointer receiver's method expression is (*pkg.Type).Method.
		recv = "*" + recv
	}
	return "(" + recv + ")." + ef.name + own
}

func typeArgList(args []types.Type, q types.Qualifier) string {
	if len(args) == 0 {
		return ""
	}
	names := make([]string, len(args))
	for i, a := range args {
		names[i] = types.TypeString(a, q)
	}
	return "[" + strings.Join(names, ", ") + "]"
}

// generateHarness produces Go source code for the synthetic probe harness.
// It imports every workspace package and assigns exported function/method
// expressions to interface{} variables, preventing dead-code elimination.
func generateHarness(pkgs []goListPackage, exports map[string][]exportedFunc) string {
	code, _ := renderHarness(pkgs, exports)
	return code
}

// checkHarness type-checks the harness and returns the first error on each
// line. A parse error is keyed by line too, so it is dropped the same way.
func checkHarness(code string, imp types.Importer, goVersion string) map[int]string {
	bad := make(map[int]string)
	note := func(line int, msg string) {
		if _, seen := bad[line]; !seen {
			bad[line] = msg
		}
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", code, parser.SkipObjectResolution)
	if err != nil {
		var list scanner.ErrorList
		if !errors.As(err, &list) {
			note(0, err.Error())
		}
		for _, e := range list {
			note(e.Pos.Line, e.Msg)
		}
		return bad
	}
	conf := types.Config{
		Importer:  imp,
		GoVersion: goVersion,
		Error: func(err error) {
			var te types.Error
			if !errors.As(err, &te) {
				note(0, err.Error())
				return
			}
			note(te.Fset.Position(te.Pos).Line, te.Msg)
		},
	}
	_, _ = conf.Check("main", fset, []*ast.File{f}, nil) //nolint:errcheck // every error reaches conf.Error
	return bad
}

// harnessSource enumerates the workspace's exports and returns a harness that
// type-checks, with every declaration left out named. An error off a reference
// line is the generator's own and is returned.
func harnessSource(all []goListPackage, goVersion string) (string, []localdomain.HarnessOmission, error) {
	var work []goListPackage
	for _, p := range all {
		if !p.DepOnly {
			work = append(work, p)
		}
	}
	imp := exportImporter(all)
	exports, omitted, err := enumerateExportedFuncs(work, imp)
	if err != nil {
		return "", nil, err
	}
	exports, unimportable := withoutUnimportable(exports, harnessPath(work))
	omitted = append(omitted, unimportable...)
	code, dropped, err := pruneHarness(work, exports, imp, goVersion)
	if err != nil {
		return "", nil, err
	}
	omitted = append(omitted, dropped...)
	localdomain.SortHarnessOmissions(omitted)
	return code, omitted, nil
}

// harnessPath is the harness package's import path, or "" outside a module.
func harnessPath(work []goListPackage) string {
	for _, p := range work {
		if p.Module != nil && p.Module.Path != "" {
			return p.Module.Path + "/" + probeHarnessDir
		}
	}
	return ""
}

// withoutUnimportable drops and names each reference whose package, or a type
// argument's, sits in an internal package the harness may not import. go/types
// does not apply that rule, so the harness build would stop the probe.
func withoutUnimportable(exports map[string][]exportedFunc, from string) (map[string][]exportedFunc, []localdomain.HarnessOmission) {
	if from == "" {
		return exports, nil
	}
	drop := make(map[harnessRef]bool)
	var omitted []localdomain.HarnessOmission
	for path, funcs := range exports {
		for i, ef := range funcs {
			for _, needed := range refPackages(path, ef) {
				if importableFrom(from, needed) {
					continue
				}
				drop[harnessRef{pkgPath: path, index: i}] = true
				omitted = append(omitted, localdomain.HarnessOmission{
					Symbol: ef.symbol(path),
					Reason: "the harness cannot import internal package " + needed,
				})
				break
			}
		}
	}
	return withoutRefs(exports, drop), omitted
}

// refPackages lists the packages a reference names: its own, then each
// package its type arguments name.
func refPackages(pkgPath string, ef exportedFunc) []string {
	paths := []string{pkgPath}
	record := func(p *types.Package) string {
		paths = append(paths, p.Path())
		return p.Name()
	}
	typeArgList(ef.recvArgs, record)
	typeArgList(ef.ownArgs, record)
	return paths
}

// importableFrom applies Go's internal-package rule: a path below an internal
// element may be imported only from within that element's parent.
func importableFrom(from, path string) bool {
	parent, found := "", false
	switch {
	case path == "internal" || strings.HasPrefix(path, "internal/"):
		return false // the standard library's own
	case strings.HasSuffix(path, "/internal"):
		parent, found = strings.TrimSuffix(path, "/internal"), true
	default:
		if i := strings.LastIndex(path, "/internal/"); i >= 0 {
			parent, found = path[:i], true
		}
	}
	return !found || from == parent || strings.HasPrefix(from, parent+"/")
}

// pruneHarness renders and type-checks the harness until it is clean, naming
// each reference it drops.
func pruneHarness(work []goListPackage, exports map[string][]exportedFunc, imp types.Importer, goVersion string) (string, []localdomain.HarnessOmission, error) {
	var omitted []localdomain.HarnessOmission
	for {
		code, refs := renderHarness(work, exports)
		bad := checkHarness(code, imp, goVersion)
		if len(bad) == 0 {
			return code, omitted, nil
		}
		drop := make(map[harnessRef]bool, len(bad))
		for line, msg := range bad {
			ref, ok := refs[line]
			if !ok {
				return "", nil, fmt.Errorf("the generated harness does not type-check at line %d: %s", line, msg)
			}
			drop[ref] = true
			omitted = append(omitted, localdomain.HarnessOmission{
				Symbol: exports[ref.pkgPath][ref.index].symbol(ref.pkgPath),
				Reason: "the harness reference does not type-check: " + msg,
			})
		}
		exports = withoutRefs(exports, drop)
	}
}

func withoutRefs(exports map[string][]exportedFunc, drop map[harnessRef]bool) map[string][]exportedFunc {
	kept := make(map[string][]exportedFunc, len(exports))
	for path, funcs := range exports {
		for i, ef := range funcs {
			if !drop[harnessRef{pkgPath: path, index: i}] {
				kept[path] = append(kept[path], ef)
			}
		}
	}
	return kept
}
