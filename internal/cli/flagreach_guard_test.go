package cli

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestEveryDispatchPathAccountsForItsCommandsFlags guards the defect family in
// which a command registers a flag, dispatches to one of several path-specific
// run functions, and only some of those functions ever read the field the flag
// wrote. The flag parses, the command exits 0, and the output is byte-identical
// to a run without it — the worst shape a flag can have, because the caller
// gets no signal at all that the question it asked was discarded.
//
// The guard is structural, not a list of known combinations: a hand-maintained
// list of (path, flag) pairs is exactly the instrument that let this family grow
// once already. For each command constructor it collects the flag-struct fields
// the constructor binds (any &f.field handed to a registrar), then for each
// function that constructor dispatches the whole flag struct into it collects
// the fields that function reads — transitively, through any helper it hands the
// same struct to, because a dispatch function that delegates to a helper hides
// the read from a per-function walk. A registered field that no reachable
// function reads is reported.
//
// Reading the field to refuse the combination counts as reading it: refusing
// names the path and tells the caller its flag did not apply, which is the
// remedy this guard exists to require. Silently ignoring it is not.
//
// A read in the constructor body (the RunE closure) does NOT account for the
// flag on every path. It accounts for it only on the paths the value it derived
// actually reaches: a field read into a local that is then handed to one
// dispatch call is answered for on that call and nowhere else, and a field read
// only to validate the invocation is answered for nowhere. Blanket
// constructor-read credit is what let a scope flag resolved by one branch, and
// a validation-only read of a flag another branch discards, both pass as
// accounted. A constructor may still resolve one flag into another field of the
// same struct (fetch resolves --policy into the effective VCS host allowlist);
// a path that reads the resolved field has consumed the flag behind it.
//
// Two shapes are outside what this guard can see, and both are held closed by
// other means:
//
//   - A flag bound to a LOCAL VARIABLE rather than a struct field is invisible
//     to the field walk. Rather than model local flow into every run function,
//     the guard requires a command with more than one dispatch path to keep its
//     flags in a struct: locals plus multiple paths is reported on its own.
//   - A branch INSIDE one dispatch function is below this guard's
//     function-level granularity: `sbom <walk-id> --stdlib-from-gomod` reaches
//     runSBOMGenerate, which does read the field — on the other branch, the one
//     that builds a project walk. That pair is held closed by the refusal in
//     sbomGenerateWith and by TestSBOMWalkIDRefusesStdlibFromGoMod, not here.
//     Nothing in this guard covers it, and nothing should be read as if it did.
func TestEveryDispatchPathAccountsForItsCommandsFlags(t *testing.T) {
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("globbing package sources: %v", err)
	}
	// Fail rather than pass vacuously if the glob finds nothing, matching
	// TestNoCommandBuildsItsLoggerAgainstStdout.
	if len(sources) == 0 {
		t.Fatal("no package sources found: the guard would pass vacuously")
	}

	fset := token.NewFileSet()
	funcs := map[string]*ast.FuncDecl{}
	structTypes := map[string]bool{}
	var constructors []*ast.FuncDecl
	sawSource := false
	for _, path := range sources {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		sawSource = true
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parsing %s: %v", path, perr)
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv != nil || d.Body == nil {
					continue
				}
				funcs[d.Name.Name] = d
				if strings.HasPrefix(d.Name.Name, "new") && strings.HasSuffix(d.Name.Name, "Cmd") {
					constructors = append(constructors, d)
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					if _, ok := ts.Type.(*ast.StructType); ok {
						structTypes[ts.Name.Name] = true
					}
				}
			}
		}
	}
	if !sawSource {
		t.Fatal("only test files matched: the guard would pass vacuously")
	}
	if len(constructors) == 0 {
		t.Fatal("no command constructors found: the guard would pass vacuously")
	}

	sort.Slice(constructors, func(i, j int) bool { return constructors[i].Name.Name < constructors[j].Name.Name })

	checked := 0
	for _, ctor := range constructors {
		flagVar, flagType := flagStructVar(ctor, structTypes)
		locals := boundFlagLocals(ctor)
		registered := []string{}
		if flagVar != "" {
			registered = boundFlagFields(ctor, flagVar)
		}
		targets := dispatchTargets(ctor, flagVar, locals, funcs)
		carried, resolvedInto := flagValueFlow(ctor, flagVar, nil)
		checkLocalFlagBindings(t, fset, ctor, locals, targets)
		if len(registered) == 0 {
			continue
		}
		checked++
		for _, d := range targets {
			if d.param == "" {
				continue // reached with a local only; the locals rule above covers it
			}
			read := resolveFields(fieldsReadTransitively(d.fn, d.param, flagType, funcs, map[string]bool{}), resolvedInto)
			viaArgs := fieldsReachingCall(d.call, flagVar, carried)
			var missing []string
			for _, field := range registered {
				if read[field] || viaArgs[field] {
					continue
				}
				missing = append(missing, field)
			}
			if len(missing) == 0 {
				continue
			}
			sort.Strings(missing)
			pos := fset.Position(d.fn.Pos())
			t.Errorf("%s registers %s but %s (%s:%d) never reads %s: the flag parses, "+
				"the command exits 0, and the output is unchanged. Honour the flag on "+
				"this path, or refuse the combination with a message naming the path.",
				ctor.Name.Name, strings.Join(missing, ", "), d.fn.Name.Name,
				filepath.Base(pos.Filename), pos.Line, plural(missing))
		}
	}
	if checked == 0 {
		t.Fatal("no command with a flag struct was checked: the guard would pass vacuously")
	}
}

func plural(missing []string) string {
	if len(missing) == 1 {
		return "it"
	}
	return "them"
}

// flagStructVar returns the name and type name of the command constructor's
// flag struct variable, declared as `var f <someFlags>` where the type is a
// struct declared in this package.
func flagStructVar(ctor *ast.FuncDecl, structTypes map[string]bool) (name, typeName string) {
	for _, stmt := range ctor.Body.List {
		decl, ok := stmt.(*ast.DeclStmt)
		if !ok {
			continue
		}
		gen, ok := decl.Decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || vs.Type == nil {
				continue
			}
			id, ok := vs.Type.(*ast.Ident)
			if !ok || !structTypes[id.Name] {
				continue
			}
			return vs.Names[0].Name, id.Name
		}
	}
	return "", ""
}

// boundFlagFields returns the flag-struct fields the constructor hands to a
// registrar by address (&f.field), which is how both cobra's *Var calls and the
// package's shared register* helpers bind a flag to its field.
func boundFlagFields(ctor *ast.FuncDecl, flagVar string) []string {
	seen := map[string]bool{}
	var out []string
	ast.Inspect(ctor.Body, func(n ast.Node) bool {
		u, ok := n.(*ast.UnaryExpr)
		if !ok || u.Op != token.AND {
			return true
		}
		if field, ok := selectorField(u.X, flagVar); ok && !seen[field] {
			seen[field] = true
			out = append(out, field)
		}
		return true
	})
	sort.Strings(out)
	return out
}

// selectorField reports the field name when expr is `<recv>.<field>`.
func selectorField(expr ast.Expr, recv string) (string, bool) {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || id.Name != recv {
		return "", false
	}
	return sel.Sel.Name, true
}

// fieldsReadIn returns the flag-struct fields read in body, excluding the
// address-of expressions that bind a flag to its field: binding a flag is not
// answering for it.
func fieldsReadIn(body *ast.BlockStmt, recv string) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		if u, ok := n.(*ast.UnaryExpr); ok && u.Op == token.AND {
			if _, isField := selectorField(u.X, recv); isField {
				return false // registration, not a read
			}
		}
		if expr, ok := n.(ast.Expr); ok {
			if field, ok := selectorField(expr, recv); ok {
				out[field] = true
			}
		}
		return true
	})
	return out
}

// checkLocalFlagBindings reports a flag bound to a local variable that one of
// the command's dispatch paths never receives. It is the coarse arm of this
// guard: a local carries no field name into the callee, so all it can ask is
// whether the value reaches each path at all — a local the constructor also
// reads for itself (to select a path, or to refuse the invocation) is credited
// without asking what that read did with it, which the field arm never does.
// Commands with more than one dispatch path are better off holding their flags
// in a struct, where the field arm applies.
func checkLocalFlagBindings(t *testing.T, fset *token.FileSet, ctor *ast.FuncDecl, locals []string, targets []dispatchTarget) {
	t.Helper()
	if len(locals) == 0 || len(targets) < 2 {
		return
	}
	seed := map[string]map[string]bool{}
	for _, l := range locals {
		seed[l] = map[string]bool{l: true}
	}
	carried, _ := flagValueFlow(ctor, "", seed)
	readInCtor := localsReadOutsideDispatch(ctor, locals, targets)
	// A flag whose spelling carries meaning on its own — one with a
	// NoOptDefVal, where "given, empty" differs from "not given" — is read as
	// cmd.Flags().Changed("name") rather than through its variable.
	for local, flag := range localFlagNames(ctor, locals) {
		if flagsChangedNames(ctor)[flag] {
			readInCtor[local] = true
		}
	}

	for _, d := range targets {
		var missing []string
		for _, l := range locals {
			if readInCtor[l] {
				continue
			}
			reached := false
			for f := range fieldsReachingCall(d.call, "", carried) {
				if f == l {
					reached = true
					break
				}
			}
			if !reached {
				missing = append(missing, l)
			}
		}
		if len(missing) == 0 {
			continue
		}
		sort.Strings(missing)
		pos := fset.Position(d.fn.Pos())
		t.Errorf("%s binds %s to a local variable and %s (%s:%d) is never handed %s: the flag "+
			"parses, the command exits 0, and the output is unchanged. Hand the value to this "+
			"path, refuse the combination with a message naming the path, or move the command's "+
			"flags into a flag struct so this guard can see them per field.",
			ctor.Name.Name, strings.Join(missing, ", "), d.fn.Name.Name,
			filepath.Base(pos.Filename), pos.Line, plural(missing))
	}
}

// localsReadOutsideDispatch reports which bound locals the constructor reads
// itself, ignoring both the address-of that binds them and the dispatch-call
// arguments that hand them on.
func localsReadOutsideDispatch(ctor *ast.FuncDecl, locals []string, targets []dispatchTarget) map[string]bool {
	isLocal := map[string]bool{}
	for _, l := range locals {
		isLocal[l] = true
	}
	skip := map[ast.Node]bool{}
	for _, d := range targets {
		for _, arg := range d.call.Args {
			skip[arg] = true
		}
	}
	out := map[string]bool{}
	ast.Inspect(ctor.Body, func(n ast.Node) bool {
		if n == nil || skip[n] {
			return false
		}
		switch d := n.(type) {
		case *ast.UnaryExpr:
			if d.Op == token.AND {
				if id, ok := d.X.(*ast.Ident); ok && isLocal[id.Name] {
					return false // registration, not a read
				}
			}
		case *ast.ValueSpec:
			for _, nm := range d.Names {
				skip[nm] = true // declaring the variable is not a read
			}
		case *ast.AssignStmt:
			for _, lhs := range d.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					skip[id] = true // writing to it is not a read
				}
			}
		case *ast.Ident:
			if isLocal[d.Name] {
				out[d.Name] = true
			}
		}
		return true
	})
	return out
}

// isDispatchTarget reports whether fn is one of a command's run functions, as
// opposed to a small helper a constructor calls to resolve a value before
// dispatching.
//
// Two signals, because neither alone is sufficient. Taking a context.Context is
// the usual one: a run function is handed the command's context. But it is not
// universal — a command whose whole job is a synchronous read of one file on
// disk takes no context and would otherwise fall out of this guard entirely,
// silently, which is the same shape of hole the guard exists to close. So a
// `run` prefix qualifies as well. The prefix is the package's own naming rule
// for run functions and nothing else uses it.
func isDispatchTarget(fn *ast.FuncDecl) bool {
	return funcTakesContext(fn) || strings.HasPrefix(fn.Name.Name, "run")
}

// funcTakesContext reports whether fn accepts a context.Context.
func funcTakesContext(fn *ast.FuncDecl) bool {
	for _, field := range fn.Type.Params.List {
		sel, ok := field.Type.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		pkg, ok := sel.X.(*ast.Ident)
		if ok && pkg.Name == "context" && sel.Sel.Name == "Context" {
			return true
		}
	}
	return false
}

// localFlagNames maps each bound local to the flag name it was registered
// under, read from the registrar call `...Var(&local, "name", ...)`.
func localFlagNames(ctor *ast.FuncDecl, locals []string) map[string]string {
	isLocal := map[string]bool{}
	for _, l := range locals {
		isLocal[l] = true
	}
	out := map[string]string{}
	ast.Inspect(ctor.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for i, arg := range call.Args {
			u, ok := arg.(*ast.UnaryExpr)
			if !ok || u.Op != token.AND {
				continue
			}
			id, ok := u.X.(*ast.Ident)
			if !ok || !isLocal[id.Name] || i+1 >= len(call.Args) {
				continue
			}
			lit, ok := call.Args[i+1].(*ast.BasicLit)
			if ok && lit.Kind == token.STRING {
				out[id.Name] = strings.Trim(lit.Value, `"`)
			}
		}
		return true
	})
	return out
}

// flagsChangedNames returns the flag names the constructor asks cobra about by
// name, as cmd.Flags().Changed("name") or Lookup("name").
func flagsChangedNames(ctor *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(ctor.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Changed" && sel.Sel.Name != "Lookup") || len(call.Args) != 1 {
			return true
		}
		if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			out[strings.Trim(lit.Value, `"`)] = true
		}
		return true
	})
	return out
}

// boundFlagLocals returns the constructor's local variables bound to a flag by
// address (&local), which is the binding form the flag-struct walk cannot see.
func boundFlagLocals(ctor *ast.FuncDecl) []string {
	declared := map[string]bool{}
	ast.Inspect(ctor.Body, func(n ast.Node) bool {
		switch d := n.(type) {
		case *ast.ValueSpec:
			for _, nm := range d.Names {
				declared[nm.Name] = true
			}
		case *ast.AssignStmt:
			if d.Tok != token.DEFINE {
				return true
			}
			for _, lhs := range d.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					declared[id.Name] = true
				}
			}
		}
		return true
	})
	seen := map[string]bool{}
	var out []string
	ast.Inspect(ctor.Body, func(n ast.Node) bool {
		u, ok := n.(*ast.UnaryExpr)
		if !ok || u.Op != token.AND {
			return true
		}
		id, ok := u.X.(*ast.Ident)
		if !ok || !declared[id.Name] || seen[id.Name] {
			return true
		}
		seen[id.Name] = true
		out = append(out, id.Name)
		return true
	})
	sort.Strings(out)
	return out
}

type dispatchTarget struct {
	fn    *ast.FuncDecl
	param string // the parameter the flag struct arrives as; "" when only locals do
	call  *ast.CallExpr
}

// dispatchTargets returns every package-level function the constructor hands
// the whole flag struct — or, for a command that binds its flags to locals, any
// of those locals — to. These are the command's dispatch paths, each paired
// with the parameter name the flag struct arrives as and the call that reaches
// it.
func dispatchTargets(ctor *ast.FuncDecl, flagVar string, locals []string, funcs map[string]*ast.FuncDecl) []dispatchTarget {
	isLocal := map[string]bool{}
	for _, l := range locals {
		isLocal[l] = true
	}
	seen := map[string]bool{}
	var out []dispatchTarget
	ast.Inspect(ctor.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		fn, ok := funcs[id.Name]
		if !ok || seen[id.Name] || !isDispatchTarget(fn) {
			return true
		}
		param := ""
		reached := false
		for i, arg := range call.Args {
			a, ok := arg.(*ast.Ident)
			if !ok {
				continue
			}
			switch {
			case flagVar != "" && a.Name == flagVar:
				if p := paramNameAt(fn, i); p != "" {
					param, reached = p, true
				}
			case isLocal[a.Name]:
				reached = true
			}
		}
		if !reached {
			return true
		}
		seen[id.Name] = true
		out = append(out, dispatchTarget{fn: fn, param: param, call: call})
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].fn.Name.Name < out[j].fn.Name.Name })
	return out
}

// flagValueFlow traces, within the constructor, where flag-struct field values
// travel. carried maps a local variable to the fields whose values flowed into
// it, so a dispatch call handed that local is handed those flags. resolvedInto
// maps a field the constructor writes to the fields that produced it, so a path
// reading the resolved field has consumed the flag behind it.
//
// The trace is deliberately over-inclusive within a statement (a multi-value
// assignment taints every name on the left) and runs to a fixed point, because
// under-reporting flow here would report a flag as dropped when a path does
// receive it.
// seed pre-loads carried, which the local-binding arm uses to trace bound
// locals rather than struct fields.
func flagValueFlow(ctor *ast.FuncDecl, flagVar string, seed map[string]map[string]bool) (carried, resolvedInto map[string]map[string]bool) {
	carried = map[string]map[string]bool{}
	for name, set := range seed {
		copied := map[string]bool{}
		for k := range set {
			copied[k] = true
		}
		carried[name] = copied
	}
	resolvedInto = map[string]map[string]bool{}

	type assignment struct {
		lhs []ast.Expr
		rhs []ast.Expr
	}
	var assigns []assignment
	ast.Inspect(ctor.Body, func(n ast.Node) bool {
		switch d := n.(type) {
		case *ast.AssignStmt:
			assigns = append(assigns, assignment{lhs: d.Lhs, rhs: d.Rhs})
		case *ast.ValueSpec:
			if len(d.Values) > 0 {
				lhs := make([]ast.Expr, 0, len(d.Names))
				for _, nm := range d.Names {
					lhs = append(lhs, nm)
				}
				assigns = append(assigns, assignment{lhs: lhs, rhs: d.Values})
			}
		}
		return true
	})

	// Assignments are visited in source order, but a value can be routed
	// through several locals, so iterate until nothing new is learned.
	for pass := 0; pass < len(assigns)+1; pass++ {
		grew := false
		for _, a := range assigns {
			for i, lhs := range a.lhs {
				var src ast.Expr
				if len(a.lhs) == len(a.rhs) {
					src = a.rhs[i]
				}
				fields := map[string]bool{}
				if src != nil {
					fields = fieldsReaching(src, flagVar, carried)
				} else {
					for _, r := range a.rhs {
						for f := range fieldsReaching(r, flagVar, carried) {
							fields[f] = true
						}
					}
				}
				if len(fields) == 0 {
					continue
				}
				switch target := lhs.(type) {
				case *ast.Ident:
					if target.Name == "_" || target.Name == flagVar {
						continue
					}
					if carried[target.Name] == nil {
						carried[target.Name] = map[string]bool{}
					}
					for f := range fields {
						if !carried[target.Name][f] {
							carried[target.Name][f] = true
							grew = true
						}
					}
				case *ast.SelectorExpr:
					field, ok := selectorField(target, flagVar)
					if !ok {
						continue
					}
					if resolvedInto[field] == nil {
						resolvedInto[field] = map[string]bool{}
					}
					for f := range fields {
						if f == field || resolvedInto[field][f] {
							continue
						}
						resolvedInto[field][f] = true
						grew = true
					}
				}
			}
		}
		if !grew {
			break
		}
	}
	return carried, resolvedInto
}

// fieldsReaching returns the flag-struct fields whose values reach expr, either
// read directly as flagVar.field or carried by a local the constructor already
// derived from one.
func fieldsReaching(expr ast.Expr, flagVar string, carried map[string]map[string]bool) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(expr, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			// The command literal holds the RunE closure: what that body reads
			// is the constructor's own reads, not a value flowing into the
			// variable the literal is assigned to.
			return false
		}
		if sel, ok := n.(*ast.SelectorExpr); ok && flagVar != "" {
			if field, ok := selectorField(sel, flagVar); ok {
				out[field] = true
				return false
			}
		}
		if id, ok := n.(*ast.Ident); ok {
			for f := range carried[id.Name] {
				out[f] = true
			}
		}
		return true
	})
	return out
}

// fieldsReachingCall returns the fields a dispatch call is handed as arguments,
// counting both a field passed directly and a local the constructor derived
// from one. Passing the flag struct itself is not a read: it is the callee's
// own reads that answer for those fields.
func fieldsReachingCall(call *ast.CallExpr, flagVar string, carried map[string]map[string]bool) map[string]bool {
	out := map[string]bool{}
	if call == nil {
		return out
	}
	for _, arg := range call.Args {
		if id, ok := arg.(*ast.Ident); ok && id.Name == flagVar {
			continue
		}
		for f := range fieldsReaching(arg, flagVar, carried) {
			out[f] = true
		}
	}
	return out
}

// resolveFields expands a set of fields a path read with the fields the
// constructor resolved into them.
func resolveFields(read map[string]bool, resolvedInto map[string]map[string]bool) map[string]bool {
	out := map[string]bool{}
	for field := range read {
		out[field] = true
		for src := range resolvedInto[field] {
			out[src] = true
		}
	}
	return out
}

// paramNameAt returns the name of fn's i-th parameter, flattening grouped
// parameter declarations. Blank and unnamed parameters yield "".
func paramNameAt(fn *ast.FuncDecl, i int) string {
	idx := 0
	for _, field := range fn.Type.Params.List {
		names := field.Names
		if len(names) == 0 {
			if idx == i {
				return ""
			}
			idx++
			continue
		}
		for _, nm := range names {
			if idx == i {
				if nm.Name == "_" {
					return ""
				}
				return nm.Name
			}
			idx++
		}
	}
	return ""
}

// fieldsReadTransitively returns the flag-struct fields fn reads, following any
// call that hands the same struct on to another package function. Without the
// transitive step a dispatch function that delegates its whole job to a helper
// would appear to read nothing, which is precisely the shape that hid a member
// of this family before.
func fieldsReadTransitively(fn *ast.FuncDecl, param, flagType string, funcs map[string]*ast.FuncDecl, visited map[string]bool) map[string]bool {
	key := fmt.Sprintf("%s/%s", fn.Name.Name, param)
	if visited[key] {
		return map[string]bool{}
	}
	visited[key] = true

	out := fieldsReadIn(fn.Body, param)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		callee, ok := funcs[id.Name]
		if !ok {
			return true
		}
		for i, arg := range call.Args {
			a, ok := arg.(*ast.Ident)
			if !ok || a.Name != param {
				continue
			}
			next := paramNameAt(callee, i)
			if next == "" {
				continue
			}
			for field := range fieldsReadTransitively(callee, next, flagType, funcs, visited) {
				out[field] = true
			}
		}
		return true
	})
	return out
}
