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
// Fields read by the constructor body itself (the RunE closure) are accounted
// for on every path, because that is where a command chooses its path: --gomod
// and --tool select a dispatch rather than travelling into one.
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
		if flagVar == "" {
			continue // command takes no flag struct
		}
		registered := boundFlagFields(ctor, flagVar)
		if len(registered) == 0 {
			continue
		}
		checked++
		inCtor := fieldsReadIn(ctor.Body, flagVar)
		for _, d := range dispatchTargets(ctor, flagVar, funcs) {
			read := fieldsReadTransitively(d.fn, d.param, flagType, funcs, map[string]bool{})
			var missing []string
			for _, field := range registered {
				if inCtor[field] || read[field] {
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

type dispatchTarget struct {
	fn    *ast.FuncDecl
	param string
}

// dispatchTargets returns every package-level function the constructor hands
// the whole flag struct to — the command's dispatch paths — paired with the
// parameter name that function receives it as.
func dispatchTargets(ctor *ast.FuncDecl, flagVar string, funcs map[string]*ast.FuncDecl) []dispatchTarget {
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
		if !ok || seen[id.Name] {
			return true
		}
		for i, arg := range call.Args {
			a, ok := arg.(*ast.Ident)
			if !ok || a.Name != flagVar {
				continue
			}
			if param := paramNameAt(fn, i); param != "" {
				seen[id.Name] = true
				out = append(out, dispatchTarget{fn: fn, param: param})
			}
			break
		}
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].fn.Name.Name < out[j].fn.Name.Name })
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
