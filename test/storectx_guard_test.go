package cmd_test

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// sqlWithoutContext is database/sql's context-free twin of each ctx-taking
// method on a connection pool or a connection.
var sqlWithoutContext = map[string]bool{"Exec": true, "Query": true, "QueryRow": true, "Begin": true, "Prepare": true}

// TestStoreStatementsHonourTheCallersContext guards what keeps a cancelled run
// from recording a failure: every statement that has a context in scope hands it
// to database/sql, which refuses a cancelled one before it reaches the store, so
// a failure record built from a cancellation is never written. A statement on a
// transaction is bound to the context the transaction began with. Migrations run
// with no context in scope by design, so they are outside the rule.
func TestStoreStatementsHonourTheCallersContext(t *testing.T) {
	cfg := &packages.Config{
		Mode: packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedName | packages.NeedFiles | packages.NeedDeps | packages.NeedImports,
		Dir: "..",
	}
	pkgs, err := packages.Load(cfg, "./internal/...", "./cmd/...")
	if err != nil {
		t.Fatalf("packages.Load: %v", err)
	}
	checked := 0
	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			name := pkg.Fset.Position(file.Pos()).Filename
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			for _, v := range contextFreeStatements(file, pkg.TypesInfo) {
				pos := pkg.Fset.Position(v)
				t.Errorf("%s:%d runs a statement without the context in scope; use the Context form, or "+
					"a cancelled run can still write", repoRelFile(pos.Filename), pos.Line)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("the guard read no files")
	}
}

// TestStoreContextGuardCatchesAContextFreeStatement plants the violation and the
// two shapes the rule allows, and shows the detector tells them apart.
func TestStoreContextGuardCatchesAContextFreeStatement(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{"a write that drops the context", "func put(ctx context.Context, db *sql.DB) { _, _ = db.Exec(\"x\") }", 1},
		{"a closure that drops it", "func put(ctx context.Context, db *sql.DB) { f := func() { _, _ = db.Begin() }; f() }", 1},
		{"the context form", "func put(ctx context.Context, db *sql.DB) { _, _ = db.ExecContext(ctx, \"x\") }", 0},
		{"a statement on a transaction", "func put(ctx context.Context, tx *sql.Tx) { _, _ = tx.Exec(\"x\") }", 0},
		{"a migration, with no context in scope", "var _ context.Context\nfunc migrate(db *sql.DB) { _, _ = db.Exec(\"x\") }", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "package p\nimport (\n\"context\"\n\"database/sql\"\n)\n" + tc.body + "\n"
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "p.go", src, 0)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}, Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}}
			conf := types.Config{Importer: importer.Default()}
			if _, err := conf.Check("p", fset, []*ast.File{file}, info); err != nil {
				t.Fatalf("type-check: %v", err)
			}
			if got := len(contextFreeStatements(file, info)); got != tc.want {
				t.Errorf("flagged %d statements, want %d", got, tc.want)
			}
		})
	}
}

// contextFreeStatements returns the context-free database/sql calls on a *sql.DB
// or *sql.Conn made where a context.Context parameter is in scope.
func contextFreeStatements(file *ast.File, info *types.Info) []token.Pos {
	var out []token.Pos
	var visit func(n ast.Node, ctxInScope bool)
	visit = func(n ast.Node, ctxInScope bool) {
		ast.Inspect(n, func(m ast.Node) bool {
			switch x := m.(type) {
			case *ast.FuncLit:
				if x != n {
					visit(x.Body, ctxInScope || takesContext(x.Type, info))
					return false
				}
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok || !ctxInScope || !sqlWithoutContext[sel.Sel.Name] {
					return true
				}
				if s := info.Selections[sel]; s != nil && isPoolOrConn(s.Recv()) {
					out = append(out, x.Pos())
				}
			}
			return true
		})
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			visit(fn.Body, takesContext(fn.Type, info))
		}
	}
	return out
}

func takesContext(ft *ast.FuncType, info *types.Info) bool {
	for _, field := range ft.Params.List {
		if tv, ok := info.Types[field.Type]; ok && types.TypeString(tv.Type, nil) == "context.Context" {
			return true
		}
	}
	return false
}

func isPoolOrConn(t types.Type) bool {
	switch types.TypeString(t, nil) {
	case "*database/sql.DB", "*database/sql.Conn":
		return true
	}
	return false
}
