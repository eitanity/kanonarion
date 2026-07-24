package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoCommandWritesProseToStdoutBeforeCheckingJSON guards the whole
// empty-result defect family (KN-458, KN-473): a command that supports --json
// must not write a human sentence to stdout on a path reached before it
// consults jsonOut. Such a sentence lands on the data channel under --json and
// the caller gets unparseable prose with exit 0, the same failure mode that let
// this family spread across a dozen commands one branch at a time.
//
// The guard is shape-based, not wording-based (which is why the family member
// in vendor.go, whose message begins "project is not vendored" rather than
// "no ...", could not hide from it): for every function in the package that
// references jsonOut, it flags any fmt.Fprint*(stdout, "<literal>") call
// positioned, by source order, before that function's first jsonOut reference.
// Moving the stdout write behind the jsonOut check — the fix applied to every
// member of the family — clears the finding. Functions that never reference
// jsonOut are out of scope: they have no JSON contract on stdout to corrupt.
func TestNoCommandWritesProseToStdoutBeforeCheckingJSON(t *testing.T) {
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
		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			first := firstJSONOutPos(fn.Body)
			if !first.IsValid() {
				return true // no JSON contract in this function
			}
			for _, call := range proseStdoutCallPositions(fn.Body) {
				if call < first {
					pos := fset.Position(call)
					t.Errorf("%s:%d writes prose to stdout before checking jsonOut; "+
						"move the stdout write behind the jsonOut branch so an empty "+
						"result does not corrupt the --json data channel",
						filepath.Base(pos.Filename), pos.Line)
				}
			}
			return true
		})
	}
	if !sawSource {
		t.Fatal("only test files matched: the guard would pass vacuously")
	}
}

// firstJSONOutPos returns the position of the earliest reference to the
// identifier "jsonOut" within body, or an invalid position if there is none.
func firstJSONOutPos(body *ast.BlockStmt) token.Pos {
	var first token.Pos
	ast.Inspect(body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == "jsonOut" {
			if !first.IsValid() || id.Pos() < first {
				first = id.Pos()
			}
		}
		return true
	})
	return first
}

// proseStdoutCallPositions returns the positions of every
// fmt.Fprint/Fprintf/Fprintln call in body whose first argument is the writer
// named "stdout" and whose next argument is a string literal — the signature of
// a human sentence written to the data channel.
func proseStdoutCallPositions(body *ast.BlockStmt) []token.Pos {
	var out []token.Pos
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "fmt" {
			return true
		}
		switch sel.Sel.Name {
		case "Fprint", "Fprintf", "Fprintln":
		default:
			return true
		}
		if len(call.Args) < 2 {
			return true
		}
		w, ok := call.Args[0].(*ast.Ident)
		if !ok || w.Name != "stdout" {
			return true
		}
		lit, ok := call.Args[1].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		out = append(out, call.Pos())
		return true
	})
	return out
}
