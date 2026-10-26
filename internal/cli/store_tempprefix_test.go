package cli

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/childproc"
)

// Every temp entry production code makes in the system temp directory is one
// `store clean` recovers. A process killed outright cannot remove its own, so a
// prefix missing from tempPrefixes is a directory that leaks for good.
func TestStoreCleanCoversEveryTempPrefix(t *testing.T) {
	covered := func(pattern string) bool {
		for _, p := range tempPrefixes {
			if strings.HasPrefix(pattern, p) {
				return true
			}
		}
		return false
	}
	if !covered(childproc.ScratchPrefix + "x") {
		t.Errorf("the child scratch prefix %q is not swept", childproc.ScratchPrefix)
	}
	seen := 0
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if perr != nil {
			return fmt.Errorf("parsing %s: %w", path, perr)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, lit, ok := systemTempPattern(n)
			if !ok {
				return true
			}
			pattern, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatalf("Unquote: %v", err)
			}
			seen++
			if !covered(pattern) {
				t.Errorf("%s: os.%s pattern %q is not in tempPrefixes, so store clean never recovers it", path, sel.Sel.Name, pattern)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking internal/: %v", err)
	}
	if seen == 0 {
		t.Fatal("found no temp-directory creation at all; the walk is not reading the source")
	}
}

// systemTempPattern reports whether n is an os.MkdirTemp or os.CreateTemp call
// in the system temp directory with a literal pattern, and returns its
// selector and pattern literal.
func systemTempPattern(n ast.Node) (*ast.SelectorExpr, *ast.BasicLit, bool) {
	call, ok := n.(*ast.CallExpr)
	if !ok || len(call.Args) != 2 {
		return nil, nil, false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "MkdirTemp" && sel.Sel.Name != "CreateTemp") {
		return nil, nil, false
	}
	if pkg, isIdent := sel.X.(*ast.Ident); !isIdent || pkg.Name != "os" {
		return nil, nil, false
	}
	dir, ok := call.Args[0].(*ast.BasicLit)
	if !ok || dir.Value != `""` {
		return nil, nil, false // a named directory, not the system temp directory
	}
	lit, ok := call.Args[1].(*ast.BasicLit)
	if !ok {
		return nil, nil, false // a constant expression; the scratch prefix is checked above
	}
	return sel, lit, true
}
