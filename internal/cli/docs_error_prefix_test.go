package cli

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// printedErrorPrefix is how an error from Run reaches the terminal: the format
// ExitStatus gives fmt.Fprintf, up to its verb, then the prefix Run puts on every
// error. It is read from ExitStatus's source so a change there moves the guard too.
func printedErrorPrefix(t *testing.T) string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "root.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing root.go: %v", err)
	}
	var exitStatus ast.Node
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "ExitStatus" {
			exitStatus = fn
		}
	}
	if exitStatus == nil {
		t.Fatal("root.go declares no ExitStatus")
	}
	format := ""
	ast.Inspect(exitStatus, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); !ok || sel.Sel.Name != "Fprintf" {
			return true
		}
		if lit, ok := call.Args[1].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if v, uerr := strconv.Unquote(lit.Value); uerr == nil {
				format = v
			}
		}
		return true
	})
	lead, _, ok := strings.Cut(format, "%v")
	if !ok || lead == "" {
		t.Fatalf("ExitStatus prints no error with a %%v format (found %q)", format)
	}
	return lead + rootErrorPrefix
}

// docErrorLine is one `error:` line in a docs example.
type docErrorLine struct {
	file string
	line int
	text string
}

// docsErrorLines returns every line starting `error:` (after indentation) inside
// a fenced block under root. Every block is read, not only those showing a
// `$ kanonarion` prompt: several refusals are quoted without one.
func docsErrorLines(t *testing.T, root string) []docErrorLine {
	t.Helper()
	var out []docErrorLine
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".md" {
			return err
		}
		data, rerr := os.ReadFile(path) // #nosec G304,G122 -- a file under the repo's own docs tree
		if rerr != nil {
			return fmt.Errorf("reading %s: %w", path, rerr)
		}
		out = append(out, errorLinesIn(path, string(data))...)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return out
}

func errorLinesIn(path, text string) []docErrorLine {
	var out []docErrorLine
	inFence := false
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
			continue
		}
		if inFence && strings.HasPrefix(line, "error:") {
			out = append(out, docErrorLine{file: path, line: i + 1, text: line})
		}
	}
	return out
}

// TestDocs_ErrorLinesCarryThePrintedPrefix: an `error:` line in a docs example
// is what the binary prints, prefix included, so the docs cannot show a refusal
// in a form no run produces.
func TestDocs_ErrorLinesCarryThePrintedPrefix(t *testing.T) {
	prefix := printedErrorPrefix(t)
	lines := docsErrorLines(t, filepath.Join("..", "..", "docs"))
	if len(lines) == 0 {
		t.Fatal("no error lines found in the docs examples; the scan is not reading them")
	}
	t.Logf("%d error line(s) in docs examples", len(lines))
	for _, l := range lines {
		if !strings.HasPrefix(l.text, prefix) {
			t.Errorf("%s:%d: %q does not start with %q", l.file, l.line, l.text, prefix)
		}
	}
}
