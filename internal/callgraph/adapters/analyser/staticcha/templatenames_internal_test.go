package staticcha

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// An embedded file gone between the load and the walk leaves the Parse text
// unreadable rather than failing the extraction; the same site reads while the
// file is there.
func TestParseText_AnEmbeddedFileRemovedAfterLoadIsUnreadable(t *testing.T) {
	dir := t.TempDir()
	for rel, content := range map[string]string{
		"go.mod": "module example.com/embedgone\n\ngo 1.21\n",
		"t.tmpl": "{{.Name}}",
		"p.go": `package embedgone

import (
	_ "embed"
	"text/template"
)

//go:embed t.tmpl
var text string

func Load() *template.Template { return template.Must(template.New("a").Parse(text)) }
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedSyntax | packages.NeedTypes |
			packages.NeedTypesInfo | packages.NeedFiles | packages.NeedImports | packages.NeedDeps,
		Dir:  dir,
		Fset: token.NewFileSet(),
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil || len(pkgs) != 1 || len(pkgs[0].Errors) > 0 {
		t.Fatalf("load: %v %v", err, pkgs)
	}
	embeds := readEmbeds(pkgs)
	if len(embeds) != 1 {
		t.Fatalf("readEmbeds = %v, want the one var", embeds)
	}
	prog, _ := ssautil.AllPackages(pkgs, ssa.BuilderMode(0))
	prog.Build()
	cg := chaCallGraph(closedFunctionSet(prog))

	var site ssa.CallInstruction
	if err := callgraph.GraphVisitEdges(cg, func(e *callgraph.Edge) error {
		if e.Callee.Func.String() == "(*text/template.Template).Parse" && e.Caller.Func.Name() == "Load" {
			site = e.Site
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if site == nil {
		t.Fatal("no Parse edge")
	}
	if text, ok := newTemplateNames(cg, embeds).parseText(site); !ok || text != "{{.Name}}" {
		t.Fatalf("with the file present parseText = %q, %v", text, ok)
	}
	if err := os.Remove(filepath.Join(dir, "t.tmpl")); err != nil {
		t.Fatal(err)
	}
	if text, ok := newTemplateNames(cg, embeds).parseText(site); ok {
		t.Errorf("with the file gone parseText = %q, want unreadable", text)
	}
}

// A directive names one regular file only with one unquoted pattern matching
// one file; anything else is no file.
func TestEmbedFile(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"a.tmpl", "b.tmpl", "one.txt"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	doc := func(lines ...string) *ast.CommentGroup {
		src := "package p\n\n"
		for _, l := range lines {
			src += l + "\n"
		}
		f, err := parser.ParseFile(token.NewFileSet(), "p.go", src+"var v string\n", parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		gd, ok := f.Decls[0].(*ast.GenDecl)
		if !ok {
			t.Fatal("no var declaration")
		}
		return gd.Doc
	}
	for _, tt := range []struct {
		name string
		doc  *ast.CommentGroup
		want string
	}{
		{"one file", doc("//go:embed one.txt"), "one.txt"},
		{"all prefix", doc("//go:embed all:one.txt"), "one.txt"},
		{"a glob of one", doc("//go:embed one.*"), "one.txt"},
		{"a glob of two", doc("//go:embed *.tmpl"), ""},
		{"two patterns", doc("//go:embed a.tmpl b.tmpl"), ""},
		{"two lines", doc("//go:embed a.tmpl", "//go:embed b.tmpl"), ""},
		{"a directory", doc("//go:embed sub"), ""},
		{"missing", doc("//go:embed gone.txt"), ""},
		{"quoted", doc(`//go:embed "one.txt"`), ""},
		{"bad glob", doc("//go:embed [one.txt"), ""},
		{"no directive", doc("//go:embedded one.txt", "// one.txt"), ""},
		{"no doc", nil, ""},
	} {
		got, ok := embedFile(tt.doc, dir)
		if tt.want == "" {
			if ok {
				t.Errorf("%s: embedFile = %q, want none", tt.name, got)
			}
			continue
		}
		if !ok || got != filepath.Join(dir, tt.want) {
			t.Errorf("%s: embedFile = %q, %v, want %s", tt.name, got, ok, tt.want)
		}
	}
}
