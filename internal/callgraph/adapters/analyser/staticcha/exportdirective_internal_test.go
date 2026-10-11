package staticcha

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"golang.org/x/tools/go/packages"
)

const directiveSrc = `package p

//export both
//go:wasmexport both
func both() {}

//export
func nameless() {}

type T struct{}

//go:wasmexport m
func (T) M() {}

func undocumented() {}
`

func parseDirectiveSrc(t *testing.T) (*packages.Package, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", directiveSrc, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	return &packages.Package{PkgPath: "example.com/p", Syntax: []*ast.File{f}}, fset
}

func TestExportDirectives_StatesWhatItCannotAttribute(t *testing.T) {
	p, fset := parseDirectiveSrc(t)
	// The package is passed twice, as a production file is met in the package
	// and in its test variant; each statement must still appear once.
	got, unattributed := exportDirectives([]*packages.Package{p, p}, fset)

	if want := (domain.ExportDirective{Kind: domain.ExportWasm, Name: "both"}); got["example.com/p.both"] != want {
		t.Errorf("both = %+v, want %+v: //go:wasmexport wins over //export", got["example.com/p.both"], want)
	}
	if len(got) != 1 {
		t.Errorf("recorded %d directives, want only both's: %v", len(got), got)
	}
	if len(unattributed) != 2 {
		t.Fatalf("unattributed = %q, want the nameless export and the method", unattributed)
	}
	// Sorted as strings, so line 13 comes before line 7.
	if !strings.Contains(unattributed[1], "p.go:7:1: invalid export directive: //export takes one name, got 0") {
		t.Errorf("nameless statement = %q", unattributed[1])
	}
	if !strings.Contains(unattributed[0], "p.go:13:1: //go:wasmexport m on method M is not recorded") {
		t.Errorf("method statement = %q", unattributed[0])
	}
}

func TestExportDirectives_SkipsTheSyntheticTestMain(t *testing.T) {
	p, fset := parseDirectiveSrc(t)
	p.ID = "example.com/p.test"
	p.PkgPath = "example.com/p.test"
	p.Name = "main"
	got, unattributed := exportDirectives([]*packages.Package{p}, fset)
	if len(got) != 0 || len(unattributed) != 0 {
		t.Errorf("the synthetic test main contributed %v and %q", got, unattributed)
	}
}

func TestAttachExportDirectives(t *testing.T) {
	nodes := []domain.CallNode{{ID: "a"}, {ID: "b"}}
	d := domain.ExportDirective{Kind: domain.ExportC, Name: "a"}
	attachExportDirectives(nodes, map[string]domain.ExportDirective{"a": d})
	if nodes[0].ExportDirective != d || !nodes[1].ExportDirective.IsZero() {
		t.Errorf("nodes = %+v", nodes)
	}
}
