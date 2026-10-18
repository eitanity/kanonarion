package staticcha

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"golang.org/x/tools/go/packages"
)

func linknamePackage(t *testing.T, path, src string) *packages.Package {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := (&types.Config{Importer: importer.Default()}).Check(path, fset, []*ast.File{f}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &packages.Package{PkgPath: path, Types: tp, Syntax: []*ast.File{f}}
}

// The directive is read as TinyGo reads it: on the doc comment, else free in
// the same file; only in a package importing unsafe; and only with two names.
func TestReadLinknames(t *testing.T) {
	withUnsafe := linknamePackage(t, "example.com/p", `package p

import _ "unsafe"

//go:linkname pull other.target
func pull()

//go:linknamestd push other.decl
func push() {}

//go:linkname free other.free

func free()

//go:linkname doc other.doc
func doc()

//go:linkname doc other.ignored

//go:linkname malformed
func malformed()

type T struct{}

//go:linkname M other.method
func (T) M()

func plain() {}
`)
	got := readLinknames([]*packages.Package{withUnsafe})
	want := map[string]linknameDecl{
		"example.com/p.pull": {symbol: "other.target"},
		"example.com/p.push": {symbol: "other.decl", hasBody: true},
		"example.com/p.free": {symbol: "other.free"},
		"example.com/p.doc":  {symbol: "other.doc"},
	}
	if len(got) != len(want) {
		t.Errorf("readLinknames = %v, want %v", got, want)
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s = %+v, want %+v", id, got[id], w)
		}
	}

	noUnsafe := linknamePackage(t, "example.com/q", `package q

//go:linkname pull other.target
func pull()
`)
	if got := readLinknames([]*packages.Package{noUnsafe}); len(got) != 0 {
		t.Errorf("a package without unsafe = %v, want TinyGo's gate to drop it", got)
	}
	untyped := &packages.Package{PkgPath: "example.com/r"}
	if got := readLinknames([]*packages.Package{untyped}); len(got) != 0 {
		t.Errorf("an untyped package = %v", got)
	}
}
