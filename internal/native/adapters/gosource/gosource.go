// Package gosource implements the native context's GoSourceReader port over
// go/parser.
//
// It exists so the application and domain layers hold no Go-parsing dependency:
// finding what a file imports, and finding the C preamble it attaches to that
// import, is infrastructure. The rules those two facts feed — that a package
// importing "C" is compiled with cgo, and what a `#cgo LDFLAGS` line names — are
// domain knowledge that needs no parser of its own.
package gosource

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"

	"github.com/eitanity/kanonarion/internal/native/domain"
)

// Reader reads the import paths and cgo preamble of a Go source file.
type Reader struct{}

// New returns a Reader.
func New() Reader { return Reader{} }

// ImportPaths returns the unquoted import paths src declares.
//
// Parsing stops at the end of the import block, so a file whose body does not
// compile — a future-syntax file, a fixture, a partially vendored source — still
// answers what it imports. A file whose header cannot be parsed at all is an
// error rather than an empty set: reading it as importing nothing would read it
// as not using cgo, and would drop a whole native component in silence.
func (Reader) ImportPaths(filename string, src []byte) ([]string, error) {
	file, err := parse(filename, src)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(file.Imports))
	for _, imp := range file.Imports {
		if imp.Path == nil {
			continue
		}
		path, uerr := strconv.Unquote(imp.Path.Value)
		if uerr != nil {
			return nil, fmt.Errorf("unquoting import %s in %s: %w", imp.Path.Value, filename, uerr)
		}
		out = append(out, path)
	}
	return out, nil
}

// CgoPreamble returns the C preamble src attaches to its `import "C"`, with the
// comment markers stripped and nothing else changed. A file that does not
// import "C", or imports it with no preamble, yields the empty string.
//
// The attachment rule is cgo's own: the comment group documenting the import
// spec, or the one documenting the declaration when it holds that import alone.
// Any looser rule — the nearest comment, every comment in the file — would read
// an unrelated block comment as a build directive.
func (Reader) CgoPreamble(filename string, src []byte) (string, error) {
	file, err := parse(filename, src)
	if err != nil {
		return "", err
	}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.IMPORT {
			continue
		}
		for _, spec := range gen.Specs {
			imp, ok := spec.(*ast.ImportSpec)
			if !ok || imp.Path == nil || imp.Path.Value != `"`+domain.CgoImportPath+`"` {
				continue
			}
			group := imp.Doc
			if group == nil && len(gen.Specs) == 1 {
				group = gen.Doc
			}
			if group == nil {
				return "", nil
			}
			return commentText(group), nil
		}
	}
	return "", nil
}

// commentText strips the comment markers from a group, joining the pieces with
// newlines. It does not use ast.CommentGroup.Text, which drops lines it reads as
// Go directives and normalises the whitespace around the rest: a `#cgo` line
// must survive verbatim, because it is recorded as the evidence for a claim.
func commentText(group *ast.CommentGroup) string {
	pieces := make([]string, 0, len(group.List))
	for _, c := range group.List {
		text := c.Text
		switch {
		case strings.HasPrefix(text, "//"):
			pieces = append(pieces, strings.TrimSuffix(text[2:], "\r"))
		case strings.HasPrefix(text, "/*"):
			pieces = append(pieces, strings.TrimSuffix(strings.TrimPrefix(text, "/*"), "*/"))
		default:
			pieces = append(pieces, text)
		}
	}
	return strings.Join(pieces, "\n")
}

// parse reads the header of a Go file: its imports and the comments around
// them, and nothing after.
func parse(filename string, src []byte) (*ast.File, error) {
	file, err := parser.ParseFile(token.NewFileSet(), filename, src,
		parser.ImportsOnly|parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parsing imports of %s: %w", filename, err)
	}
	return file, nil
}
