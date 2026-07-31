// Package goast reads Go declaration TEXT.
//
// The interface records this serves carry formatted signature strings and no
// type information, so every question about what a signature means has to be
// answered by parsing that text. Parsing is infrastructure — the domain
// compares records, it does not read Go — so it lives here, behind
// ports.SignatureReader, and the domain receives the answers.
package goast

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"reflect"
	"strings"

	"github.com/eitanity/kanonarion/internal/iface/domain"
	"github.com/eitanity/kanonarion/internal/iface/ports"
)

// Reader satisfies both the port and the shape the domain comparison asks for.
// They are declared separately because a domain package cannot import ports;
// these two lines are what keeps them from drifting apart.
var (
	_ ports.SignatureReader  = Reader{}
	_ domain.SignatureReader = Reader{}
)

// Reader is the ports.SignatureReader this package provides. It holds no
// state: every answer is computed from the text it is handed.
type Reader struct{}

// DiffersOnlyInSpelling implements the port.
func (Reader) DiffersOnlyInSpelling(a, b string) bool { return DiffersOnlyInSpelling(a, b) }

// CanonicalDeclaration returns a layout- and spelling-independent rendering of a
// stored declaration signature, and whether it could be produced at all.
//
// Two declarations whose canonical forms are equal denote the same Go
// declaration: a consumer compiled against one compiles against the other. The
// spellings collapsed here are exactly the ones the language itself treats as
// identical:
//
//   - the predeclared aliases: an empty interface{} and any are the same type,
//     as are byte/uint8 and rune/int32;
//   - parameter and result NAMES, which are not part of a function's type — a
//     signature that stops naming its results has the same type it had before;
//   - source layout, since the canonical form is whitespace-collapsed.
//
// Nothing else is collapsed. A field name in a struct, a struct tag, an
// argument's type, an added or dropped parameter: all of those survive, because
// each of them can break a consumer.
//
// The records this reads carry FORMATTED SIGNATURE TEXT and no type
// information, so this cannot be a go/types comparison — there is no type
// checker to ask, and no source to re-load. It is instead an AST comparison:
// the text is parsed with go/parser, rewritten as a tree (so `map[string]interface{}`
// is reached as reliably as a bare `interface{}`, which a textual substitution
// could not promise), and printed back. Text that does not parse yields ok=false
// and is never reported as equivalent to anything — an unreadable signature is
// not evidence of sameness.
func CanonicalDeclaration(s string) (string, bool) {
	src := domain.NormalizeSignature(s)
	if src == "" {
		return "", false
	}

	var wrapped string
	typeOnly := false
	switch {
	case strings.HasPrefix(src, "func "):
		// A method signature keeps its "func (recv T) Name(...)" form; a bare
		// "func(...)" is a type expression, not a declaration, and falls to the
		// value branch below.
		wrapped = "package p\n" + src
	case strings.HasPrefix(src, "type "):
		wrapped = "package p\n" + src
	default:
		// A ValueDecl carries a bare type expression ("map[string]any"), which is
		// only parseable in a declaration context.
		wrapped = "package p\nvar _ " + src
		typeOnly = true
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "signature.go", wrapped, parser.SkipObjectResolution)
	if err != nil || len(file.Decls) != 1 {
		return "", false
	}

	var node ast.Node
	// restoreMeaning re-applies the one thing clearPositions must not erase.
	restoreMeaning := func() {}
	switch decl := file.Decls[0].(type) {
	case *ast.FuncDecl:
		decl.Doc = nil
		decl.Body = nil
		normaliseFuncType(decl.Type)
		if decl.Recv != nil {
			normaliseFieldList(decl.Recv, false)
		}
		node = decl
	case *ast.GenDecl:
		decl.Doc = nil
		spec, ok := singleSpec(decl)
		if !ok {
			return "", false
		}
		switch s := spec.(type) {
		case *ast.TypeSpec:
			s.Doc, s.Comment = nil, nil
			s.Type = normaliseExpr(s.Type)
			// TypeSpec.Assign is a position that carries MEANING: valid for
			// "type T = U" and invalid for "type T U", which are different
			// declarations. Clearing positions would erase the difference — it did
			// — so the alias marker is put back before the canonical form is
			// printed.
			if s.Assign.IsValid() {
				restoreMeaning = func() { s.Assign = 1 }
			}
			node = decl
		case *ast.ValueSpec:
			if !typeOnly || s.Type == nil {
				return "", false
			}
			node = normaliseExpr(s.Type)
		default:
			return "", false
		}
	default:
		return "", false
	}

	clearPositions(reflect.ValueOf(node), map[uintptr]bool{})
	restoreMeaning()

	var buf strings.Builder
	if err := printer.Fprint(&buf, token.NewFileSet(), node); err != nil {
		return "", false
	}
	return strings.Join(strings.Fields(buf.String()), " "), true
}

// posType is token.Pos, the one field kind the canonical form must forget.
var posType = reflect.TypeOf(token.Pos(0))

// clearPositions zeroes every source position in a tree before it is printed.
//
// go/printer lays a node out from the positions it carries, and a rewritten node
// carries none — which made it print a parameter list as if it spanned lines,
// trailing comma and all, so `func F(any,) bool` and `func F(any) bool` were two
// different canonical forms for the same signature. With every position dropped
// the printer has one layout to choose and both sides get it.
func clearPositions(v reflect.Value, seen map[uintptr]bool) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() || seen[v.Pointer()] {
			return
		}
		seen[v.Pointer()] = true
		clearPositions(v.Elem(), seen)
	case reflect.Interface:
		if v.IsNil() {
			return
		}
		clearPositions(v.Elem(), seen)
	case reflect.Struct:
		for i := range v.NumField() {
			f := v.Field(i)
			if f.Type() == posType {
				if f.CanSet() {
					f.SetInt(0)
				}
				continue
			}
			clearPositions(f, seen)
		}
	case reflect.Slice:
		for i := range v.Len() {
			clearPositions(v.Index(i), seen)
		}
	}
}

// singleSpec returns the one spec of a declaration, refusing a grouped
// declaration: a stored signature names one declaration, so a group means the
// text is not what this function was told it is.
func singleSpec(decl *ast.GenDecl) (ast.Spec, bool) {
	if len(decl.Specs) != 1 {
		return nil, false
	}
	return decl.Specs[0], true
}

// DiffersOnlyInSpelling reports whether two stored signatures differ, and
// differ only in spellings the language treats as identical (see
// CanonicalDeclaration).
//
// Identical text is NOT a spelling difference — there is no difference to
// report — and text that will not parse is never equivalent, so a signature
// this cannot read is left as the change it looks like rather than quietly
// discounted.
func DiffersOnlyInSpelling(a, b string) bool {
	if a == b {
		return false
	}
	canonA, okA := CanonicalDeclaration(a)
	if !okA {
		return false
	}
	canonB, okB := CanonicalDeclaration(b)
	if !okB {
		return false
	}
	return canonA == canonB
}

// normaliseFuncType rewrites a function type in place: type parameters keep
// their names (a constraint is named by it), parameters and results lose theirs.
func normaliseFuncType(ft *ast.FuncType) {
	if ft == nil {
		return
	}
	normaliseFieldList(ft.TypeParams, false)
	normaliseFieldList(ft.Params, true)
	normaliseFieldList(ft.Results, true)
}

// normaliseFieldList rewrites every field's type in place. With dropNames set
// the identifiers are removed, expanding a grouped field ("a, b int") into one
// field per name first: collapsing it to a single unnamed field would silently
// change the signature's arity.
func normaliseFieldList(fl *ast.FieldList, dropNames bool) {
	if fl == nil {
		return
	}
	out := make([]*ast.Field, 0, len(fl.List))
	for _, f := range fl.List {
		f.Doc, f.Comment = nil, nil
		f.Type = normaliseExpr(f.Type)
		if !dropNames {
			out = append(out, f)
			continue
		}
		if len(f.Names) <= 1 {
			f.Names = nil
			out = append(out, f)
			continue
		}
		for range f.Names {
			out = append(out, &ast.Field{Type: f.Type, Tag: f.Tag})
		}
	}
	fl.List = out
}

// normaliseExpr rewrites a type expression in place, returning the node that
// replaces it. An expression form this does not know is returned untouched, so
// an unrecognised construct compares as itself rather than being normalised into
// agreement with something else.
func normaliseExpr(e ast.Expr) ast.Expr {
	switch t := e.(type) {
	case *ast.Ident:
		// The predeclared aliases. byte and uint8, rune and int32 are the same
		// type, not merely convertible.
		switch t.Name {
		case "byte":
			return ast.NewIdent("uint8")
		case "rune":
			return ast.NewIdent("int32")
		}
	case *ast.InterfaceType:
		if t.Methods == nil || len(t.Methods.List) == 0 {
			return ast.NewIdent("any")
		}
		normaliseFieldList(t.Methods, false)
	case *ast.StarExpr:
		t.X = normaliseExpr(t.X)
	case *ast.ParenExpr:
		t.X = normaliseExpr(t.X)
	case *ast.ArrayType:
		t.Elt = normaliseExpr(t.Elt)
	case *ast.Ellipsis:
		t.Elt = normaliseExpr(t.Elt)
	case *ast.MapType:
		t.Key = normaliseExpr(t.Key)
		t.Value = normaliseExpr(t.Value)
	case *ast.ChanType:
		t.Value = normaliseExpr(t.Value)
	case *ast.StructType:
		normaliseFieldList(t.Fields, false)
	case *ast.FuncType:
		normaliseFuncType(t)
	case *ast.IndexExpr:
		t.X = normaliseExpr(t.X)
		t.Index = normaliseExpr(t.Index)
	case *ast.IndexListExpr:
		t.X = normaliseExpr(t.X)
		for i := range t.Indices {
			t.Indices[i] = normaliseExpr(t.Indices[i])
		}
	case *ast.BinaryExpr:
		// A constraint union: T | U.
		t.X = normaliseExpr(t.X)
		t.Y = normaliseExpr(t.Y)
	case *ast.UnaryExpr:
		// An approximation element: ~T.
		t.X = normaliseExpr(t.X)
	}
	return e
}

// ResultRegistryShape reports whether a function signature returns a
// registry-shaped value.
func (Reader) ResultRegistryShape(signature string, local map[string]string) (string, bool) {
	canonical := domain.NormalizeSignature(signature)
	if canonical == "" {
		return "", false
	}
	fset, file, ok := parseDecl("package p\n" + canonical)
	if !ok {
		return "", false
	}
	fn, ok := file.Decls[0].(*ast.FuncDecl)
	if !ok || fn.Type.Results == nil {
		return "", false
	}
	for _, r := range fn.Type.Results.List {
		if shape, ok := registryShapeExpr(r.Type, fset, local); ok {
			return shape, true
		}
	}
	return "", false
}

// RegistryShape reports whether a declared type text is registry-shaped.
func (r Reader) RegistryShape(typeText string, local map[string]string) (string, bool) {
	typeText = strings.TrimSpace(typeText)
	if typeText == "" {
		return "", false
	}
	fset, file, ok := parseDecl("package p\nvar _ " + typeText)
	if !ok {
		return "", false
	}
	decl, ok := file.Decls[0].(*ast.GenDecl)
	if !ok || len(decl.Specs) != 1 {
		return "", false
	}
	spec, ok := decl.Specs[0].(*ast.ValueSpec)
	if !ok || spec.Type == nil {
		return "", false
	}
	return registryShapeExpr(spec.Type, fset, local)
}

// registryShapeExpr reports whether a type expression is a string-keyed table of
// functions or dynamically typed values.
//
// Three forms count, and the third is a name: text/template and html/template
// both call theirs FuncMap, and the record carries the qualified name rather
// than the map type it stands for, because a stored signature holds no type
// information to unfold it with.
func registryShapeExpr(e ast.Expr, fset *token.FileSet, local map[string]string) (string, bool) {
	switch t := e.(type) {
	case *ast.MapType:
		key, ok := t.Key.(*ast.Ident)
		if !ok || key.Name != "string" {
			return "", false
		}
		if !dynamicValueType(t.Value) {
			return "", false
		}
		return exprText(e, fset), true
	case *ast.SelectorExpr:
		if t.Sel.Name == "FuncMap" {
			return exprText(e, fset), true
		}
	case *ast.Ident:
		under, ok := local[t.Name]
		if !ok || under == "" {
			return "", false
		}
		// One level of indirection: a local named type resolves to its
		// declaration text, which is checked as a type in its own right. A chain
		// of local aliases is not followed, so the answer stays a measurement of
		// what the record says rather than a search.
		if _, ok := (Reader{}).RegistryShape(under, nil); ok {
			return t.Name + " (" + under + ")", true
		}
	}
	return "", false
}

// dynamicValueType reports whether a map's value type is a function or a value
// whose concrete type is not fixed by the declaration.
func dynamicValueType(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.FuncType:
		return true
	case *ast.InterfaceType:
		return true
	case *ast.Ident:
		return t.Name == "any"
	}
	return false
}

// parseDecl parses a one-declaration source, reporting failure rather than an
// error: every caller treats unreadable text as "not this shape".
func parseDecl(src string) (*token.FileSet, *ast.File, bool) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "signature.go", src, parser.SkipObjectResolution)
	if err != nil || len(file.Decls) != 1 {
		return nil, nil, false
	}
	return fset, file, true
}

// exprText renders a type expression back to source text.
func exprText(e ast.Expr, fset *token.FileSet) string {
	var buf strings.Builder
	if err := printer.Fprint(&buf, fset, e); err != nil {
		return ""
	}
	return strings.Join(strings.Fields(buf.String()), " ")
}
