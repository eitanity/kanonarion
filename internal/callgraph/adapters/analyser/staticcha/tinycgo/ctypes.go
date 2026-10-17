package tinycgo

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// cType is a C type as the JSON AST spells it, parsed.
type cType struct {
	kind cKind
	// name is the canonical builtin ("unsigned long"), the typedef name, or the
	// tag of a struct, union or enum.
	name string
	tag  string
	elem *cType
	n    int64
}

type cKind int

const (
	cBuiltin cKind = iota
	cVoid
	cTypedef
	cTagged
	cPointer
	cArray
	cFunction
)

// errUnsupportedType marks a C type outside the set the translation covers.
var errUnsupportedType = errors.New("a C type this analysis does not translate")

var cQualifiers = map[string]bool{"const": true, "volatile": true, "restrict": true, "__restrict": true}

// parseCType parses the qualType spellings clang writes: a base type with
// pointers and arrays, or a function type, or a pointer to one.
func parseCType(s string) (*cType, error) {
	s = stripTrailingAttributes(strings.TrimSpace(s))
	if strings.Contains(s, "(unnamed") || strings.Contains(s, "(anonymous") {
		return nil, fmt.Errorf("%w: %s", errUnsupportedType, s)
	}
	if strings.HasSuffix(s, ")") {
		return parseFunctionType(s)
	}
	var dims []int64
	for strings.HasSuffix(s, "]") {
		open := strings.LastIndex(s, "[")
		if open < 0 {
			return nil, fmt.Errorf("%w: %s", errUnsupportedType, s)
		}
		n, err := strconv.ParseInt(strings.TrimSpace(s[open+1:len(s)-1]), 0, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", errUnsupportedType, s)
		}
		dims = append([]int64{n}, dims...)
		s = strings.TrimSpace(s[:open])
	}
	t, err := parsePointerType(s)
	if err != nil {
		return nil, err
	}
	for i := len(dims) - 1; i >= 0; i-- {
		t = &cType{kind: cArray, n: dims[i], elem: t}
	}
	return t, nil
}

// parseFunctionType reads "R (params)" and "R (*)(params)".
func parseFunctionType(s string) (*cType, error) {
	open := matchingOpen(s)
	if open < 0 {
		return nil, fmt.Errorf("%w: %s", errUnsupportedType, s)
	}
	head := strings.TrimSpace(s[:open])
	switch {
	case strings.HasSuffix(head, "(*)") && !strings.Contains(strings.TrimSuffix(head, "(*)"), "("):
		return &cType{kind: cPointer, elem: &cType{kind: cFunction}}, nil
	case !strings.Contains(head, "("):
		return &cType{kind: cFunction}, nil
	}
	return nil, fmt.Errorf("%w: %s", errUnsupportedType, s)
}

// parsePointerType reads a base type followed by stars and qualifiers.
func parsePointerType(s string) (*cType, error) {
	var words []string
	stars := 0
	for _, tok := range strings.Fields(strings.ReplaceAll(s, "*", " * ")) {
		switch {
		case tok == "*":
			stars++
		case cQualifiers[tok]:
		case stars > 0 || strings.ContainsAny(tok, "()[],"):
			return nil, fmt.Errorf("%w: %s", errUnsupportedType, s)
		default:
			words = append(words, tok)
		}
	}
	t, err := parseBaseType(words, s)
	if err != nil {
		return nil, err
	}
	for range stars {
		t = &cType{kind: cPointer, elem: t}
	}
	return t, nil
}

func parseBaseType(words []string, spelled string) (*cType, error) {
	if len(words) == 0 {
		return nil, fmt.Errorf("%w: %s", errUnsupportedType, spelled)
	}
	switch words[0] {
	case "struct", "union", "enum":
		if len(words) != 2 {
			return nil, fmt.Errorf("%w: %s", errUnsupportedType, spelled)
		}
		return &cType{kind: cTagged, tag: words[0], name: words[1]}, nil
	}
	if name, ok := builtinName(words); ok {
		if name == "void" {
			return &cType{kind: cVoid}, nil
		}
		return &cType{kind: cBuiltin, name: name}, nil
	}
	if len(words) == 1 && !strings.HasPrefix(words[0], "__int") && !strings.HasPrefix(words[0], "_Float") && words[0] != "_Complex" {
		return &cType{kind: cTypedef, name: words[0]}, nil
	}
	return nil, fmt.Errorf("%w: %s", errUnsupportedType, spelled)
}

// builtinName canonicalises the spellings of C's fundamental types.
func builtinName(words []string) (string, bool) {
	n := map[string]int{}
	for _, w := range words {
		if w == "bool" {
			w = "_Bool"
		}
		if !cBuiltinWords[w] {
			return "", false
		}
		n[w]++
	}
	for _, single := range []string{"void", "_Bool", "float"} {
		if n[single] > 0 {
			return single, len(words) == 1
		}
	}
	if n["double"] > 0 {
		if n["long"] == 1 {
			return "long double", len(words) == 2
		}
		return "double", len(words) == 1
	}
	sign := ""
	if n["unsigned"] > 0 {
		sign = "unsigned "
	}
	if n["char"] > 0 {
		if n["signed"] > 0 {
			sign = "signed "
		}
		return sign + "char", true
	}
	return sign + integerBase(n["short"] > 0, n["long"]), true
}

var cBuiltinWords = map[string]bool{
	"unsigned": true, "signed": true, "char": true, "short": true, "int": true, "long": true,
	"float": true, "double": true, "void": true, "_Bool": true,
}

func integerBase(short bool, long int) string {
	switch {
	case short:
		return "short"
	case long == 1:
		return "long"
	case long == 2:
		return "long long"
	}
	return "int"
}

// matchingOpen is the index of the '(' that the final ')' of s closes.
func matchingOpen(s string) int {
	depth := 0
	for i := len(s) - 1; i >= 0; i-- {
		switch s[i] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// stripTrailingAttributes drops the __attribute__((...)) clang appends to a
// function type's spelling, such as noreturn.
func stripTrailingAttributes(s string) string {
	for {
		i := strings.LastIndex(s, " __attribute__((")
		if i < 0 || !strings.HasSuffix(s, "))") || matchingOpen(s) <= i {
			return s
		}
		s = strings.TrimSpace(s[:i])
	}
}

// functionResult is the result type spelled before a function type's
// parameter list.
func functionResult(fnType string) (string, error) {
	s := stripTrailingAttributes(strings.TrimSpace(fnType))
	open := matchingOpen(s)
	if open < 0 || !strings.HasSuffix(s, ")") {
		return "", fmt.Errorf("%w: %s", errUnsupportedType, fnType)
	}
	return strings.TrimSpace(s[:open]), nil
}

// SPDX-SnippetBegin
// SPDX-SnippetCopyrightText: Copyright (c) 2018-2026 The TinyGo Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// SPDX-SnippetName: TinyGo cgo transform, target definitions and type sizes
// SPDX-SnippetComment: Ported from github.com/tinygo-org/tinygo@v0.42.0, cgo/libclang.go (createASTNode, makeDecayingASTType, makeASTType, getIntegerType, makeASTRecordType), reading clang's JSON AST in place of libclang cursors

// createASTNode converts the C declaration under c to a Go declaration. A C
// construct outside the translated set is reported, naming the file, the C
// name and what clang spelled, and yields no declaration.
func (f *cgoFile) createASTNode(name string, c cursor) ast.Node {
	pos := f.generatedPos
	if c.macro != nil {
		return f.createMacroNode(name, c.macro)
	}
	if c.node == nil {
		f.unsupported(name, "a name clang did not declare")
		return nil
	}
	n := c.node
	switch n.Kind {
	case "FunctionDecl":
		return f.createFuncNode(name, n)
	case "RecordDecl":
		return f.createRecordNode(name, n)
	case "TypedefDecl":
		typ := f.typedefUnderlying(name, n)
		if typ == nil {
			return nil
		}
		return &ast.TypeSpec{
			Name:   &ast.Ident{NamePos: pos, Name: "_Cgo_" + name},
			Assign: pos,
			Type:   typ,
		}
	case "VarDecl":
		typ := f.makeASTType(name, n.Type)
		if typ == nil {
			return nil
		}
		return &ast.GenDecl{
			TokPos: pos,
			Tok:    token.VAR,
			Doc:    &ast.CommentGroup{List: []*ast.Comment{{Slash: pos - 1, Text: "//go:extern " + name}}},
			Specs: []ast.Spec{&ast.ValueSpec{
				Names: []*ast.Ident{{NamePos: pos, Name: "_Cgo_" + name}},
				Type:  typ,
			}},
		}
	case "EnumDecl":
		typ := f.enumUnderlying(name, n)
		if typ == nil {
			return nil
		}
		return &ast.TypeSpec{
			Name:   &ast.Ident{NamePos: pos, Name: "_Cgo_" + name},
			Assign: pos,
			Type:   typ,
		}
	case "EnumConstantDecl":
		return constDecl(pos, name, &ast.BasicLit{ValuePos: pos, Kind: token.INT, Value: rawValue(n.Value)})
	}
	f.unsupported(name, "a "+n.Kind)
	return nil
}

func (f *cgoFile) createFuncNode(name string, n *astNode) ast.Node {
	pos := f.generatedPos
	exportName, localName := name, name
	if n.StorageClass == "static" {
		fileName := f.fset.File(f.file.Pos()).Name()
		exportName = staticExportName(f.importPath, fileName, name)
		localName = name + "!" + filepath.Base(fileName)
	}
	decl := &ast.FuncDecl{
		Doc:  &ast.CommentGroup{List: []*ast.Comment{{Slash: pos - 1, Text: "//export " + exportName}}},
		Name: &ast.Ident{NamePos: pos, Name: "_Cgo_" + localName},
		Type: &ast.FuncType{Func: pos, Params: &ast.FieldList{Opening: pos, Closing: pos}},
	}
	var doc []string
	if n.Variadic {
		doc = append(doc, "//go:variadic")
	}
	if ne, ok := f.noescapingFuncs[name]; ok {
		doc = append(doc, "//go:noescape")
		ne.used = true
	}
	if len(doc) != 0 {
		decl.Doc.List = append(decl.Doc.List, &ast.Comment{Slash: pos - 1, Text: strings.Join(doc, "\n")})
	}
	i := 0
	for _, arg := range n.Inner {
		if arg.Kind != "ParmVarDecl" {
			continue
		}
		argName := arg.Name
		if argName == "" {
			argName = "$" + strconv.Itoa(i)
		}
		typ := f.makeDecayingASTType(name, arg.Type)
		if typ == nil {
			return nil
		}
		decl.Type.Params.List = append(decl.Type.Params.List, &ast.Field{
			Names: []*ast.Ident{{NamePos: pos, Name: argName}},
			Type:  typ,
		})
		i++
	}
	result, err := functionResult(spelling(n.Type))
	if err != nil {
		f.unsupported(name, spelling(n.Type))
		return nil
	}
	if result != "void" {
		typ := f.makeASTType(name, &qualType{QualType: result})
		if typ == nil {
			return nil
		}
		decl.Type.Results = &ast.FieldList{List: []*ast.Field{{Type: typ}}}
	}
	return decl
}

func (f *cgoFile) createRecordNode(name string, n *astNode) ast.Node {
	pos := f.generatedPos
	fieldList := &ast.FieldList{Opening: pos, Closing: pos}
	for _, field := range n.Inner {
		switch field.Kind {
		case "FieldDecl":
		case "RecordDecl", "EnumDecl", "FullComment":
			continue
		default:
			f.unsupported(name, n.TagUsed+" holding a "+field.Kind)
			return nil
		}
		if field.Name == "" {
			continue
		}
		if field.IsBitfield {
			f.unsupported(name, n.TagUsed+" with the bit field "+field.Name)
			return nil
		}
		typ := f.makeASTType(name, field.Type)
		if typ == nil {
			return nil
		}
		fieldList.List = append(fieldList.List, &ast.Field{
			Names: []*ast.Ident{{NamePos: pos, Name: field.Name}},
			Type:  typ,
		})
	}
	if n.TagUsed == "union" && len(fieldList.List) > 1 {
		f.unsupported(name, "union of "+strconv.Itoa(len(fieldList.List))+" fields, which needs accessors")
		return nil
	}
	renameFieldKeywords(fieldList)
	return &ast.TypeSpec{
		Name: &ast.Ident{NamePos: pos, Name: "_Cgo_" + name},
		Type: &ast.StructType{Struct: pos, Fields: fieldList},
	}
}

// typedefUnderlying is a typedef's type, naming an anonymous struct, union or
// enum it declares as TinyGo names one.
func (f *cgoFile) typedefUnderlying(name string, n *astNode) ast.Expr {
	if len(n.Inner) == 1 && n.Inner[0].OwnedTagDecl != nil && n.Inner[0].OwnedTagDecl.Name == "" {
		owned := f.decls.byID[n.Inner[0].OwnedTagDecl.ID]
		if owned == nil {
			f.unsupported(name, spelling(n.Type))
			return nil
		}
		prefix := "_Ctype_" + owned.TagUsed + "___"
		if owned.Kind == "EnumDecl" {
			prefix = "_Ctype_enum___"
		}
		anon := f.getUnnamedDeclName(prefix, owned.ID)
		return &ast.Ident{NamePos: f.generatedPos, Name: f.getASTDeclName(anon, cursor{node: owned}, false)}
	}
	return f.makeASTType(name, n.Type)
}

// enumUnderlying is the integer type clang chose for an enum.
func (f *cgoFile) enumUnderlying(name string, n *astNode) ast.Expr {
	if n.FixedUnderlyingType != nil {
		return f.makeASTType(name, n.FixedUnderlyingType)
	}
	f.probeEnums()
	ctype, ok := f.decls.enumTypes[n.ID]
	if !ok {
		f.unsupported(name, "an enum whose integer type clang did not report")
		return nil
	}
	return f.makeASTType(name, &qualType{QualType: ctype})
}

func (f *cgoFile) createMacroNode(name string, m *macroDef) ast.Node {
	expr, scannerError := parseConst(token.NoPos, f.fset, m.value, nil, token.NoPos, f)
	if scannerError != nil {
		f.addErrorAt(f.fileErrorPos(), fmt.Sprintf("C.%s: the macro %q is not a constant this analysis evaluates: %s", name, m.value, scannerError.Msg))
		return nil
	}
	return constDecl(f.generatedPos, name, expr)
}

func constDecl(pos token.Pos, name string, value ast.Expr) *ast.GenDecl {
	return &ast.GenDecl{
		Tok: token.CONST,
		Specs: []ast.Spec{&ast.ValueSpec{
			Names:  []*ast.Ident{{NamePos: pos, Name: "_Cgo_" + name}},
			Values: []ast.Expr{value},
		}},
	}
}

// makeDecayingASTType is makeASTType for a parameter: an array, or a typedef
// of one, decays to a pointer to its element.
func (f *cgoFile) makeDecayingASTType(name string, q *qualType) ast.Expr {
	t, err := parseCType(spelling(q))
	if err == nil && t.kind == cTypedef {
		if td := f.decls.typedefs[t.name]; td != nil {
			if under, uerr := parseCType(spelling(td.Type)); uerr == nil && under.kind == cArray {
				return f.ctypeToAST(name, &cType{kind: cPointer, elem: under.elem}, spelling(q))
			}
		}
	}
	if err == nil && t.kind == cArray {
		return f.ctypeToAST(name, &cType{kind: cPointer, elem: t.elem}, spelling(q))
	}
	return f.makeASTType(name, q)
}

// makeASTType converts a C type to Go. The spelling clang wrote is tried
// first and its desugared form second, for a builtin alias clang names but
// declares nowhere.
func (f *cgoFile) makeASTType(name string, q *qualType) ast.Expr {
	if q == nil {
		f.unsupported(name, "a declaration clang gave no type")
		return nil
	}
	t, err := parseCType(q.QualType)
	if err == nil && f.resolvable(t) {
		return f.ctypeToAST(name, t, q.QualType)
	}
	if q.Desugared != "" {
		if dt, derr := parseCType(q.Desugared); derr == nil && f.resolvable(dt) {
			return f.ctypeToAST(name, dt, q.Desugared)
		}
	}
	f.unsupported(name, spelling(q))
	return nil
}

// resolvable reports whether every named type in t is one this file declares.
func (f *cgoFile) resolvable(t *cType) bool {
	switch t.kind {
	case cPointer, cArray:
		if t.kind == cPointer && t.elem.kind == cVoid {
			return true
		}
		return f.resolvable(t.elem)
	case cTypedef:
		return f.decls.typedefs[t.name] != nil
	case cTagged:
		return t.tag != "enum" || f.decls.enums["enum_"+t.name] != nil
	case cBuiltin:
		_, ok := f.builtinIdent(t.name)
		return ok
	case cVoid:
		return false
	}
	return true
}

func (f *cgoFile) ctypeToAST(name string, t *cType, spelled string) ast.Expr {
	pos := f.generatedPos
	switch t.kind {
	case cPointer:
		if t.elem.kind == cVoid {
			return &ast.SelectorExpr{X: &ast.Ident{NamePos: pos, Name: "unsafe"}, Sel: &ast.Ident{NamePos: pos, Name: "Pointer"}}
		}
		return &ast.StarExpr{Star: pos, X: f.ctypeToAST(name, t.elem, spelled)}
	case cArray:
		return &ast.ArrayType{
			Lbrack: pos,
			Len:    &ast.BasicLit{ValuePos: pos, Kind: token.INT, Value: strconv.FormatInt(t.n, 10)},
			Elt:    f.ctypeToAST(name, t.elem, spelled),
		}
	case cFunction:
		return &ast.ArrayType{Lbrack: pos, Len: &ast.BasicLit{ValuePos: pos, Kind: token.INT, Value: "0"}, Elt: &ast.Ident{NamePos: pos, Name: "byte"}}
	case cTypedef:
		return &ast.Ident{NamePos: pos, Name: f.getASTDeclName(t.name, cursor{node: f.decls.typedefs[t.name]}, false)}
	case cTagged:
		key := t.tag + "_" + t.name
		var c cursor
		switch {
		case t.tag == "enum":
			c = cursor{node: f.decls.enums[key]}
		case f.decls.records[key] != nil:
			c = cursor{node: f.decls.records[key]}
		default:
			// Named and never defined, as a pointer's target may be: an
			// incomplete type, which TinyGo translates as an empty struct.
			c = cursor{node: &astNode{Kind: "RecordDecl", TagUsed: t.tag, Name: t.name}}
		}
		return &ast.Ident{NamePos: pos, Name: f.getASTDeclName(key, c, false)}
	}
	ident, _ := f.builtinIdent(t.name)
	return &ast.Ident{NamePos: pos, Name: ident}
}

// builtinIdent is the Go name of a C fundamental type.
func (f *cgoFile) builtinIdent(name string) (string, bool) {
	switch name {
	case "char":
		return "_Cgo_char", true
	case "signed char":
		return "_Cgo_schar", true
	case "unsigned char":
		return "_Cgo_uchar", true
	case "short":
		return "_Cgo_short", true
	case "unsigned short":
		return "_Cgo_ushort", true
	case "int":
		return "_Cgo_int", true
	case "unsigned int":
		return "_Cgo_uint", true
	case "long":
		return "_Cgo_long", true
	case "unsigned long":
		return "_Cgo_ulong", true
	case "long long":
		return "_Cgo_longlong", true
	case "unsigned long long":
		return "_Cgo_ulonglong", true
	case "_Bool":
		return "bool", true
	}
	size := map[string]int{"float": f.sizes.float, "double": f.sizes.double, "long double": f.sizes.longDouble}[name]
	switch size {
	case 4:
		return "float32", true
	case 8:
		return "float64", true
	}
	return "", false
}

// builtinTypeDecl declares _Cgo_char and its siblings with the Go integer of
// the same size and signedness, as getIntegerType does.
func (p *cgoPackage) builtinTypeDecl() *ast.GenDecl {
	gen := &ast.GenDecl{TokPos: p.generatedPos, Tok: token.TYPE}
	sizes := map[string]int{
		"char": 1, "schar": 1, "uchar": 1, "short": p.sizes.short, "ushort": p.sizes.short,
		"int": p.sizes.int, "uint": p.sizes.int, "long": p.sizes.long, "ulong": p.sizes.long,
		"longlong": p.sizes.longLong, "ulonglong": p.sizes.longLong,
	}
	for _, name := range builtinAliases {
		signed := name == "schar" || name == "short" || name == "int" || name == "long" || name == "longlong"
		if name == "char" {
			signed = !p.sizes.charUnsigned
		}
		goName := "int"
		if bits := sizes[name] * 8; bits == 8 || bits == 16 || bits == 32 || bits == 64 {
			goName = "int" + strconv.Itoa(bits)
			if !signed {
				goName = "u" + goName
			}
		} else {
			p.addError(p.generatedPos, "internal error: did not find Go type for C type _Cgo_"+name)
		}
		gen.Specs = append(gen.Specs, &ast.TypeSpec{
			Name: &ast.Ident{NamePos: p.generatedPos, Name: "_Cgo_" + name},
			Type: &ast.Ident{NamePos: p.generatedPos, Name: goName},
		})
	}
	return gen
}

// SPDX-SnippetEnd

// unsupported reports a C declaration outside the translated set, naming the
// Go file, the C name and the C type as clang spelled it.
func (f *cgoFile) unsupported(name, what string) {
	f.addErrorAt(f.fileErrorPos(), fmt.Sprintf("C.%s: %s is a C type this analysis does not translate", name, what))
}

// fileErrorPos is the position errors about this file's declarations carry:
// the file itself, since the declarations have no Go position of their own.
func (f *cgoFile) fileErrorPos() token.Position {
	return token.Position{Filename: f.fset.File(f.file.Pos()).Name()}
}

func spelling(q *qualType) string {
	if q == nil {
		return ""
	}
	return q.QualType
}

// probeEnums fills the integer type of every enum this file's translation
// unit declares, the first time one is needed.
func (f *cgoFile) probeEnums() {
	if f.enumTried || f.enumProbe == nil {
		return
	}
	f.enumTried = true
	var ids, spellings []string
	for _, key := range slices.Sorted(maps.Keys(f.decls.enums)) {
		ids, spellings = append(ids, f.decls.enums[key].ID), append(spellings, "enum "+strings.TrimPrefix(key, "enum_"))
	}
	for _, name := range slices.Sorted(maps.Keys(f.decls.typedefs)) {
		td := f.decls.typedefs[name]
		if len(td.Inner) == 1 && td.Inner[0].OwnedTagDecl != nil && td.Inner[0].OwnedTagDecl.Name == "" &&
			td.Inner[0].OwnedTagDecl.Kind == "EnumDecl" {
			ids, spellings = append(ids, td.Inner[0].OwnedTagDecl.ID), append(spellings, name)
		}
	}
	if len(ids) == 0 {
		return
	}
	sizes, signed, err := f.enumProbe(spellings)
	if err != nil {
		f.addErrorAt(f.fileErrorPos(), "reading the integer types of the preamble's enums: "+err.Error())
		return
	}
	for i, id := range ids {
		if ctype, ok := f.sizes.enumIntegerType(sizes[i], signed[i]); ok {
			f.decls.enumTypes[id] = ctype
		}
	}
}
