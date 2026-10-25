package tinycgo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/scanner"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/ast/astutil"
)

// cursor is one C declaration as clang reported it: a node of its JSON AST, or
// a macro from its -dM output. The zero value stands for a C type Go aliases.
type cursor struct {
	node  *astNode
	macro *macroDef
}

func (c cursor) isFunctionLikeMacro() bool { return c.macro != nil && c.macro.funcLike }

// hasCReferences reports whether any file selects a name from "C". A package
// that only imports "C" for its preamble needs no compiler and no declarations.
func hasCReferences(files []*ast.File) bool {
	found := false
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if found {
				return false
			}
			if s, ok := n.(*ast.SelectorExpr); ok {
				if x, ok := s.X.(*ast.Ident); ok && x.Name == "C" {
					found = true
				}
			}
			return true
		})
	}
	return found
}

// importsC reports whether f imports "C".
func importsC(f *ast.File) bool {
	for _, is := range f.Imports {
		if is.Path != nil && is.Path.Value == `"C"` {
			return true
		}
	}
	return false
}

// SPDX-SnippetBegin
// SPDX-SnippetCopyrightText: Copyright (c) 2018-2026 The TinyGo Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// SPDX-SnippetName: TinyGo cgo transform, target definitions and type sizes
// SPDX-SnippetComment: Ported from github.com/tinygo-org/tinygo@v0.42.0, cgo/cgo.go (Process, the alias tables, the generated prefix, getASTDeclName, getASTDeclNode, walker, renameFieldKeywords)

// cgoPackage holds the cgo state of one package.
type cgoPackage struct {
	generated       *ast.File
	packageName     string
	generatedPos    token.Pos
	errors          []error
	importPath      string
	fset            *token.FileSet
	definedGlobally map[string]ast.Node
	noescapingFuncs map[string]*noescapingFunc
	anonDecls       map[any]string
	cgoHeaders      []string
	sizes           cSizes
}

// cgoFile holds the state of one Go file with an `import "C"`.
type cgoFile struct {
	*cgoPackage
	file    *ast.File
	index   int
	defined map[string]ast.Node
	names   map[string]cursor
	decls   *fileDecls
	// enumProbe compiles the preamble again with probes for the spellings
	// given; it runs at most once per file, and only for a file whose Go code
	// reaches an enum type.
	enumProbe func(spellings []string) ([]int, []bool, error)
	enumTried bool
}

// Information about a #cgo noescape line in the source code.
type noescapingFunc struct {
	name string
	pos  token.Pos
	used bool
}

// cgoAliases are the C types that are the same type in Go.
var cgoAliases = map[string]string{
	"_Cgo_int8_t":    "int8",
	"_Cgo_int16_t":   "int16",
	"_Cgo_int32_t":   "int32",
	"_Cgo_int64_t":   "int64",
	"_Cgo_uint8_t":   "uint8",
	"_Cgo_uint16_t":  "uint16",
	"_Cgo_uint32_t":  "uint32",
	"_Cgo_uint64_t":  "uint64",
	"_Cgo_uintptr_t": "uintptr",
	"_Cgo_float":     "float32",
	"_Cgo_double":    "float64",
	"_Cgo__Bool":     "bool",
}

// builtinAliases exist only on the Go side, prefixed with "_Cgo_" there.
var builtinAliases = []string{
	"char",
	"schar",
	"uchar",
	"short",
	"ushort",
	"int",
	"uint",
	"long",
	"ulong",
	"longlong",
	"ulonglong",
}

// First part of the generated Go file.
const generatedGoFilePrefixBase = `
import "syscall"
import "unsafe"

var _ unsafe.Pointer

//go:linkname _Cgo_CString runtime.cgo_CString
func _Cgo_CString(string) *_Cgo_char

//go:linkname _Cgo_GoString runtime.cgo_GoString
func _Cgo_GoString(*_Cgo_char) string

//go:linkname _Cgo___GoStringN runtime.cgo_GoStringN
func _Cgo___GoStringN(*_Cgo_char, uintptr) string

func _Cgo_GoStringN(cstr *_Cgo_char, length _Cgo_int) string {
	return _Cgo___GoStringN(cstr, uintptr(length))
}

//go:linkname _Cgo___GoBytes runtime.cgo_GoBytes
func _Cgo___GoBytes(unsafe.Pointer, uintptr) []byte

func _Cgo_GoBytes(ptr unsafe.Pointer, length _Cgo_int) []byte {
	return _Cgo___GoBytes(ptr, uintptr(length))
}

//go:linkname _Cgo___CBytes runtime.cgo_CBytes
func _Cgo___CBytes([]byte) unsafe.Pointer

func _Cgo_CBytes(b []byte) unsafe.Pointer {
	return _Cgo___CBytes(b)
}

//go:linkname _Cgo___get_errno_num runtime.cgo_errno
func _Cgo___get_errno_num() uintptr
`

const generatedGoFilePrefixOther = generatedGoFilePrefixBase + `
func _Cgo___get_errno() error {
	return syscall.Errno(_Cgo___get_errno_num())
}
`

// Windows maps mingw-w64's errno values onto the syscall package's.
const generatedGoFilePrefixWindows = generatedGoFilePrefixBase + `
var _Cgo___errno_mapping = [...]syscall.Errno{
	1:  syscall.EPERM,
	2:  syscall.ENOENT,
	3:  syscall.ESRCH,
	4:  syscall.EINTR,
	5:  syscall.EIO,
	6:  syscall.ENXIO,
	7:  syscall.E2BIG,
	8:  syscall.ENOEXEC,
	9:  syscall.EBADF,
	10: syscall.ECHILD,
	11: syscall.EAGAIN,
	12: syscall.ENOMEM,
	13: syscall.EACCES,
	14: syscall.EFAULT,
	16: syscall.EBUSY,
	17: syscall.EEXIST,
	18: syscall.EXDEV,
	19: syscall.ENODEV,
	20: syscall.ENOTDIR,
	21: syscall.EISDIR,
	22: syscall.EINVAL,
	23: syscall.ENFILE,
	24: syscall.EMFILE,
	25: syscall.ENOTTY,
	27: syscall.EFBIG,
	28: syscall.ENOSPC,
	29: syscall.ESPIPE,
	30: syscall.EROFS,
	31: syscall.EMLINK,
	32: syscall.EPIPE,
	33: syscall.EDOM,
	34: syscall.ERANGE,
	36: syscall.EDEADLK,
	38: syscall.ENAMETOOLONG,
	39: syscall.ENOLCK,
	40: syscall.ENOSYS,
	41: syscall.ENOTEMPTY,
	42: syscall.EILSEQ,
}

func _Cgo___get_errno() error {
	num := _Cgo___get_errno_num()
	if num < uintptr(len(_Cgo___errno_mapping)) {
		if mapped := _Cgo___errno_mapping[num]; mapped != 0 {
			return mapped
		}
	}
	return syscall.Errno(num)
}
`

// newCgoPackage starts the generated file, named !cgo.go in the package
// directory as TinyGo names it, so a position in it renders under the root.
func newCgoPackage(files []*ast.File, dir, importPath, goos string, fset *token.FileSet) *cgoPackage {
	p := &cgoPackage{
		packageName:     files[0].Name.Name,
		importPath:      importPath,
		fset:            fset,
		definedGlobally: map[string]ast.Node{},
		noescapingFuncs: map[string]*noescapingFunc{},
		anonDecls:       map[any]string{},
	}
	goCode := "package " + files[0].Name.Name + "\n\n"
	if goos == "windows" {
		goCode += generatedGoFilePrefixWindows
	} else {
		goCode += generatedGoFilePrefixOther
	}
	generated, err := parser.ParseFile(fset, filepath.Join(dir, "!cgo.go"), goCode, parser.ParseComments)
	if err != nil {
		panic("unexpected error: " + err.Error())
	}
	generated.Comments = nil
	p.generated = generated
	p.generatedPos = generated.Package
	return p
}

// extractPreambles removes every single-spec `import "C"` and returns each
// file's preamble as one C fragment, led by a line directive naming the Go file.
func (p *cgoPackage) extractPreambles(files []*ast.File) {
	p.cgoHeaders = make([]string, len(files))
	for fi, f := range files {
		var cgoHeader strings.Builder
		for i := 0; i < len(f.Decls); i++ {
			genDecl, ok := f.Decls[i].(*ast.GenDecl)
			if !ok || len(genDecl.Specs) != 1 {
				continue
			}
			spec, ok := genDecl.Specs[0].(*ast.ImportSpec)
			if !ok {
				continue
			}
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil || path != "C" {
				continue
			}
			f.Decls = append(f.Decls[:i], f.Decls[i+1:]...)
			i--
			if genDecl.Doc == nil {
				continue
			}
			position := p.fset.Position(genDecl.Doc.Pos())
			var fragment strings.Builder
			fmt.Fprintf(&fragment, "# %d %#v\n", position.Line, position.Filename)
			for _, comment := range genDecl.Doc.List {
				c := p.parseCGoPreprocessorLines(comment.Text, comment.Slash)
				if c[1] == '/' {
					c = "  " + c[2:]
				} else {
					c = "  " + c[2:len(c)-2]
				}
				fragment.WriteString(c)
				fragment.WriteByte('\n')
			}
			cgoHeader.WriteString(fragment.String())
		}
		p.cgoHeaders[fi] = cgoHeader.String()
		dropImportSpecC(f)
	}
}

// dropImportSpecC keeps f.Imports in step with the declarations removed above.
func dropImportSpecC(f *ast.File) {
	kept := f.Imports[:0]
	for _, is := range f.Imports {
		if is.Path == nil || is.Path.Value != `"C"` || !removedFromDecls(f, is) {
			kept = append(kept, is)
		}
	}
	f.Imports = kept
}

func removedFromDecls(f *ast.File, is *ast.ImportSpec) bool {
	for _, d := range f.Decls {
		if g, ok := d.(*ast.GenDecl); ok {
			for _, s := range g.Specs {
				if s == is {
					return false
				}
			}
		}
	}
	return true
}

// parseCGoPreprocessorLines blanks the #cgo lines of a preamble. noescape and
// nocallback are read as TinyGo reads them and LDFLAGS only reach a linker;
// CFLAGS would change the declarations and are refused by name.
func (p *cgoPackage) parseCGoPreprocessorLines(text string, pos token.Pos) string {
	for {
		lineStart := strings.Index(text, "#cgo ")
		if lineStart < 0 {
			break
		}
		lineLen := strings.IndexByte(text[lineStart:], '\n')
		if lineLen < 0 {
			lineLen = len(text) - lineStart
		}
		lineEnd := lineStart + lineLen
		line := text[lineStart:lineEnd]
		text = text[:lineStart] + strings.Repeat(" ", len(line)) + text[lineEnd:]
		p.readCGoLine(line, text[:lineStart], pos)
	}
	return text
}

func (p *cgoPackage) readCGoLine(line, before string, pos token.Pos) {
	allFields := strings.Fields(line[4:])
	if len(allFields) == 0 {
		p.addErrorAfter(pos, before, "invalid #cgo line")
		return
	}
	switch allFields[0] {
	case "noescape":
		if len(allFields) != 2 {
			p.addErrorAfter(pos, before, "a #cgo noescape line names exactly one function")
			return
		}
		p.noescapingFuncs[allFields[1]] = &noescapingFunc{name: allFields[1], pos: pos}
		return
	case "nocallback":
		return
	}
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		p.addErrorAfter(pos, before, "missing colon in #cgo line")
		return
	}
	fields := strings.Fields(line[4:colon])
	switch {
	case len(fields) == 0:
		p.addErrorAfter(pos, before, "invalid #cgo line")
	case len(fields) > 1:
		p.addErrorAfter(pos, before, "not implemented: build constraints in #cgo line")
	case fields[0] == "LDFLAGS":
	case fields[0] == "CFLAGS":
		p.addErrorAfter(pos, before, "#cgo CFLAGS lines are not read by this analysis")
	default:
		p.addErrorAfter(pos, before, "invalid #cgo line: "+fields[0])
	}
}

func (p *cgoPackage) newCGoFile(file *ast.File, index int) *cgoFile {
	return &cgoFile{
		cgoPackage: p,
		file:       file,
		index:      index,
		defined:    make(map[string]ast.Node),
		names:      make(map[string]cursor),
	}
}

// getUnnamedDeclName names an anonymous struct, union or enum, in order of
// first use.
func (p *cgoPackage) getUnnamedDeclName(prefix string, itf any) string {
	if name, ok := p.anonDecls[itf]; ok {
		return name
	}
	name := prefix + strconv.Itoa(len(p.anonDecls))
	p.anonDecls[itf] = name
	return name
}

// getASTDeclName declares the given C declaration if it is not yet, and
// returns its Go name.
func (f *cgoFile) getASTDeclName(name string, found cursor, iscall bool) string {
	if alias := cgoAliases["_Cgo_"+name]; alias != "" {
		return alias
	}
	node := f.getASTDeclNode(name, found)
	if node, ok := node.(*ast.FuncDecl); ok {
		if !iscall {
			return node.Name.Name + "$funcaddr"
		}
		return node.Name.Name
	}
	return "_Cgo_" + name
}

// getASTDeclNode declares the given C declaration if it is not yet, and
// returns it. A declaration another file of the package made first must be
// the same declaration; the two are compared as printed Go.
func (f *cgoFile) getASTDeclNode(name string, found cursor) ast.Node {
	if node, ok := f.defined[name]; ok {
		return node
	}
	if node, ok := f.definedGlobally[name]; ok {
		f.defined[name] = nil
		newNode := f.createASTNode(name, found)
		if printedNode(node) != printedNode(newNode) {
			f.addError(getPos(node), name+" defined previously at "+f.fset.Position(getPos(newNode)).String()+" with a different type")
		}
		f.defined[name] = node
		return node
	}

	f.defined[name] = nil
	node := f.createASTNode(name, found)
	f.defined[name] = node
	switch node := node.(type) {
	case *ast.FuncDecl:
		if !strings.HasPrefix(node.Doc.List[0].Text, "//export _Cgo_static_") {
			f.definedGlobally[name] = node
		}
		f.generated.Decls = append(f.generated.Decls, node, &ast.GenDecl{
			Tok: token.VAR,
			Specs: []ast.Spec{
				&ast.ValueSpec{
					Names: []*ast.Ident{{NamePos: f.generatedPos, Name: node.Name.Name + "$funcaddr"}},
					Type: &ast.SelectorExpr{
						X:   &ast.Ident{NamePos: f.generatedPos, Name: "unsafe"},
						Sel: &ast.Ident{NamePos: f.generatedPos, Name: "Pointer"},
					},
				},
			},
		})
	case *ast.GenDecl:
		f.definedGlobally[name] = node
		f.generated.Decls = append(f.generated.Decls, node)
	case *ast.TypeSpec:
		f.definedGlobally[name] = node
		f.generated.Decls = append(f.generated.Decls, &ast.GenDecl{
			TokPos: f.generatedPos,
			Tok:    token.TYPE,
			Specs:  []ast.Spec{node},
		})
	}
	return node
}

// walker replaces every "C".<name> with the identifier TinyGo declares for
// it. A call assigned to two values also returns errno, as in TinyGo.
func (f *cgoFile) walker(cursor *astutil.Cursor, names map[string]cursor) bool {
	switch node := cursor.Node().(type) {
	case *ast.AssignStmt:
		f.walkErrnoAssign(node, names)
	case *ast.CallExpr:
		fun, ok := node.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		x, ok := fun.X.(*ast.Ident)
		if !ok {
			return true
		}
		if found, ok := names[fun.Sel.Name]; ok && x.Name == "C" {
			node.Fun = &ast.Ident{
				NamePos: x.NamePos,
				Name:    f.getASTDeclName(fun.Sel.Name, found, true),
			}
		}
	case *ast.SelectorExpr:
		x, ok := node.X.(*ast.Ident)
		if !ok {
			return true
		}
		if x.Name == "C" {
			name := "_Cgo_" + node.Sel.Name
			if found, ok := names[node.Sel.Name]; ok {
				name = f.getASTDeclName(node.Sel.Name, found, false)
			}
			cursor.Replace(&ast.Ident{
				NamePos: x.NamePos,
				Name:    name,
			})
		}
	}
	return true
}

// walkErrnoAssign rewrites `val, errno := C.f()` to also read errno.
func (f *cgoFile) walkErrnoAssign(node *ast.AssignStmt, names map[string]cursor) {
	if len(node.Lhs) != 2 || len(node.Rhs) != 1 {
		return
	}
	rhs, ok := node.Rhs[0].(*ast.CallExpr)
	if !ok {
		return
	}
	fun, ok := rhs.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	x, ok := fun.X.(*ast.Ident)
	if !ok {
		return
	}
	if found, ok := names[fun.Sel.Name]; ok && x.Name == "C" {
		rhs.Fun = &ast.Ident{
			NamePos: x.NamePos,
			Name:    f.getASTDeclName(fun.Sel.Name, found, true),
		}
		node.Rhs = append(node.Rhs, &ast.CallExpr{
			Fun: &ast.Ident{
				NamePos: node.Lhs[1].End(),
				Name:    "_Cgo___get_errno",
			},
		})
	}
}

// renameFieldKeywords renames a field named like a Go keyword with a "_"
// prefix, as cgo does.
func renameFieldKeywords(fieldList *ast.FieldList) {
	renameFieldName(fieldList, "type")
}

func renameFieldName(fieldList *ast.FieldList, name string) {
	var ident *ast.Ident
	for _, f := range fieldList.List {
		for _, n := range f.Names {
			if n.Name == name {
				ident = n
			}
		}
	}
	if ident == nil {
		return
	}
	renameFieldName(fieldList, "_"+name)
	ident.Name = "_" + ident.Name
}

// staticExportName is the symbol a static C function is given: unique per
// file, as TinyGo derives it.
func staticExportName(importPath, fileName, name string) string {
	path := importPath + "/" + filepath.Base(fileName)
	staticIDBuf := sha256.Sum256([]byte(path))
	return "_Cgo_static_" + hex.EncodeToString(staticIDBuf[:10]) + "_" + name
}

// unusedNoescapeErrors reports #cgo noescape lines naming a function no Go
// code calls, as upstream Go does.
func (p *cgoPackage) unusedNoescapeErrors() {
	var unused []*noescapingFunc
	for _, value := range p.noescapingFuncs {
		if !value.used {
			unused = append(unused, value)
		}
	}
	sort.SliceStable(unused, func(i, j int) bool { return unused[i].pos < unused[j].pos })
	for _, value := range unused {
		p.addError(value.pos, fmt.Sprintf("function %#v in #cgo noescape line is not used", value.name))
	}
}

func (p *cgoPackage) addError(pos token.Pos, msg string) {
	p.addErrorAt(p.fset.PositionFor(pos, true), msg)
}

func (p *cgoPackage) addErrorAfter(pos token.Pos, after, msg string) {
	position := p.fset.PositionFor(pos, true)
	lines := strings.Split(after, "\n")
	if len(lines) != 1 {
		position.Line += len(lines) - 1
		position.Column = len(lines[len(lines)-1]) + 1
	} else {
		position.Column += len(after)
	}
	p.addErrorAt(position, msg)
}

func (p *cgoPackage) addErrorAt(position token.Position, msg string) {
	p.errors = append(p.errors, scanner.Error{Pos: position, Msg: msg})
}

// getPos returns node.Pos(), or a closely related valid position.
func getPos(node ast.Node) token.Pos {
	pos := node.Pos()
	if pos.IsValid() {
		return pos
	}
	if decl, ok := node.(*ast.GenDecl); ok && len(decl.Specs) > 0 {
		return getPos(decl.Specs[0])
	}
	return token.NoPos
}

// SPDX-SnippetEnd

// printedNode renders a declaration without positions, the form two files'
// declarations of one C name are compared in.
func printedNode(n ast.Node) string {
	if n == nil {
		return ""
	}
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, token.NewFileSet(), n); err != nil {
		return "unprintable: " + err.Error()
	}
	return buf.String()
}
