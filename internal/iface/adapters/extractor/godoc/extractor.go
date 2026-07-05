package godoc

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/doc"
	"go/format"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"path"
	"strings"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/iface/domain"
)

// Extractor implements ports.InterfaceExtractor using go/parser and go/doc.
type Extractor struct {
	pipelineVersion string
	clock           interface{ Now() time.Time }
}

// New constructs an Extractor.
func New(pipelineVersion string, clock interface{ Now() time.Time }) *Extractor {
	return &Extractor{pipelineVersion: pipelineVersion, clock: clock}
}

// Extract walks sourceTree, parses every non-test.go file per package
// directory, and produces an InterfaceRecord.
func (e *Extractor) Extract(ctx context.Context, sourceTree fs.FS, coord fetchdomain.ModuleCoordinate) (domain.InterfaceRecord, error) {
	dirs, err := collectPackageDirs(sourceTree)
	if err != nil {
		return domain.InterfaceRecord{}, fmt.Errorf("collecting package directories: %w", err)
	}

	var pkgs []domain.PackageInterface
	anyPartial := false

	for _, dir := range dirs {
		if ctx.Err() != nil {
			r := domain.InterfaceRecord{
				SchemaVersion:   domain.InterfaceSchemaVersion,
				Ecosystem:       fetchdomain.EcosystemGo,
				Coordinate:      coord,
				Packages:        pkgs,
				OverallStatus:   domain.InterfaceStatusCancelled,
				ExtractedAt:     e.clock.Now().UTC(),
				PipelineVersion: e.pipelineVersion,
			}
			r.Sort()
			return r, nil //nolint:nilerr // intentional: context cancellation is reported via OverallStatus, not error
		}

		pkg, err := parsePackageDir(sourceTree, dir, coord)
		if err != nil {
			// A directory with no parseable Go files is skipped silently.
			continue
		}

		if len(pkg.ParseFailures) > 0 {
			anyPartial = true
		}
		pkgs = append(pkgs, pkg)
	}

	status := domain.InterfaceStatusExtracted
	if anyPartial {
		status = domain.InterfaceStatusPartial
	}

	r := domain.InterfaceRecord{
		SchemaVersion:   domain.InterfaceSchemaVersion,
		Ecosystem:       fetchdomain.EcosystemGo,
		Coordinate:      coord,
		Packages:        pkgs,
		OverallStatus:   status,
		ExtractedAt:     e.clock.Now().UTC(),
		PipelineVersion: e.pipelineVersion,
	}
	r.Sort()
	return r, nil
}

// collectPackageDirs walks sourceTree and returns every directory that
// contains at least one non-test.go file, excluding vendor/ subtrees.
func collectPackageDirs(fsys fs.FS) ([]string, error) {
	seen := map[string]bool{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Skip vendor directories entirely.
		if d.IsDir() && (d.Name() == "vendor" || strings.Contains("/"+p+"/", "/vendor/")) {
			return fs.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			dir := path.Dir(p)
			seen[dir] = true
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking source tree: %w", err)
	}
	dirs := make([]string, 0, len(seen))
	for d := range seen {
		dirs = append(dirs, d)
	}
	return dirs, nil
}

// packageImportPath returns the full Go import path for a directory within a
// module zip. dir is "." for the root package and a relative path (e.g.
// "modfile") for sub-packages.
func packageImportPath(modulePath, dir string) string {
	if dir == "." {
		return modulePath
	}
	return modulePath + "/" + dir
}

// parsePackageDir parses all non-test.go files in dir within fsys and
// returns a PackageInterface.
func parsePackageDir(fsys fs.FS, dir string, coord fetchdomain.ModuleCoordinate) (domain.PackageInterface, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return domain.PackageInterface{}, fmt.Errorf("reading dir %s: %w", dir, err)
	}

	fset := token.NewFileSet()
	var parsed []*ast.File
	var failures []domain.ParseFailure
	generatedFiles := map[string]bool{}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		filePath := path.Join(dir, name)
		data, rerr := fs.ReadFile(fsys, filePath)
		if rerr != nil {
			failures = append(failures, domain.ParseFailure{File: filePath, Error: rerr.Error()})
			continue
		}

		if isGeneratedFile(data) {
			generatedFiles[filePath] = true
		}

		f, perr := parser.ParseFile(fset, filePath, data, parser.ParseComments)
		if perr != nil {
			failures = append(failures, domain.ParseFailure{File: filePath, Error: perr.Error()})
			continue
		}
		parsed = append(parsed, f)
	}

	importPath := packageImportPath(coord.Path, dir)

	if len(parsed) == 0 {
		if len(failures) > 0 {
			// Return a partial package with just the failures recorded.
			return domain.PackageInterface{
				ImportPath:    importPath,
				ParseFailures: failures,
			}, nil
		}
		return domain.PackageInterface{}, fmt.Errorf("no parseable Go files in %s", dir)
	}

	// Use go/doc to build a structured view of the package's exported API.
	// Pass the full import path so go/doc resolves cross-package references correctly.
	dpkg, err := doc.NewFromFiles(fset, parsed, importPath, doc.PreserveAST)
	if err != nil {
		return domain.PackageInterface{}, fmt.Errorf("go/doc for %s: %w", importPath, err)
	}

	pi := domain.PackageInterface{
		ImportPath:    importPath,
		Name:          dpkg.Name,
		Doc:           strings.TrimSpace(dpkg.Doc),
		ParseFailures: failures,
		IsInternal:    isInternalPath(importPath),
		IsMain:        dpkg.Name == "main",
	}

	pi.Types = extractTypes(fset, dpkg.Types, generatedFiles)
	// go/doc promotes constructor functions (e.g. New *T) to be associated
	// with the returned type. We collect them from each type's Funcs list so
	// they appear in the package-level Funcs as well.
	pi.Funcs = extractFuncs(fset, dpkg.Funcs, generatedFiles)
	for _, t := range dpkg.Types {
		pi.Funcs = append(pi.Funcs, extractFuncs(fset, t.Funcs, generatedFiles)...)
	}
	pi.Consts = extractValues(fset, dpkg.Consts, generatedFiles)
	pi.Vars = extractValues(fset, dpkg.Vars, generatedFiles)

	return pi, nil
}

func extractTypes(fset *token.FileSet, types []*doc.Type, generated map[string]bool) []domain.TypeDecl {
	out := make([]domain.TypeDecl, 0, len(types))
	for _, t := range types {
		if len(t.Decl.Specs) == 0 {
			continue
		}
		spec, ok := t.Decl.Specs[0].(*ast.TypeSpec)
		if !ok {
			continue
		}

		pos := fset.Position(t.Decl.Pos())
		td := domain.TypeDecl{
			Name: t.Name,
			Doc:  strings.TrimSpace(t.Doc),
			// go/printer emits the doc-comment block verbatim; NormalizeSignature drops it.
			Signature:   domain.NormalizeSignature(formatNode(fset, t.Decl)),
			Position:    domain.SourcePosition{File: pos.Filename, Line: pos.Line},
			Kind:        classifyTypeSpec(spec),
			IsGenerated: generated[pos.Filename],
		}

		td.TypeParams = extractTypeParams(spec)
		td.EmbeddedTypes = extractEmbedded(spec)
		td.Fields = extractFields(fset, spec, generated[pos.Filename])
		td.Methods = extractMethods(fset, t.Methods, t.Funcs, generated)

		out = append(out, td)
	}
	return out
}

func extractMethods(fset *token.FileSet, methods []*doc.Func, _ []*doc.Func, generated map[string]bool) []domain.MethodDecl {
	out := make([]domain.MethodDecl, 0, len(methods))
	for _, m := range methods {
		if m.Decl == nil {
			continue
		}
		pos := fset.Position(m.Decl.Pos())
		md := domain.MethodDecl{
			Name: m.Name,
			Doc:  strings.TrimSpace(m.Doc),
			// go/printer emits the doc-comment block verbatim; NormalizeSignature drops it.
			Signature:   domain.NormalizeSignature(formatFuncSignature(fset, m.Decl)),
			Position:    domain.SourcePosition{File: pos.Filename, Line: pos.Line},
			PtrReceiver: isPtrReceiver(m.Decl),
		}
		_ = generated // IsGenerated not tracked on methods; inherited from type
		out = append(out, md)
	}
	return out
}

func extractFuncs(fset *token.FileSet, funcs []*doc.Func, generated map[string]bool) []domain.FuncDecl {
	out := make([]domain.FuncDecl, 0, len(funcs))
	for _, f := range funcs {
		if f.Decl == nil {
			continue
		}
		pos := fset.Position(f.Decl.Pos())
		fd := domain.FuncDecl{
			Name: f.Name,
			Doc:  strings.TrimSpace(f.Doc),
			// go/printer emits the doc-comment block verbatim; NormalizeSignature drops it.
			Signature:   domain.NormalizeSignature(formatFuncSignature(fset, f.Decl)),
			Position:    domain.SourcePosition{File: pos.Filename, Line: pos.Line},
			IsGenerated: generated[pos.Filename],
		}
		if f.Decl.Type != nil && f.Decl.Type.TypeParams != nil {
			fd.TypeParams = fieldListToTypeParams(f.Decl.Type.TypeParams)
		}
		out = append(out, fd)
	}
	return out
}

func extractValues(fset *token.FileSet, groups []*doc.Value, generated map[string]bool) []domain.ValueDecl {
	var out []domain.ValueDecl
	for _, g := range groups {
		if g.Decl == nil {
			continue
		}
		pos := fset.Position(g.Decl.Pos())
		isGen := generated[pos.Filename]
		for _, spec := range g.Decl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			typeStr := ""
			if vs.Type != nil {
				typeStr = formatNode(fset, vs.Type)
			}
			for _, ident := range vs.Names {
				if !ident.IsExported() {
					continue
				}
				ipos := fset.Position(ident.Pos())
				out = append(out, domain.ValueDecl{
					Name:        ident.Name,
					Type:        typeStr,
					Doc:         strings.TrimSpace(vs.Comment.Text()),
					Position:    domain.SourcePosition{File: ipos.Filename, Line: ipos.Line},
					IsGenerated: isGen,
				})
			}
		}
	}
	return out
}

// -- helpers --

func classifyTypeSpec(spec *ast.TypeSpec) domain.TypeKind {
	if spec.Assign.IsValid() {
		return domain.TypeKindAlias
	}
	if spec.TypeParams != nil && len(spec.TypeParams.List) > 0 {
		return domain.TypeKindGeneric
	}
	switch spec.Type.(type) {
	case *ast.StructType:
		return domain.TypeKindStruct
	case *ast.InterfaceType:
		return domain.TypeKindInterface
	default:
		return domain.TypeKindDefined
	}
}

func extractTypeParams(spec *ast.TypeSpec) []domain.TypeParam {
	if spec.TypeParams == nil {
		return nil
	}
	return fieldListToTypeParams(spec.TypeParams)
}

func fieldListToTypeParams(fl *ast.FieldList) []domain.TypeParam {
	if fl == nil {
		return nil
	}
	var out []domain.TypeParam
	for _, field := range fl.List {
		constraint := ""
		if field.Type != nil {
			var buf bytes.Buffer
			if err := format.Node(&buf, token.NewFileSet(), field.Type); err == nil {
				constraint = buf.String()
			}
		}
		for _, name := range field.Names {
			out = append(out, domain.TypeParam{Name: name.Name, Constraint: constraint})
		}
	}
	return out
}

func extractEmbedded(spec *ast.TypeSpec) []string {
	iface, ok := spec.Type.(*ast.InterfaceType)
	if !ok || iface.Methods == nil {
		return nil
	}
	var names []string
	for _, field := range iface.Methods.List {
		if len(field.Names) == 0 {
			// embedded interface
			names = append(names, typeExprString(field.Type))
		}
	}
	return names
}

func extractFields(fset *token.FileSet, spec *ast.TypeSpec, isGenerated bool) []domain.FieldDecl {
	st, ok := spec.Type.(*ast.StructType)
	if !ok || st.Fields == nil {
		return nil
	}
	var out []domain.FieldDecl
	for _, field := range st.Fields.List {
		typeStr := formatNode(fset, field.Type)
		tag := ""
		if field.Tag != nil {
			tag = field.Tag.Value
		}
		doc := strings.TrimSpace(field.Doc.Text())
		if doc == "" {
			doc = strings.TrimSpace(field.Comment.Text())
		}

		if len(field.Names) == 0 {
			// embedded field
			pos := fset.Position(field.Pos())
			name := typeExprString(field.Type)
			if ast.IsExported(strings.TrimPrefix(strings.TrimPrefix(name, "*"), "~")) {
				out = append(out, domain.FieldDecl{
					Name:     name,
					Type:     typeStr,
					Tag:      tag,
					Doc:      doc,
					Embedded: true,
					Position: domain.SourcePosition{File: pos.Filename, Line: pos.Line},
				})
			}
			continue
		}

		for _, ident := range field.Names {
			if !ident.IsExported() {
				continue
			}
			pos := fset.Position(ident.Pos())
			out = append(out, domain.FieldDecl{
				Name:        ident.Name,
				Type:        typeStr,
				Tag:         tag,
				Doc:         doc,
				Embedded:    false,
				Position:    domain.SourcePosition{File: pos.Filename, Line: pos.Line},
				IsGenerated: isGenerated,
			})
		}
	}
	return out
}

func isPtrReceiver(decl *ast.FuncDecl) bool {
	if decl.Recv == nil || len(decl.Recv.List) == 0 {
		return false
	}
	_, ok := decl.Recv.List[0].Type.(*ast.StarExpr)
	return ok
}

func formatNode(fset *token.FileSet, node ast.Node) string {
	var buf bytes.Buffer
	cfg := printer.Config{Mode: printer.UseSpaces | printer.TabIndent, Tabwidth: 8}
	if err := cfg.Fprint(&buf, fset, node); err != nil {
		return ""
	}
	return buf.String()
}

// formatFuncSignature renders a FuncDecl without its body.
func formatFuncSignature(fset *token.FileSet, decl *ast.FuncDecl) string {
	// Clone with nil body so we only print the signature.
	clone := *decl
	clone.Body = nil
	var buf bytes.Buffer
	cfg := printer.Config{Mode: printer.UseSpaces | printer.TabIndent, Tabwidth: 8}
	if err := cfg.Fprint(&buf, fset, &clone); err != nil {
		return ""
	}
	return strings.TrimSpace(buf.String())
}

func typeExprString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return typeExprString(e.X) + "." + e.Sel.Name
	case *ast.StarExpr:
		return "*" + typeExprString(e.X)
	default:
		var buf bytes.Buffer
		if err := format.Node(&buf, token.NewFileSet(), expr); err == nil {
			return buf.String()
		}
		return ""
	}
}

func isInternalPath(importPath string) bool {
	return strings.Contains("/"+importPath+"/", "/internal/")
}

// isGeneratedFile returns true if the file content contains the canonical
// "Code generated … DO NOT EDIT." marker in its first 512 bytes.
func isGeneratedFile(data []byte) bool {
	check := data
	if len(check) > 512 {
		check = check[:512]
	}
	return bytes.Contains(check, []byte("DO NOT EDIT"))
}
