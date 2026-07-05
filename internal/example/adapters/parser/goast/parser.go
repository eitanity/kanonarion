package goast

import (
	"archive/zip"
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/example/domain"
	"github.com/eitanity/kanonarion/internal/example/ports"
)

// Parser implements ports.ExampleParser.
type Parser struct{}

var _ ports.ExampleParser = (*Parser)(nil)

// New returns a goast-backed ExampleParser.
func New() *Parser { return &Parser{} }

// Parse constructs a zip reader over zipData and scans all _test.go entries
// under modulePrefix for Example* functions.
func (Parser) Parse(zipData []byte, modulePrefix string) ([]domain.ExampleEntry, []domain.ParseFailure, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, nil, fmt.Errorf("parsing zip: %w", err)
	}
	examples, failures := parseTestFiles(zr, modulePrefix)
	return examples, failures, nil
}

// parseTestFiles scans all _test.go entries in the zip for the given module
// prefix and returns the examples found and any files that failed to parse.
func parseTestFiles(zr *zip.Reader, modulePrefix string) ([]domain.ExampleEntry, []domain.ParseFailure) {
	var examples []domain.ExampleEntry
	var failures []domain.ParseFailure

	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, modulePrefix) {
			continue
		}
		if f.FileInfo().IsDir() {
			continue
		}
		relPath := strings.TrimPrefix(f.Name, modulePrefix)
		baseName := path.Base(relPath)
		if !strings.HasSuffix(baseName, "_test.go") {
			continue
		}

		fileExamples, err := parseOneTestFile(f, relPath)
		if err != nil {
			failures = append(failures, domain.ParseFailure{
				File:  relPath,
				Error: err.Error(),
			})
			continue
		}
		examples = append(examples, fileExamples...)
	}

	return examples, failures
}

// parseOneTestFile reads and parses a single _test.go zip entry, returning
// all Example* functions found.
func parseOneTestFile(f *zip.File, relPath string) (_ []domain.ExampleEntry, retErr error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("opening zip entry %s: %w", relPath, err)
	}
	defer func() {
		if cerr := rc.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("closing zip entry %s: %w", relPath, cerr)
		}
	}()

	src, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("reading zip entry %s: %w", relPath, err)
	}

	fset := token.NewFileSet()
	astFile, err := parser.ParseFile(fset, relPath, src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", relPath, err)
	}

	// Use "dir:pkgname" rather than the bare AST package name. Two sources of
	// ambiguity exist:
	//   1. Sibling sub-packages share a name (e.g. apiv1/ and apiv1beta1/ both
	//      declare "package aiplatform") — dir fixes this.
	//   2. A directory can contain both an internal ("package foo") and external
	//      ("package foo_test") test package, both legitimately defining the same
	//      Example function — pkgName disambiguates within a directory.
	pkgKey := path.Dir(relPath) + ":" + astFile.Name.Name
	var entries []domain.ExampleEntry

	for _, decl := range astFile.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Body == nil {
			continue
		}
		if !strings.HasPrefix(fn.Name.Name, "Example") {
			continue
		}

		entry := extractExampleEntry(fset, astFile, src, fn, pkgKey, relPath)
		entries = append(entries, entry)
	}

	return entries, nil
}

func extractExampleEntry(
	fset *token.FileSet,
	astFile *ast.File,
	src []byte,
	fn *ast.FuncDecl,
	pkgKey, relPath string,
) domain.ExampleEntry {
	symbol, sub := domain.DeriveAssociatedSymbol(fn.Name.Name)
	body := extractBody(fset, src, fn)
	output, validates := extractOutput(astFile, fn)
	imports := extractUsedImports(astFile, fn)
	doc := extractDoc(fn)
	pos := fset.Position(fn.Pos())

	return domain.ExampleEntry{
		Name:             fn.Name.Name,
		Package:          pkgKey,
		AssociatedSymbol: symbol,
		SubExample:       sub,
		Body:             body,
		Output:           output,
		Imports:          imports,
		Doc:              doc,
		Position:         domain.SourcePosition{File: relPath, Line: pos.Line},
		Validates:        validates,
	}
}

// extractBody returns the canonical source of the function body by slicing
// the raw source between { and } and reformatting via go/format.Source.
// Falls back to the raw bytes if formatting fails.
func extractBody(fset *token.FileSet, src []byte, fn *ast.FuncDecl) string {
	tf := fset.File(fn.Body.Lbrace)
	start := tf.Offset(fn.Body.Lbrace)
	end := tf.Offset(fn.Body.Rbrace) + 1
	if start < 0 || end > len(src) || start >= end {
		return ""
	}
	rawBody := src[start:end]

	// Wrap in a minimal Go file so go/format can parse and reformat.
	wrapped := make([]byte, 0, len("package _\nfunc _() ")+len(rawBody)+1)
	wrapped = append(wrapped, "package _\nfunc _() "...)
	wrapped = append(wrapped, rawBody...)
	wrapped = append(wrapped, '\n')

	formatted, err := format.Source(wrapped)
	if err != nil {
		return string(rawBody)
	}

	// Extract the body from the formatted output (everything from the first '{').
	s := string(formatted)
	idx := strings.Index(s, "{")
	if idx < 0 {
		return string(rawBody)
	}
	return strings.TrimRight(s[idx:], "\n")
}

// extractOutput looks for // Output: or // Unordered output: comment blocks
// within the function body. Returns the output text and whether the example
// has a validated output comment.
func extractOutput(astFile *ast.File, fn *ast.FuncDecl) (output string, validates bool) {
	var bodyComments []*ast.CommentGroup
	for _, cg := range astFile.Comments {
		if cg.Pos() > fn.Body.Lbrace && cg.Pos() < fn.Body.Rbrace {
			bodyComments = append(bodyComments, cg)
		}
	}
	if len(bodyComments) == 0 {
		return "", false
	}

	last := bodyComments[len(bodyComments)-1]
	if len(last.List) == 0 {
		return "", false
	}

	firstText := last.List[0].Text
	var marker string
	switch {
	case strings.HasPrefix(firstText, "// Output:"):
		marker = "// Output:"
	case strings.HasPrefix(firstText, "// Unordered output:"):
		marker = "// Unordered output:"
	default:
		return "", false
	}

	var lines []string

	// Capture any inline text on the marker line itself (e.g. "// Output: foo").
	inline := strings.TrimSpace(strings.TrimPrefix(firstText, marker))
	if inline != "" {
		lines = append(lines, inline)
	}

	// Subsequent comment lines are output lines.
	for _, c := range last.List[1:] {
		text := c.Text
		if strings.HasPrefix(text, "// ") {
			lines = append(lines, strings.TrimPrefix(text, "// "))
		} else {
			lines = append(lines, strings.TrimPrefix(text, "//"))
		}
	}

	return strings.Join(lines, "\n"), true
}

// extractUsedImports filters the file's import list to those actually
// referenced in fn's body. Returns a sorted slice of import paths.
func extractUsedImports(astFile *ast.File, fn *ast.FuncDecl) []string {
	used := make(map[string]bool)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		used[id.Name] = true
		return true
	})

	var imports []string
	for _, spec := range astFile.Imports {
		importPath := strings.Trim(spec.Path.Value, `"`)
		var localName string
		if spec.Name != nil {
			localName = spec.Name.Name
		} else {
			localName = path.Base(importPath)
		}
		// Skip blank imports and dot imports.
		if localName == "_" || localName == "." {
			continue
		}
		if used[localName] {
			imports = append(imports, importPath)
		}
	}

	sort.Strings(imports)
	return imports
}

// extractDoc returns the doc comment text for the function, or empty string.
func extractDoc(fn *ast.FuncDecl) string {
	if fn.Doc == nil {
		return ""
	}
	var lines []string
	for _, comment := range fn.Doc.List {
		text := comment.Text
		if strings.HasPrefix(text, "// ") {
			lines = append(lines, strings.TrimPrefix(text, "// "))
		} else {
			lines = append(lines, strings.TrimPrefix(text, "//"))
		}
	}
	return strings.Join(lines, "\n")
}
