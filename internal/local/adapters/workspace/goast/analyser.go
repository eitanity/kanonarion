// Package goast implements ports.WorkspaceAnalyser using go/parser to extract
// function declarations directly from Snapshot file contents without disk I/O.
package goast

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/local/domain"
	"github.com/eitanity/kanonarion/internal/local/ports"
)

// Analyser implements ports.WorkspaceAnalyser using go/parser on in-memory
// snapshot files.
type Analyser struct{}

// Analyse parses every.go file in snap and returns the workspace metadata
// needed for dynamic callgraph root selection. No disk reads are performed;
// all source is read from snap.Files.
func (Analyser) Analyse(_ context.Context, snap domain.Snapshot) (ports.WorkspaceInfo, error) {
	modulePath, moduleRoot, err := findModule(snap.Files)
	if err != nil {
		return ports.WorkspaceInfo{}, fmt.Errorf("locating go.mod in snapshot: %w", err)
	}

	var info ports.WorkspaceInfo
	fset := token.NewFileSet()

	for path, content := range snap.Files {
		if !strings.HasSuffix(path, ".go") {
			continue
		}

		isTestFile := strings.HasSuffix(path, "_test.go")
		if isTestFile {
			info.Kind.HasTestFiles = true
		}

		f, err := parser.ParseFile(fset, path, content, 0)
		if err != nil {
			// Partial parse errors are non-fatal; skip the file.
			continue
		}

		pkgImportPath := importPath(modulePath, moduleRoot, path)

		if !isTestFile && f.Name.Name == "main" {
			info.Kind.IsMain = true
		}

		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			d := domain.FuncDecl{
				Package:    pkgImportPath,
				Name:       fd.Name.Name,
				IsExported: ast.IsExported(fd.Name.Name),
				IsTestFile: isTestFile,
			}
			if fd.Recv != nil && len(fd.Recv.List) > 0 {
				d.Receiver = receiverName(fd.Recv.List[0].Type)
			}
			info.Funcs = append(info.Funcs, d)
		}
	}

	return info, nil
}

// findModule locates go.mod in the snapshot files and returns the declared
// module path and the absolute directory containing go.mod (the module root).
func findModule(files map[string][]byte) (modulePath, moduleRoot string, err error) {
	for path, content := range files {
		if filepath.Base(path) != "go.mod" {
			continue
		}
		mp, parseErr := parseModulePath(content)
		if parseErr != nil {
			continue
		}
		return mp, filepath.Dir(path), nil
	}
	return "", "", fmt.Errorf("no go.mod found in snapshot")
}

// parseModulePath extracts the module path from go.mod content by scanning
// for the "module" directive without importing golang.org/x/mod.
func parseModulePath(content []byte) (string, error) {
	for _, line := range bytes.Split(content, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("module ")) {
			continue
		}
		path := strings.TrimSpace(string(line[len("module "):]))
		// Strip inline comments.
		if idx := strings.Index(path, "//"); idx >= 0 {
			path = strings.TrimSpace(path[:idx])
		}
		if path != "" {
			return path, nil
		}
	}
	return "", fmt.Errorf("module directive not found in go.mod")
}

// importPath derives the Go import path for a.go source file given the
// module path, the module root directory, and the file's absolute path.
func importPath(modulePath, moduleRoot, filePath string) string {
	dir := filepath.Dir(filePath)
	rel, err := filepath.Rel(moduleRoot, dir)
	if err != nil || rel == "." {
		return modulePath
	}
	return modulePath + "/" + filepath.ToSlash(rel)
}

// receiverName extracts a concise string for a receiver type expression.
func receiverName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return "*" + exprName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return exprName(t.X)
	case *ast.IndexListExpr:
		return exprName(t.X)
	default:
		return ""
	}
}

func exprName(expr ast.Expr) string {
	if id, ok := expr.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// Ensure Analyser implements ports.WorkspaceAnalyser at compile time.
var _ ports.WorkspaceAnalyser = Analyser{}
