package cmd_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// modulePath is the Go module path; package paths are made repo-relative by
// trimming this prefix.
const modulePath = "github.com/eitanity/kanonarion"

// boundedContexts is the closed set of DDD bounded contexts (CLAUDE.md /
// ). Only these count as "another context" for the cross-context
// import rule; the shared kernel under internal/adapters/** and
// internal/adapters generally is deliberately exempt.
var boundedContexts = map[string]bool{
	"fetch": true, "walk": true, "license": true, "iface": true,
	"callgraph": true, "example": true, "extract": true,
	"vuln": true, "sbom": true, "local": true,
}

// forbiddenLayerImports are infrastructure/parsing packages that must never
// be imported from an application or domain layer (prevention 2a).
// Source/format parsing belongs behind a port-backed adapter; raw SQL belongs
// in an adapters store.
var forbiddenLayerImports = map[string]string{
	"archive/zip":  "archive extraction belongs behind a port-backed adapter",
	"go/ast":       "AST parsing belongs behind a port-backed adapter",
	"go/parser":    "Go source parsing belongs behind a port-backed adapter",
	"go/printer":   "Go source printing belongs behind a port-backed adapter",
	"go/format":    "Go source formatting belongs behind a port-backed adapter",
	"database/sql": "SQL access belongs in an adapters store, not application/domain",
}

// knownInfraViolations grandfathers infrastructure imports that predate the
// enforcement. Each entry is tracked by a remediation ticket and MUST
// be removed when that ticket lands. The test fails both on a NEW violation
// (regression guard) and on a STALE entry here that no longer violates
// (forces this baseline to drain as the tickets close). Key:
// "<repo-relative package path> <import path>".
//
// The original archive/zip baseline (..) has fully drained: ZIP
// access now routes through the shared internal/adapters/ziparchive adapter.
var knownInfraViolations = map[string]string{}

// layerOf returns the bounded context and layer for a repo-relative package
// path like "internal/vuln/application/foo". ctx is "" when the path is not a
// context-scoped layer (e.g. the shared internal/adapters/** kernel).
func layerOf(rel string) (ctx, layer string) {
	parts := strings.Split(rel, "/")
	if len(parts) < 3 || parts[0] != "internal" {
		return "", ""
	}
	if !boundedContexts[parts[1]] {
		return "", ""
	}
	return parts[1], parts[2]
}

func loadInternalPackages(t *testing.T) []*packages.Package {
	t.Helper()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedImports,
		Dir:  "..",
	}
	pkgs, err := packages.Load(cfg, "./internal/...")
	if err != nil {
		t.Fatalf("packages.Load: %v", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatalf("packages.Load reported errors")
	}
	return pkgs
}

func rel(pkgPath string) string {
	return strings.TrimPrefix(pkgPath, modulePath+"/")
}

// TestNoCrossContextApplicationImports enforces that an application layer
// never reaches into another bounded context's application or adapters
// package. Cross-context use must go through the other context's ports (or
// the shared fetch/domain coordinate), with composition pushed into adapters
// (prevention 2a, first bullet).
func TestNoCrossContextApplicationImports(t *testing.T) {
	for _, pkg := range loadInternalPackages(t) {
		ctx, layer := layerOf(rel(pkg.PkgPath))
		if ctx == "" || layer != "application" {
			continue
		}
		for impPath := range pkg.Imports {
			impCtx, impLayer := layerOf(rel(impPath))
			if impCtx == "" || impCtx == ctx {
				continue
			}
			if impLayer == "application" || impLayer == "adapters" {
				t.Errorf("%s imports %s: application must not depend on another context's %s layer — use %s/ports and compose in adapters",
					rel(pkg.PkgPath), rel(impPath), impLayer, impCtx)
			}
		}
	}
}

// TestNoWallClockInApplicationOrDomain is the enforced equivalent of the
// .golangci.yml forbidigo rule (prevention 2b): no time.Now or
// time.Since in any application or domain layer. It is implemented as a
// test, not only as lint config, because `make lint` does not run
// golangci-lint — `make test` is the mechanism that actually gates CI.
// Wall-clock access must go through the injected Clock (record timestamps)
// or a Stopwatch (latency metrics). Comments do not count (AST-based).
func TestNoWallClockInApplicationOrDomain(t *testing.T) {
	const repoRoot = ".."
	banned := map[string]bool{"Now": true, "Since": true}

	for _, ctx := range keysOf(boundedContexts) {
		for _, layer := range []string{"application", "domain"} {
			root := filepath.Join(repoRoot, "internal", ctx, layer)
			if _, err := os.Stat(root); err != nil {
				continue
			}
			err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return fmt.Errorf("walk %s: %w", path, err)
				}
				if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
					return nil
				}
				fset := token.NewFileSet()
				f, perr := parser.ParseFile(fset, path, nil, 0)
				if perr != nil {
					return fmt.Errorf("parse %s: %w", path, perr)
				}
				ast.Inspect(f, func(n ast.Node) bool {
					sel, ok := n.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					pkgIdent, ok := sel.X.(*ast.Ident)
					if !ok || pkgIdent.Name != "time" || !banned[sel.Sel.Name] {
						return true
					}
					rp := strings.TrimPrefix(filepath.ToSlash(path), "../")
					t.Errorf("%s: time.%s in %s layer — inject clock.Clock (timestamps) or a Stopwatch (latency)",
						rp, sel.Sel.Name, layer)
					return true
				})
				return nil
			})
			if err != nil {
				t.Fatalf("walking %s: %v", root, err)
			}
		}
	}
}

// facadeExportViolations reports every exported top-level identifier in the
// given parsed files that lacks a doc comment or a Stability line (§5).
// A doc comment and Stability line may come from the identifier's own comment or,
// for a single-spec or grouped declaration, the enclosing GenDecl's comment — so
// a grouped const/var block documents its members collectively. Messages are
// "<name>: <reason>" so callers can prefix the file path. The check is purely
// AST-based: it never imports the package, so it runs even mid-refactor.
func facadeExportViolations(files []*ast.File) []string {
	var out []string
	check := func(name string, own, parent *ast.CommentGroup) {
		if !ast.IsExported(name) {
			return
		}
		var text string
		if own != nil {
			text += own.Text()
		}
		if parent != nil {
			text += parent.Text()
		}
		switch {
		case strings.TrimSpace(text) == "":
			out = append(out, name+": exported but undocumented — add a doc comment with a Stability line")
		case !strings.Contains(text, "Stability:"):
			out = append(out, name+": documented but untagged — add a Stability line stating its consumer relationship")
		}
	}
	for _, f := range files {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv != nil {
					continue // methods are documented under their receiver type
				}
				check(d.Name.Name, d.Doc, nil)
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						check(s.Name.Name, s.Doc, d.Doc)
					case *ast.ValueSpec:
						for _, n := range s.Names {
							check(n.Name, s.Doc, d.Doc)
						}
					}
				}
			}
		}
	}
	return out
}

// TestPublicFacadeExportsDocumentedAndTagged enforces §5: the frozen
// public surface in pkg/kanonarion must not grow accidentally, so every exported
// identifier carries BOTH a doc comment and a Stability line stating its
// consumer relationship. This is the CI gate that fails on a new undocumented or
// untagged export and passes on the curated surface. The checker logic lives in
// facadeExportViolations and is exercised against synthetic sources by
// TestFacadeExportCheckerRejectsBadExports.
func TestPublicFacadeExportsDocumentedAndTagged(t *testing.T) {
	const dir = "../pkg/kanonarion"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ParseComments)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("no non-test source files found in pkg/kanonarion")
	}
	for _, v := range facadeExportViolations(files) {
		t.Errorf("pkg/kanonarion %s", v)
	}
}

// TestFacadeExportCheckerRejectsBadExports is the regression guard for the gate
// itself: it proves facadeExportViolations actually rejects an undocumented
// export and a documented-but-untagged export, and accepts a properly curated
// one. Without a working checker this test fails, so the CI gate cannot silently
// degrade into a no-op.
func TestFacadeExportCheckerRejectsBadExports(t *testing.T) {
	const src = `package kanonarion

// Good is documented and tagged.
//
// Stability: result type (received by consumers); unstable pre-v1.
type Good = int

type Undocumented = int

// Untagged has a doc comment but no Stability line.
type Untagged = int

// unexported is ignored even without a Stability line.
type unexported = int
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse synthetic source: %v", err)
	}
	got := facadeExportViolations([]*ast.File{f})
	joined := strings.Join(got, "\n")
	if strings.Contains(joined, "Good:") {
		t.Errorf("checker flagged a well-formed export:\n%s", joined)
	}
	if strings.Contains(joined, "unexported") {
		t.Errorf("checker flagged an unexported identifier:\n%s", joined)
	}
	if !strings.Contains(joined, "Undocumented: exported but undocumented") {
		t.Errorf("checker did not reject the undocumented export:\n%s", joined)
	}
	if !strings.Contains(joined, "Untagged: documented but untagged") {
		t.Errorf("checker did not reject the untagged export:\n%s", joined)
	}
}

// TestConsumerCapstoneImportsPublicSurfaceOnly enforces the capstone
// acceptance mechanically: the consumer-shaped acceptance test under
// test/consumer must compile against the public façade ONLY. It fails if any
// file there imports an internal package — the boundary the façade exists to
// hold. It also asserts the public package IS imported, so the guard cannot pass
// vacuously against an empty directory.
func TestConsumerCapstoneImportsPublicSurfaceOnly(t *testing.T) {
	const dir = "consumer"
	const publicPkg = modulePath + "/pkg/kanonarion"
	internalPrefix := modulePath + "/internal/"

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	var importsPublic, sawGoFile bool
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		sawGoFile = true
		f, perr := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.ImportsOnly)
		if perr != nil {
			t.Fatalf("parse %s: %v", e.Name(), perr)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if strings.HasPrefix(path, internalPrefix) || path == modulePath+"/internal" {
				t.Errorf("%s imports internal package %q — the capstone must consume only the public façade", e.Name(), path)
			}
			if path == publicPkg {
				importsPublic = true
			}
		}
	}
	if !sawGoFile {
		t.Fatalf("no Go files found under %s", dir)
	}
	if !importsPublic {
		t.Errorf("no file under %s imports %q — the capstone must exercise the public façade", dir, publicPkg)
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestNoInfraImportsInApplicationOrDomain enforces that the application and
// domain layers stay free of source/format parsing and raw SQL — those
// concerns belong behind port-backed adapters (prevention 2a,
// second bullet).
func TestNoInfraImportsInApplicationOrDomain(t *testing.T) {
	seen := make(map[string]bool, len(knownInfraViolations))
	for _, pkg := range loadInternalPackages(t) {
		relPath := rel(pkg.PkgPath)
		ctx, layer := layerOf(relPath)
		if ctx == "" || (layer != "application" && layer != "domain") {
			continue
		}
		for impPath := range pkg.Imports {
			reason, forbidden := forbiddenLayerImports[impPath]
			if !forbidden {
				continue
			}
			key := relPath + " " + impPath
			if ticket, grandfathered := knownInfraViolations[key]; grandfathered {
				seen[key] = true
				t.Logf("known layering violation (tracked by %s): %s imports %q", ticket, relPath, impPath)
				continue
			}
			t.Errorf("%s imports %q: %s — new violation; route through a port-backed adapter",
				relPath, impPath, reason)
		}
	}
	for key, ticket := range knownInfraViolations {
		if !seen[key] {
			t.Errorf("knownInfraViolations entry %q (%s) no longer violates — remove it from the baseline now that %s is fixed",
				key, ticket, ticket)
		}
	}
}

// valueObjectAccessors are the methods that replaced an exported field on each
// value object, keyed by the fully qualified receiver type. A missing call on
// one of these yields a func value rather than the string or bool the reader
// meant, which is what makes the omission dangerous rather than merely wrong.
//
// Each entry is one conversion: ModuleCoordinate, then the artefact identity
// and the hash inside it, then the blob identity that addresses an artefact in
// a store. The identity is the key the fetch ledger composes on and the value
// the extraction contexts embed, so an uncalled accessor there reaches a SQL
// parameter by the same route the coordinate's did. The blob identity reaches
// one by a shorter route still: its String is written to the content_location
// and go_mod_location columns of every fact record.
var valueObjectAccessors = map[string]map[string]bool{
	modulePath + "/internal/coordinate.ModuleCoordinate": {
		"Path": true, "Version": true, "String": true, "IsLocal": true,
	},
	modulePath + "/internal/fetch/domain.ArtefactIdentity": {
		"Hash": true, "GoModOnly": true, "String": true, "IsZero": true,
	},
	modulePath + "/internal/fetch/domain.ModuleHash": {
		"Algorithm": true, "Value": true, "String": true, "IsZero": true,
	},
	modulePath + "/internal/fetch/ports.BlobIdentity": {
		"Kind": true, "Hash": true, "String": true, "IsZero": true,
	},
}

// TestNoCoordinateAccessorMethodValues is the residual guard on unexporting the
// fields of the value objects above.
//
// Unexporting them turned every read of coord.Path into a call. The compiler
// catches almost all of the ones that were missed — a func() string will not
// concatenate, compare or pass as a string — but it accepts three shapes that
// fail only at run time: an argument typed any (a SQL query parameter, a
// structured-log field, an audit event's payload), a %v or %s verb (go vet
// catches those, and did), and a value stored into an interface field.
//
// This is not hypothetical. The coordinate conversion left 88 such method
// values behind: they built cleanly and vet passed on all but seven, and the
// first evidence was "sql: converting argument $1 type: unsupported type
// func() string" from the fact store. Nothing else in the toolchain rejects
// them, so the check lives here, and every later conversion is added to
// valueObjectAccessors rather than trusted to a clean build.
func TestNoCoordinateAccessorMethodValues(t *testing.T) {
	cfg := &packages.Config{
		Mode:  packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedName | packages.NeedFiles | packages.NeedDeps | packages.NeedImports,
		Tests: true,
		Dir:   "..",
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		t.Fatalf("packages.Load: %v", err)
	}
	reported := map[string]bool{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			called := map[ast.Expr]bool{}
			ast.Inspect(file, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok {
					called[c.Fun] = true
				}
				return true
			})
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || called[ast.Expr(sel)] {
					return true
				}
				selection := pkg.TypesInfo.Selections[sel]
				if selection == nil || selection.Kind() != types.MethodVal {
					return true
				}
				// Selections is the only reliable oracle here: the receiver type
				// says which value object this is, and a nil Selection means the
				// selector is not a method on a value at all.
				recv := strings.TrimPrefix(selection.Recv().String(), "*")
				if !valueObjectAccessors[recv][sel.Sel.Name] {
					return true
				}
				pos := pkg.Fset.Position(sel.Sel.Pos())
				msg := fmt.Sprintf("%s:%d:%d: %s.%s is used as a method value, not called — add the parentheses; a func() reaching an any-typed argument fails at run time, not at build time",
					pos.Filename, pos.Line, pos.Column, recv[strings.LastIndex(recv, ".")+1:], sel.Sel.Name)
				if !reported[msg] {
					reported[msg] = true
					t.Error(msg)
				}
				return true
			})
		}
	}
}
