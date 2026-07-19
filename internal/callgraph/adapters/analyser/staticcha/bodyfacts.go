package staticcha

import (
	"context"
	"go/ast"
	"go/token"
	"log/slog"
	"os"
	"runtime"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"golang.org/x/tools/go/packages"
)

// bodyFacts captures per-function properties derived from a function's own
// source body rather than from its callee identity. These are the capability
// witnesses that a call graph plus a package/function sink map structurally
// cannot detect: the unsafe package exposes no callable functions,
// assembly / //go:linkname functions have no Go body and thus no call edges
// into them, and a plugin.Open / Lookup boundary loads code that is resolved at
// runtime and never appears in the static graph.
type bodyFacts struct {
	usesUnsafePointer    bool
	isAssemblyOrLinkname bool
	usesPlugin           bool
}

// attachBodyFacts scans the packages present in nodes for body-level capability
// facts and stamps them onto the matching nodes in place. It is best-effort:
// packages whose syntax cannot be loaded simply contribute no facts.
func (a *Analyser) attachBodyFacts(ctx context.Context, nodes []domain.CallNode, dir string) {
	pkgPaths := distinctNodePackages(nodes)
	if len(pkgPaths) == 0 {
		return
	}

	facts := scanBodyFacts(ctx, dir, pkgPaths)
	if len(facts) == 0 {
		return
	}

	var unsafeCount, asmCount, pluginCount int
	for i := range nodes {
		f, ok := facts[nodes[i].ID]
		if !ok {
			continue
		}
		nodes[i].UsesUnsafePointer = f.usesUnsafePointer
		nodes[i].IsAssemblyOrLinkname = f.isAssemblyOrLinkname
		nodes[i].UsesPlugin = f.usesPlugin
		if f.usesUnsafePointer {
			unsafeCount++
		}
		if f.isAssemblyOrLinkname {
			asmCount++
		}
		if f.usesPlugin {
			pluginCount++
		}
	}

	a.logger.InfoContext(ctx, "callgraph_body_facts_attached",
		slog.Int("scanned_packages", len(pkgPaths)),
		slog.Int("uses_unsafe_pointer", unsafeCount),
		slog.Int("assembly_or_linkname", asmCount),
		slog.Int("uses_plugin", pluginCount),
	)
}

// distinctNodePackages returns the sorted set of package import paths that
// appear across nodes, skipping nodes with an empty package.
func distinctNodePackages(nodes []domain.CallNode) []string {
	seen := make(map[string]struct{}, len(nodes))
	for _, n := range nodes {
		if n.Package != "" {
			seen[n.Package] = struct{}{}
		}
	}
	paths := make([]string, 0, len(seen))
	for p := range seen {
		paths = append(paths, p)
	}
	return paths
}

// scanBodyFacts parses the syntax of the given packages and records body-level
// facts keyed by function ID (matching nodeID's format so the caller can attach
// them to the corresponding graph node). Detection is purely syntactic — no
// type checking — so loading is cheap and independent of the SSA build. Loading
// is batched and syntax is discarded after each batch to bound peak memory; a
// failure to load any batch is non-fatal and simply yields no facts for those
// packages (capability analysis then falls back to the sink map alone).
//
// A dedicated FileSet is used because these facts need no source positions and
// re-parsing into the SSA program's FileSet would bloat it.
func scanBodyFacts(ctx context.Context, dir string, pkgPaths []string) map[string]bodyFacts {
	facts := make(map[string]bodyFacts)
	if len(pkgPaths) == 0 {
		return facts
	}

	const batchSize = 40
	for i := 0; i < len(pkgPaths); i += batchSize {
		if ctx.Err() != nil {
			return facts
		}
		end := i + batchSize
		if end > len(pkgPaths) {
			end = len(pkgPaths)
		}

		cfg := &packages.Config{
			Mode:    packages.NeedName | packages.NeedSyntax | packages.NeedFiles | packages.NeedCompiledGoFiles,
			Dir:     dir,
			Context: ctx,
			Fset:    token.NewFileSet(),
			Tests:   false,
		}

		oldGOGC := os.Getenv("GOGC")
		_ = os.Setenv("GOGC", "30")
		pkgs, err := packages.Load(cfg, pkgPaths[i:end]...)
		_ = os.Setenv("GOGC", oldGOGC)
		if err != nil {
			continue
		}

		for _, p := range pkgs {
			scanPackageFacts(p, facts)
			p.Syntax = nil
		}
		runtime.GC()
	}
	return facts
}

// scanPackageFacts records the body facts for every top-level function
// declaration in p.
func scanPackageFacts(p *packages.Package, facts map[string]bodyFacts) {
	if p.PkgPath == "" {
		return
	}
	for _, file := range p.Syntax {
		importsUnsafe := fileImportsUnsafe(file)
		importsPlugin := fileImportsPlugin(file)
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			id := funcDeclID(p.PkgPath, fd)
			if id == "" {
				continue
			}
			f := facts[id]
			// A nil body means the implementation is external: assembly, a
			// compiler intrinsic, or provided via //go:linkname.
			if fd.Body == nil {
				f.isAssemblyOrLinkname = true
			}
			if importsUnsafe && fd.Body != nil && bodyUsesUnsafePointer(fd.Body) {
				f.usesUnsafePointer = true
			}
			if importsPlugin && fd.Body != nil && bodyUsesPlugin(fd.Body) {
				f.usesPlugin = true
			}
			facts[id] = f
		}
	}
}

// fileImportsUnsafe reports whether file imports the unsafe package, a
// prerequisite for any unsafe.Pointer reference in its declarations.
func fileImportsUnsafe(file *ast.File) bool {
	for _, imp := range file.Imports {
		if imp.Path != nil && imp.Path.Value == `"unsafe"` {
			return true
		}
	}
	return false
}

// bodyUsesUnsafePointer reports whether body references unsafe.Pointer, which
// witnesses an unsafe.Pointer conversion or type use.
func bodyUsesUnsafePointer(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if ok && pkg.Name == "unsafe" && sel.Sel.Name == "Pointer" {
			found = true
			return false
		}
		return true
	})
	return found
}

// fileImportsPlugin reports whether file imports the plugin package, a
// prerequisite for any plugin-package reference in its declarations.
func fileImportsPlugin(file *ast.File) bool {
	for _, imp := range file.Imports {
		if imp.Path != nil && imp.Path.Value == `"plugin"` {
			return true
		}
	}
	return false
}

// bodyUsesPlugin reports whether body references the plugin package qualifier
// (e.g. plugin.Open, plugin.Plugin), which witnesses a runtime plugin-load
// boundary whose loaded targets are absent from the static graph. Detection is
// package-qualified so any use of the plugin API — not only Open — is a witness;
// a subsequent (*Plugin).Lookup runs on a value that necessarily references the
// qualifier at the load site.
func bodyUsesPlugin(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if ok && pkg.Name == "plugin" {
			found = true
			return false
		}
		return true
	})
	return found
}

// funcDeclID computes the graph node ID for a function declaration, matching
// nodeID's SSA-derived format: "pkg/path.FuncName" for free functions and
// "pkg/path.(*RecvType).MethodName" for methods.
func funcDeclID(pkgPath string, fd *ast.FuncDecl) string {
	if fd.Name == nil {
		return ""
	}
	name := fd.Name.Name
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return pkgPath + "." + name
	}
	recv := recvTypeStrAST(fd.Recv.List[0].Type)
	if recv == "" {
		return ""
	}
	return pkgPath + ".(" + recv + ")." + name
}

// recvTypeStrAST renders a receiver type expression as recvTypeStr renders the
// corresponding types.Type, so IDs from the AST scan match SSA node IDs. It
// strips type parameters from generic receivers (Store[T] -> Store) because the
// SSA form names the generic type without its arguments.
func recvTypeStrAST(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.StarExpr:
		inner := recvTypeStrAST(e.X)
		if inner == "" {
			return ""
		}
		return "*" + inner
	case *ast.IndexExpr:
		return recvTypeStrAST(e.X)
	case *ast.IndexListExpr:
		return recvTypeStrAST(e.X)
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	default:
		return ""
	}
}
