package staticcha

import (
	"go/token"
	"go/types"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

func buildNode(fn *ssa.Function, coord coordinate.ModuleCoordinate, fset *token.FileSet, tempDir string) domain.CallNode {
	pkgPath := funcPackagePath(fn)
	isExternal := pkgPath == "" ||
		(pkgPath != coord.Path() && !strings.HasPrefix(pkgPath, coord.Path()+"/"))

	symbol := fn.Name()
	receiver := extractReceiverName(fn)

	pos := domain.SourcePosition{}
	if fn.Pos() != token.NoPos && fset != nil {
		p := fset.Position(fn.Pos())
		if p.IsValid() {
			pos = domain.SourcePosition{
				File: relativePath(p.Filename, tempDir),
				Line: p.Line,
			}
		}
	}

	// A function with an enclosing function is never public API: no consumer can
	// name a closure, only reach it by calling what encloses it. See
	// isExportedAPI for the rest of the rule.
	isSynthetic := fn.Parent() != nil || hasSyntheticSymbolMarker(symbol)

	exportedAPI := isExportedAPI(isExternal, isSynthetic, symbol, pkgPath, isMainPkg(fn))

	modulePath := ""
	if !isExternal {
		modulePath = coord.Path()
	}

	return domain.CallNode{
		ID:            nodeID(fn),
		Module:        modulePath,
		Package:       pkgPath,
		Symbol:        symbol,
		Receiver:      receiver,
		IsExternal:    isExternal,
		IsExportedAPI: exportedAPI,
		Position:      pos,
		IsTest:        isTestFunc(fn, fset, pkgPath),
	}
}

// isTestFunc reports whether fn is test-scope: declared in a _test.go file, or
// in an external test package.
//
// The position is taken from the object rather than the function when the
// function has none, which is the case for the synthetic wrappers SSA
// materialises for a method set. A wrapper around a test fake's method is test
// code, and attributing it to production would put it back in exactly the
// answer the role exists to keep separate.
func isTestFunc(fn *ssa.Function, fset *token.FileSet, pkgPath string) bool {
	if isTestPackagePath(pkgPath) {
		return true
	}
	if fset == nil {
		return false
	}
	pos := fn.Pos()
	if pos == token.NoPos {
		if obj := fn.Object(); obj != nil {
			pos = obj.Pos()
		}
	}
	if pos == token.NoPos {
		// A synthetic function with no object at all — a package initialiser or
		// a bound-method thunk. It inherits its parent's role when it has one.
		if parent := fn.Parent(); parent != nil {
			return isTestFunc(parent, fset, pkgPath)
		}
		return false
	}
	p := fset.Position(pos)
	return p.IsValid() && strings.HasSuffix(p.Filename, "_test.go")
}

// isTestDeclaration is the type-level form of isTestFunc, for a declaration
// identified by its position rather than by an SSA function.
func isTestDeclaration(pos token.Pos, fset *token.FileSet, pkgPath string) bool {
	if isTestPackagePath(pkgPath) {
		return true
	}
	if fset == nil || pos == token.NoPos {
		return false
	}
	p := fset.Position(pos)
	return p.IsValid() && strings.HasSuffix(p.Filename, "_test.go")
}

// isTestPackagePath reports whether an import path names an external test
// package, whose every declaration is test code.
func isTestPackagePath(pkgPath string) bool {
	return strings.HasSuffix(pkgPath, "_test")
}

// funcPackagePath returns the import path of the package a function belongs to.
//
// SSA leaves Package() nil for the synthetic wrappers it materialises for a
// method set — a value-receiver method reached through a pointer, a bound
// method value. Those wrappers are not package members, but they are not
// package-less either: they wrap a method declared in a real package, and the
// object records which. Reading only Package() attributed every one of them to
// no module and marked it external, which mis-scopes reachability rooting and
// module attribution for a symbol that is the module's own code.
func funcPackagePath(fn *ssa.Function) string {
	pkg := funcPackage(fn)
	if pkg == nil {
		return ""
	}
	return pkg.Path()
}

// funcPackage returns the package that declares a function, and is the single
// resolution every package-derived fact goes through — the import path a node
// is attributed to, and whether that package is a command.
//
// Package() is documented to be nil for the shared functions SSA synthesises:
// method wrappers, thunks, bound-method values, error.Error. Those functions
// are not package-less, they are shared, and the object records the method they
// stand for. Object() is nil in turn for a function literal and a synthetic
// init, and a literal inherits the package of whatever encloses it.
//
// It returns nil when nothing names the function, which every caller must read
// as the absence of an answer rather than as a package.
func funcPackage(fn *ssa.Function) *types.Package {
	if fn == nil {
		return nil
	}
	if pkg := fn.Package(); pkg != nil && pkg.Pkg != nil {
		return pkg.Pkg
	}
	if obj := fn.Object(); obj != nil && obj.Pkg() != nil {
		return obj.Pkg()
	}
	// A closure inherits the package of whatever encloses it.
	if parent := fn.Parent(); parent != nil {
		return funcPackage(parent)
	}
	return nil
}

// nodeID returns a stable, unique identifier for an SSA function.
// Format: "pkg/path.FuncName", "pkg/path.(*RecvType).MethodName", or, for an
// anonymous function, the enclosing function's identifier plus the SSA anon
// suffix: "pkg/path.(*RecvType).MethodName$1".
//
// A closure is identified through its parent rather than its own signature. Its
// signature has no receiver even when it is declared inside a method, and
// ssa.Function.Name() renders only the enclosing function's *simple* name, so
// deriving the ID from the closure alone drops the receiver — and two same-named
// methods on different receivers then collide on one ID, merging the edge sets
// of unrelated functions.
func nodeID(fn *ssa.Function) string {
	if fn.Package() == nil {
		return fn.String()
	}
	// Anonymous functions carry a parent; qualify them with its full ID so the
	// receiver is preserved. Recursion composes nested closures.
	if parent := fn.Parent(); parent != nil {
		if suffix, ok := anonSuffix(fn.Name(), parent.Name()); ok {
			return nodeID(parent) + suffix
		}
	}
	pkgPath := fn.Package().Pkg.Path()
	sig := fn.Signature
	if sig.Recv() != nil {
		recvTyp := recvTypeStr(sig.Recv().Type())
		return pkgPath + ".(" + recvTyp + ")." + fn.Name()
	}
	return pkgPath + "." + fn.Name()
}

// anonSuffix returns the SSA anon marker that distinguishes a closure's name
// from its parent's (e.g. "$1"), and whether the name had the expected shape.
// A name that does not extend the parent's is left to the caller to handle
// rather than being mangled by a blind trim.
func anonSuffix(name, parentName string) (string, bool) {
	if parentName == "" || !strings.HasPrefix(name, parentName) {
		return "", false
	}
	suffix := name[len(parentName):]
	if suffix == "" || !strings.HasPrefix(suffix, "$") {
		return "", false
	}
	return suffix, true
}

// recvTypeStr returns a concise representation of a receiver type.
func recvTypeStr(t types.Type) string {
	switch v := t.(type) {
	case *types.Pointer:
		if named, ok := v.Elem().(*types.Named); ok {
			return "*" + named.Obj().Name()
		}
		return "*" + v.Elem().String()
	case *types.Named:
		return v.Obj().Name()
	default:
		return t.String()
	}
}
func extractReceiverName(fn *ssa.Function) string {
	sig := fn.Signature
	if sig.Recv() == nil {
		return ""
	}
	return recvTypeStr(sig.Recv().Type())
}

// classifyConfidence resolves an edge's confidence tag. The second result
// reports whether the edge originated from a reflect call; such edges are folded
// into ConfidenceUnknown but carry the reflect provenance as an edge attribute.
func classifyConfidence(edge *callgraph.Edge) (domain.EdgeConfidence, bool) {
	if edge.Site == nil {
		return domain.ConfidenceUnknown, false
	}
	common := edge.Site.Common()
	if common.IsInvoke() {
		// An unrefined CHA interface over-approximation.
		return domain.ConfidenceCHAOverapprox, false
	}
	if common.StaticCallee() != nil {
		// Reflect-dispatched calls are unresolved edges tagged with the reflect
		// origin, not a distinct confidence rank.
		if edge.Callee.Func != nil && edge.Callee.Func.Package() != nil {
			if edge.Callee.Func.Package().Pkg.Path() == "reflect" {
				return domain.ConfidenceUnknown, true
			}
		}
		return domain.ConfidenceDirect, false
	}
	return domain.ConfidenceUnknown, false
}

// isExportedAPI reports whether a node is consumable public API of the module
// under analysis. It is the single definition of that rule: every node builder
// must use it, because IsExportedAPI feeds reachability rooting and a symbol
// that is API on one construction path and not on another makes the axis mean
// two things.
//
// token.IsExported inspects the first rune only, and an anonymous function's
// name is the enclosing function's name plus the SSA anon marker ("Method$1"),
// so without the synthetic guard every closure inside an exported function
// reads as exported and becomes a library reachability root that cannot
// actually be triggered; the same holds for bound-method and thunk wrappers.
// Package-main symbols are not consumable API either: nothing can import them.
//
// isSynthetic and isMain are passed in rather than derived because the callers
// hold different evidence — a builder working from go/types has no
// *ssa.Function to ask.
func isExportedAPI(isExternal, isSynthetic bool, symbol, pkgPath string, isMain bool) bool {
	return !isExternal &&
		len(symbol) > 0 &&
		!isSynthetic &&
		token.IsExported(symbol) &&
		!isInternalPkg(pkgPath) &&
		!isMain
}

// hasSyntheticSymbolMarker reports whether a symbol name carries the SSA marker
// that distinguishes a closure, bound-method or thunk wrapper from a declared
// function.
func hasSyntheticSymbolMarker(symbol string) bool {
	return strings.Contains(symbol, "$")
}

func isInternalPkg(path string) bool {
	return strings.Contains(path, "/internal/") ||
		strings.HasSuffix(path, "/internal")
}

// isMainPkg reports whether a function belongs to a command — a package nothing
// can import, and so nothing can call from outside the binary.
//
// It resolves the package through funcPackage rather than Package() alone. A
// value-receiver method on a package-main type, reached through a pointer, is
// carried by a synthetic wrapper whose own Package() is nil; reading only that
// answered "not main" and minted the method as exported library API, which is
// a false claim rather than a weaker one and roots library reachability at an
// entry no consumer could ever reach.
//
// Where no package can be resolved the guard fails closed and answers true: a
// symbol nothing can name is not library API by default. Failing open would
// trade a false root for a missing one, which is harder to notice because
// nothing appears.
func isMainPkg(fn *ssa.Function) bool {
	pkg := funcPackage(fn)
	if pkg == nil {
		return true
	}
	return pkg.Name() == "main"
}

// relativePath strips tempDir prefix from path for cleaner output.
func relativePath(path, tempDir string) string {
	if tempDir == "" {
		return path
	}
	rel := strings.TrimPrefix(path, tempDir)
	rel = strings.TrimPrefix(rel, string(filepath.Separator))
	if rel == "" {
		return path
	}
	return rel
}
