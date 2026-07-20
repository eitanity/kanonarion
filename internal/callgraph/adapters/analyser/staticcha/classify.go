package staticcha

import (
	"go/token"
	"go/types"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

func buildNode(fn *ssa.Function, coord fetchdomain.ModuleCoordinate, fset *token.FileSet, tempDir string) domain.CallNode {
	pkgPath := ""
	isExternal := true
	if fn.Package() != nil {
		pkgPath = fn.Package().Pkg.Path()
		isExternal = pkgPath != coord.Path &&
			!strings.HasPrefix(pkgPath, coord.Path+"/")
	}

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
	// name a closure, only reach it by calling what encloses it. token.IsExported
	// inspects the first rune only, and an anonymous function's name is the
	// enclosing function's name plus the SSA anon marker ("Method$1"), so without
	// this guard every closure inside an exported function reads as exported and
	// becomes a library reachability root that cannot actually be triggered.
	// The "$" test covers the same way for bound-method and thunk wrappers.
	isSynthetic := fn.Parent() != nil || strings.Contains(symbol, "$")

	isExportedAPI := !isExternal &&
		len(symbol) > 0 &&
		!isSynthetic &&
		token.IsExported(symbol) &&
		!isInternalPkg(pkgPath) &&
		!isMainPkg(fn)

	modulePath := ""
	if !isExternal {
		modulePath = coord.Path
	}

	return domain.CallNode{
		ID:            nodeID(fn),
		Module:        modulePath,
		Package:       pkgPath,
		Symbol:        symbol,
		Receiver:      receiver,
		IsExternal:    isExternal,
		IsExportedAPI: isExportedAPI,
		Position:      pos,
	}
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
func isInternalPkg(path string) bool {
	return strings.Contains(path, "/internal/") ||
		strings.HasSuffix(path, "/internal")
}
func isMainPkg(fn *ssa.Function) bool {
	if fn.Package() == nil {
		return false
	}
	return fn.Package().Pkg.Name() == "main"
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
