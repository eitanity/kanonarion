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

	isExportedAPI := !isExternal &&
		len(symbol) > 0 &&
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
// Format: "pkg/path.FuncName" or "pkg/path.(*RecvType).MethodName".
func nodeID(fn *ssa.Function) string {
	if fn.Package() == nil {
		return fn.String()
	}
	pkgPath := fn.Package().Pkg.Path()
	sig := fn.Signature
	if sig.Recv() != nil {
		recvTyp := recvTypeStr(sig.Recv().Type())
		return pkgPath + ".(" + recvTyp + ")." + fn.Name()
	}
	return pkgPath + "." + fn.Name()
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
func classifyConfidence(edge *callgraph.Edge) domain.EdgeConfidence {
	if edge.Site == nil {
		return domain.ConfidenceUnknown
	}
	common := edge.Site.Common()
	if common.IsInvoke() {
		return domain.ConfidenceDynamicDispatch
	}
	if common.StaticCallee() != nil {
		// Check for reflection-based calls.
		if edge.Callee.Func != nil && edge.Callee.Func.Package() != nil {
			if edge.Callee.Func.Package().Pkg.Path() == "reflect" {
				return domain.ConfidenceReflection
			}
		}
		return domain.ConfidenceDirect
	}
	return domain.ConfidenceUnknown
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
