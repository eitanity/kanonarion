package staticcha

import (
	"go/ast"
	"go/types"
	"slices"
	"strings"

	"golang.org/x/tools/go/packages"
)

// linknameDecl is what TinyGo's //go:linkname makes of one package-level
// function: the symbol it is linked under, and whether it has a body.
type linknameDecl struct {
	symbol  string
	hasBody bool
}

// readLinknames reads every //go:linkname that renames a package-level function,
// keyed by node ID, the way TinyGo's parsePragmas reads it (compiler/symbol.go):
// the function's doc comment first, then a free-standing directive in the same
// file, honoured only when the package imports "unsafe".
func readLinknames(loaded []*packages.Package) map[string]linknameDecl {
	out := make(map[string]linknameDecl)
	for _, p := range loaded {
		if isSyntheticTestMain(p) || p.Types == nil || !importsUnsafe(p) {
			continue
		}
		for _, file := range p.Syntax {
			free := freeLinknames(file)
			for _, decl := range file.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Recv != nil || fd.Name == nil {
					continue
				}
				symbol, ok := linknameIn(fd.Doc, fd.Name.Name)
				if !ok {
					symbol, ok = free[fd.Name.Name]
				}
				if ok {
					out[funcDeclID(p.PkgPath, fd)] = linknameDecl{symbol: symbol, hasBody: fd.Body != nil}
				}
			}
		}
	}
	return out
}

func importsUnsafe(p *packages.Package) bool {
	return slices.ContainsFunc(p.Types.Imports(), func(i *types.Package) bool { return i.Path() == "unsafe" })
}

// linknameIn returns the symbol a comment group's //go:linkname gives local.
func linknameIn(g *ast.CommentGroup, local string) (string, bool) {
	if g == nil {
		return "", false
	}
	for _, c := range g.List {
		if l, remote, ok := parseLinkname(c.Text); ok && l == local {
			return remote, true
		}
	}
	return "", false
}

// freeLinknames is every //go:linkname in a file's comments, by local name. A
// doc comment's directive wins over these, so including doc comments here
// changes nothing.
func freeLinknames(f *ast.File) map[string]string {
	out := make(map[string]string)
	for _, g := range f.Comments {
		for _, c := range g.List {
			if l, remote, ok := parseLinkname(c.Text); ok {
				if _, seen := out[l]; !seen {
					out[l] = remote
				}
			}
		}
	}
	return out
}

func parseLinkname(text string) (local, remote string, ok bool) {
	parts := strings.Fields(text)
	if len(parts) != 3 || (parts[0] != "//go:linkname" && parts[0] != "//go:linknamestd") {
		return "", "", false
	}
	return parts[1], parts[2], true
}
