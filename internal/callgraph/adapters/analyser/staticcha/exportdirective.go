package staticcha

import (
	"context"
	"go/ast"
	"go/token"
	"log/slog"
	"sort"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"golang.org/x/tools/go/packages"
)

// readExportDirectives reads the directives and logs each one it could not
// attribute, so a directive the record leaves out is stated rather than dropped.
func (a *Analyser) readExportDirectives(ctx context.Context, coord coordinate.ModuleCoordinate, loaded []*packages.Package, fset *token.FileSet) map[string]domain.ExportDirective {
	directives, unattributed := exportDirectives(loaded, fset)
	for _, u := range unattributed {
		a.logger.WarnContext(ctx, "callgraph_export_directive_unattributed",
			slog.String("module", coord.Path()), slog.String("detail", u))
	}
	return directives
}

// exportDirectives reads the export directive of every package-level function
// the analysed packages declare, keyed by node ID. A directive it cannot
// attribute — on a method, or malformed — comes back as a sentence to state.
func exportDirectives(loaded []*packages.Package, fset *token.FileSet) (map[string]domain.ExportDirective, []string) {
	out := make(map[string]domain.ExportDirective)
	// A production file is parsed into both the package and its test variant, so
	// one directive is met twice; the set keeps each statement once.
	stated := make(map[string]bool)
	for _, p := range loaded {
		if isSyntheticTestMain(p) {
			continue
		}
		for _, file := range p.Syntax {
			for _, decl := range file.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Doc == nil {
					continue
				}
				d, problems := declExportDirective(fd, fset)
				for _, problem := range problems {
					stated[problem] = true
				}
				if d.IsZero() {
					continue
				}
				if id := funcDeclID(p.PkgPath, fd); id != "" {
					out[id] = d
				}
			}
		}
	}
	unattributed := make([]string, 0, len(stated))
	for s := range stated {
		unattributed = append(unattributed, s)
	}
	sort.Strings(unattributed)
	return out, unattributed
}

// declExportDirective returns the directive fd's doc comment carries. A method
// records none, because neither toolchain exports one. Where both are present
// //go:wasmexport wins over //export, as it does in TinyGo.
func declExportDirective(fd *ast.FuncDecl, fset *token.FileSet) (domain.ExportDirective, []string) {
	var found []domain.ExportDirective
	var problems []string
	for _, c := range fd.Doc.List {
		d, matched, err := domain.ParseExportDirective(c.Text)
		switch {
		case !matched:
		case err != nil:
			problems = append(problems, fset.Position(c.Pos()).String()+": "+err.Error())
		default:
			found = append(found, d)
		}
	}
	if len(found) == 0 {
		return domain.ExportDirective{}, problems
	}
	if fd.Recv != nil {
		problems = append(problems, fset.Position(fd.Pos()).String()+": "+found[0].String()+
			" on method "+fd.Name.Name+" is not recorded: no toolchain exports a method")
		return domain.ExportDirective{}, problems
	}
	for _, d := range found {
		if d.Kind == domain.ExportWasm {
			return d, problems
		}
	}
	return found[0], problems
}

// attachExportDirectives stamps each node with the directive its declaration
// carries.
func attachExportDirectives(nodes []domain.CallNode, directives map[string]domain.ExportDirective) {
	for i := range nodes {
		if d, ok := directives[nodes[i].ID]; ok {
			nodes[i].ExportDirective = d
		}
	}
}
