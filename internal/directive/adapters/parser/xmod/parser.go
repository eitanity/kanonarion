// Package xmod implements ports.DirectiveParser using
// golang.org/x/mod/modfile. It is pure parsing: it produces raw directives
// with file/line provenance and resolves go.work-over-go.mod precedence, but
// performs no risk classification or policy evaluation (those are the domain
// and config concerns respectively, per).
package xmod

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/eitanity/kanonarion/internal/directive/domain"
	"golang.org/x/mod/modfile"
)

// Parser implements ports.DirectiveParser.
type Parser struct{}

// New returns a new Parser.
func New() *Parser { return &Parser{} }

// ParseProject parses goModPath and any go.work discovered upward from its
// directory. A go.work `replace` overriding a go.mod `replace` for the same
// module marks the go.mod one not-applied (workspace precedence), so the
// applied set reflects what actually compiles.
func (p *Parser) ParseProject(goModPath string) (domain.ParseResult, error) {
	data, err := os.ReadFile(filepath.Clean(goModPath))
	if err != nil {
		return domain.ParseResult{}, fmt.Errorf("reading go.mod %q: %w", goModPath, err)
	}
	f, err := modfile.Parse(goModPath, data, nil)
	if err != nil {
		return domain.ParseResult{}, fmt.Errorf("parsing go.mod %q: %w", goModPath, err)
	}

	res := domain.ParseResult{ResolvedVersions: map[string]string{}}
	if f.Module != nil {
		res.ProjectModulePath = f.Module.Mod.Path
	}
	for _, r := range f.Require {
		res.ResolvedVersions[r.Mod.Path] = r.Mod.Version
	}

	var ds []domain.Directive
	for _, r := range f.Replace {
		ds = append(ds, replaceDirective("go.mod", r))
	}
	for _, e := range f.Exclude {
		line := 0
		if e.Syntax != nil {
			line = e.Syntax.Start.Line
		}
		ds = append(ds, domain.Directive{
			Kind:       domain.KindExclude,
			Source:     "go.mod",
			Line:       line,
			OldPath:    e.Mod.Path,
			OldVersion: e.Mod.Version,
			Applied:    true,
		})
	}

	if goworkPath, ok := findGoWork(filepath.Dir(goModPath)); ok {
		work, werr := parseWorkReplaces(goworkPath)
		if werr != nil {
			return domain.ParseResult{}, werr
		}
		applyWorkPrecedence(ds, work)
		ds = append(ds, work...)
	}

	res.Directives = ds
	return res, nil
}

// replaceDirective maps a modfile Replace into a raw domain.Directive.
func replaceDirective(source string, r *modfile.Replace) domain.Directive {
	line := 0
	if r.Syntax != nil {
		line = r.Syntax.Start.Line
	}
	d := domain.Directive{
		Kind:       domain.KindReplace,
		Source:     source,
		Line:       line,
		OldPath:    r.Old.Path,
		OldVersion: r.Old.Version,
		Applied:    true,
	}
	if modfile.IsDirectoryPath(r.New.Path) {
		d.IsLocal = true
		d.LocalPath = r.New.Path
	} else {
		d.NewPath = r.New.Path
		d.NewVersion = r.New.Version
	}
	return d
}

// parseWorkReplaces reads go.work and returns its replace directives.
func parseWorkReplaces(goworkPath string) ([]domain.Directive, error) {
	data, err := os.ReadFile(filepath.Clean(goworkPath))
	if err != nil {
		return nil, fmt.Errorf("reading go.work %q: %w", goworkPath, err)
	}
	wf, err := modfile.ParseWork(goworkPath, data, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.work %q: %w", goworkPath, err)
	}
	var ds []domain.Directive
	for _, r := range wf.Replace {
		ds = append(ds, replaceDirective("go.work", r))
	}
	return ds, nil
}

// applyWorkPrecedence marks any go.mod replace not-applied when a go.work
// replace overrides the same module (matching OldPath, and OldVersion equal
// or the go.work side is a wildcard replace-all).
func applyWorkPrecedence(gomod []domain.Directive, work []domain.Directive) {
	for i := range gomod {
		g := &gomod[i]
		if g.Kind != domain.KindReplace || g.Source != "go.mod" {
			continue
		}
		for _, w := range work {
			if w.OldPath != g.OldPath {
				continue
			}
			if w.OldVersion == "" || w.OldVersion == g.OldVersion {
				g.Applied = false
				break
			}
		}
	}
}

// findGoWork walks upward from dir looking for a go.work file, stopping at
// the filesystem root.
func findGoWork(dir string) (string, bool) {
	for {
		candidate := filepath.Join(dir, "go.work")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}
