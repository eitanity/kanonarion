// Package gopackages implements ports.SymbolAnalyser using go/packages
// type-checking to identify which exported symbols from dependency packages
// are referenced by the local workspace (~2-5s).
package gopackages

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"

	"code.eitanity.com/kanonarion/internal/adapters/goenv"
	"code.eitanity.com/kanonarion/internal/gotoolchain"
	"code.eitanity.com/kanonarion/internal/local/domain"
	"code.eitanity.com/kanonarion/internal/local/ports"
)

// Analyser implements ports.SymbolAnalyser using go/packages.
type Analyser struct{}

// New constructs an Analyser.
func New() *Analyser { return &Analyser{} }

// NeedDeps is deliberately absent. The imported-package PkgPath and Module the
// indexing recursion below reads are populated anyway by the type-checking
// bits; adding it type-checks every dependency function body for no new fact.
const loadMode = packages.NeedName |
	packages.NeedImports |
	packages.NeedTypes |
	packages.NeedTypesInfo |
	packages.NeedModule

// loadEnv is the environment for the type-checking load: the same worktree
// posture as the import lister and the symbol probe that measure this tree.
func loadEnv(root string) []string { return goenv.Worktree(os.Environ(), root) }

// load type-checks every package under root, running again under an on-disk
// toolchain when the installed one is older than the tree's go directive, as
// the sibling working-tree children do.
func load(ctx context.Context, root string) ([]*packages.Package, error) {
	toolchains := goenv.NewToolchains()
	defer func() { _ = toolchains.Close() }()
	for {
		cfg := &packages.Config{
			Mode:    loadMode,
			Dir:     root,
			Env:     toolchains.Apply(loadEnv(root)),
			Tests:   true,
			Context: ctx,
		}
		pkgs, err := packages.Load(cfg, "./...")
		if err == nil {
			return pkgs, nil
		}
		retry, refusal := toolchains.Escalate(err.Error())
		if refusal != "" {
			return nil, fmt.Errorf("loading packages: %w\n%s", err, refusal)
		}
		if !retry {
			return nil, fmt.Errorf("loading packages: %w", err)
		}
	}
}

// AnalyseSymbols loads and type-checks all packages in root, then scans
// identifier references to find which exported symbols from external modules
// are used. Both ImportedPackages and UsedSymbols are populated in the result,
// with the entries only test code references marked.
//
// Tests are loaded because a symbol a _test.go file references is referenced.
// Each reference is classified by the file it sits in, not by the package
// variant carrying it: the in-package test variant holds the production
// references too, so classifying it wholesale would move them.
func (a *Analyser) AnalyseSymbols(ctx context.Context, root string) ([]domain.ImportedModule, error) {
	pkgs, err := load(ctx, root)
	if err != nil {
		return nil, err
	}
	// Fatal only when this binary could not read the source: every reference
	// it would report then rests on a type check that never happened.
	if l, ok := analyserLimit(pkgs); ok {
		return nil, &gotoolchain.AnalyserLimitError{Limit: l}
	}
	// Non-fatal: emit partial results on type-check errors. One line per
	// distinct problem, rather than packages.PrintErrors' three lines for one
	// — see reportLoadErrors.
	reportLoadErrors(os.Stderr, root, pkgs)

	// Index external packages: importPath → (modulePath, moduleVersion).
	extPkgToMod := indexExternalPackages(pkgs)

	// Per-module accumulators. Each holds every reference and, separately,
	// those a production file makes; the difference is the test-only set.
	type modData struct {
		version     string
		pkgs        map[string]struct{}
		symbols     map[string]struct{}
		prodPkgs    map[string]struct{}
		prodSymbols map[string]struct{}
	}
	mods := make(map[string]*modData)

	ensure := func(modPath, modVersion string) *modData {
		if d := mods[modPath]; d != nil {
			return d
		}
		d := &modData{
			version:     modVersion,
			pkgs:        make(map[string]struct{}),
			symbols:     make(map[string]struct{}),
			prodPkgs:    make(map[string]struct{}),
			prodSymbols: make(map[string]struct{}),
		}
		mods[modPath] = d
		return d
	}

	// Scan workspace packages for external symbol references.
	for _, pkg := range pkgs {
		if pkg.Module == nil || !pkg.Module.Main || pkg.TypesInfo == nil {
			continue
		}
		for id, obj := range pkg.TypesInfo.Uses {
			if obj == nil || !obj.Exported() {
				continue
			}
			defPkg := obj.Pkg()
			if defPkg == nil {
				continue
			}
			ref, ok := extPkgToMod[defPkg.Path()]
			if !ok {
				continue
			}
			d := ensure(ref.path, ref.version)
			symbol := defPkg.Path() + "." + qualifiedName(obj)
			d.pkgs[defPkg.Path()] = struct{}{}
			d.symbols[symbol] = struct{}{}
			if isTestFile(pkg.Fset, id) {
				continue
			}
			d.prodPkgs[defPkg.Path()] = struct{}{}
			d.prodSymbols[symbol] = struct{}{}
		}
	}

	result := make([]domain.ImportedModule, 0, len(mods))
	for modPath, d := range mods {
		result = append(result, domain.ImportedModule{
			Path:             modPath,
			Version:          d.version,
			ImportedPackages: sortedSet(d.pkgs),
			UsedSymbols:      sortedSet(d.symbols),
			TestOnlyPackages: sortedDifference(d.pkgs, d.prodPkgs),
			TestOnlySymbols:  sortedDifference(d.symbols, d.prodSymbols),
		})
	}
	return result, nil
}

// modRef names the module an external package belongs to.
type modRef struct{ path, version string }

// indexExternalPackages maps each external package reachable from pkgs, test
// variants included, to the module it belongs to.
func indexExternalPackages(pkgs []*packages.Package) map[string]modRef {
	extPkgToMod := make(map[string]modRef)
	visited := make(map[string]bool)
	var indexPkg func(p *packages.Package)
	indexPkg = func(p *packages.Package) {
		// Keyed on ID, not PkgPath: a tested package and its in-package test
		// variant share a PkgPath, so keying on that visits whichever comes
		// first and never walks the other's imports — losing exactly the
		// dependencies only the _test.go files reach.
		if visited[p.ID] {
			return
		}
		visited[p.ID] = true
		if p.Module != nil && !p.Module.Main {
			extPkgToMod[p.PkgPath] = modRef{path: p.Module.Path, version: p.Module.Version}
		}
		for _, imp := range p.Imports {
			indexPkg(imp)
		}
	}
	for _, p := range pkgs {
		indexPkg(p)
	}
	return extPkgToMod
}

// isTestFile reports whether the identifier sits in a _test.go file — the
// file-level definition of test scope the graph commands already use.
//
// An unresolvable position is treated as production: over-reporting a narrowed
// answer is visible, whereas the other default would let --exclude-tests
// silently drop a real production user.
func isTestFile(fset *token.FileSet, id *ast.Ident) bool {
	if fset == nil || id == nil {
		return false
	}
	f := fset.File(id.Pos())
	if f == nil {
		return false
	}
	return strings.HasSuffix(f.Name(), "_test.go")
}

// qualifiedName returns a display name for the object. For methods it prepends
// the receiver type ("ReceiverType.Method"); for other objects just the name.
func qualifiedName(obj types.Object) string {
	fn, ok := obj.(*types.Func)
	if !ok {
		return obj.Name()
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return fn.Name()
	}
	recv := sig.Recv().Type()
	if ptr, ok := recv.(*types.Pointer); ok {
		recv = ptr.Elem()
	}
	if named, ok := recv.(*types.Named); ok {
		return named.Obj().Name() + "." + fn.Name()
	}
	return fn.Name()
}

// sortedDifference returns the sorted members of all that are absent from
// some. Nil when nothing is left over, so an unmarked module carries no empty
// slice.
func sortedDifference(all, some map[string]struct{}) []string {
	var out []string
	for k := range all {
		if _, present := some[k]; !present {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func sortedSet(m map[string]struct{}) []string {
	s := make([]string, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}

// Ensure Analyser implements ports.SymbolAnalyser at compile time.
var _ ports.SymbolAnalyser = (*Analyser)(nil)
