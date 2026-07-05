// Package gopackages implements ports.SymbolAnalyser using go/packages
// type-checking to identify which exported symbols from dependency packages
// are referenced by the local workspace (~2-5s).
package gopackages

import (
	"context"
	"fmt"
	"go/types"
	"sort"

	"golang.org/x/tools/go/packages"

	"github.com/eitanity/kanonarion/internal/local/domain"
	"github.com/eitanity/kanonarion/internal/local/ports"
)

// Analyser implements ports.SymbolAnalyser using go/packages.
type Analyser struct{}

// New constructs an Analyser.
func New() *Analyser { return &Analyser{} }

const loadMode = packages.NeedName |
	packages.NeedImports |
	packages.NeedTypes |
	packages.NeedTypesInfo |
	packages.NeedModule

// AnalyseSymbols loads and type-checks all packages in root, then scans
// identifier references to find which exported symbols from external modules
// are used. Both ImportedPackages and UsedSymbols are populated in the result.
func (a *Analyser) AnalyseSymbols(ctx context.Context, root string) ([]domain.ImportedModule, error) {
	cfg := &packages.Config{
		Mode:    loadMode,
		Dir:     root,
		Context: ctx,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, fmt.Errorf("loading packages: %w", err)
	}
	// Non-fatal: emit partial results on type-check errors.
	packages.PrintErrors(pkgs)

	// Index external packages: importPath → (modulePath, moduleVersion).
	type modRef struct{ path, version string }
	extPkgToMod := make(map[string]modRef)
	visited := make(map[string]bool)
	var indexPkg func(p *packages.Package)
	indexPkg = func(p *packages.Package) {
		if visited[p.PkgPath] {
			return
		}
		visited[p.PkgPath] = true
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

	// Per-module accumulators.
	type modData struct {
		version string
		pkgs    map[string]struct{}
		symbols map[string]struct{}
	}
	mods := make(map[string]*modData)

	ensure := func(modPath, modVersion string) *modData {
		if d := mods[modPath]; d != nil {
			return d
		}
		d := &modData{version: modVersion, pkgs: make(map[string]struct{}), symbols: make(map[string]struct{})}
		mods[modPath] = d
		return d
	}

	// Scan workspace packages for external symbol references.
	for _, pkg := range pkgs {
		if pkg.Module == nil || !pkg.Module.Main || pkg.TypesInfo == nil {
			continue
		}
		for _, obj := range pkg.TypesInfo.Uses {
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
			d.pkgs[defPkg.Path()] = struct{}{}
			d.symbols[defPkg.Path()+"."+qualifiedName(obj)] = struct{}{}
		}
	}

	result := make([]domain.ImportedModule, 0, len(mods))
	for modPath, d := range mods {
		result = append(result, domain.ImportedModule{
			Path:             modPath,
			Version:          d.version,
			ImportedPackages: sortedSet(d.pkgs),
			UsedSymbols:      sortedSet(d.symbols),
		})
	}
	return result, nil
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
