// Package golist implements ports.ImportAnalyser by running go list -json -deps
// against the workspace directory and grouping imported packages by module.
package golist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"

	"github.com/eitanity/kanonarion/internal/goenv"
	"github.com/eitanity/kanonarion/internal/local/domain"
	"github.com/eitanity/kanonarion/internal/local/ports"
)

// Analyser implements ports.ImportAnalyser using go list -json -deps.
type Analyser struct {
	goBinary string // empty → resolved via PATH as "go"
}

// New constructs an Analyser. goBinary may be empty (uses "go" from PATH).
func New(goBinary string) *Analyser {
	return &Analyser{goBinary: goBinary}
}

func (a *Analyser) goBin() string {
	if a.goBinary == "" {
		return "go"
	}
	return a.goBinary
}

// listEnv is the environment for the go list children. It is the same
// resolution the call-graph load of this tree runs under; these children were
// inheriting the caller's instead, so one command answered two build questions.
func listEnv(root string) []string { return goenv.Worktree(os.Environ(), root) }

// goListPackage mirrors the fields we need from `go list -json`.
type goListPackage struct {
	ImportPath string
	Standard   bool
	// Imports are the packages directly imported by this package's non-test files.
	Imports []string
	Module  *struct {
		Path    string
		Version string
		Main    bool
	}
}

// AnalyseImports runs go list -json -deps./... in root and returns one
// ImportedModule per external dependency module that the workspace imports.
func (a *Analyser) AnalyseImports(ctx context.Context, root string) ([]domain.ImportedModule, error) {
	cmd := exec.CommandContext(ctx, a.goBin(), "list", "-json", "-deps", "./...") // #nosec G204 -- binary path is either "go" (hardcoded) or caller-supplied and trusted
	cmd.Dir = root
	cmd.Env = listEnv(root)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			return nil, fmt.Errorf("go list: %w\n%s", err, exitErr.Stderr)
		}
		return nil, fmt.Errorf("go list: %w", err)
	}

	pkgs, err := parseGoListOutput(out)
	if err != nil {
		return nil, err
	}

	// Build a map from import path → module info for external packages.
	type modInfo struct {
		path, version string
	}
	pkgToMod := make(map[string]modInfo, len(pkgs))
	workspacePkgs := make(map[string][]string) // importPath → imports

	for _, pkg := range pkgs {
		if pkg.Standard || pkg.Module == nil {
			continue
		}
		if pkg.Module.Main {
			// Workspace package: capture its imports.
			workspacePkgs[pkg.ImportPath] = pkg.Imports
			continue
		}
		pkgToMod[pkg.ImportPath] = modInfo{path: pkg.Module.Path, version: pkg.Module.Version}
	}

	// Collect external packages imported by any workspace package.
	imported := make(map[string]map[string]struct{}) // modulePath → set of pkg importPaths
	for _, imports := range workspacePkgs {
		for _, imp := range imports {
			mod, ok := pkgToMod[imp]
			if !ok {
				continue
			}
			if imported[mod.path] == nil {
				imported[mod.path] = make(map[string]struct{})
			}
			imported[mod.path][imp] = struct{}{}
		}
	}

	// Build the module version index.
	modVersions := make(map[string]string)
	for _, info := range pkgToMod {
		if _, seen := modVersions[info.path]; !seen {
			modVersions[info.path] = info.version
		}
	}

	mods := make([]domain.ImportedModule, 0, len(imported))
	for modPath, pkgSet := range imported {
		pkgs := make([]string, 0, len(pkgSet))
		for p := range pkgSet {
			pkgs = append(pkgs, p)
		}
		sort.Strings(pkgs)
		mods = append(mods, domain.ImportedModule{
			Path:             modPath,
			Version:          modVersions[modPath],
			ImportedPackages: pkgs,
		})
	}

	return mods, nil
}

// BuildModules runs the same `go list -json -deps ./...` and projects it onto
// every non-main module the build resolves, direct and transitive alike.
//
// It is a second projection of one command rather than a filter applied to
// AnalyseImports' result, because AnalyseImports discards the transitive
// modules before it returns: they are exactly the entries missing from its
// output, and no consumer can reconstruct them from what it kept.
func (a *Analyser) BuildModules(ctx context.Context, root string) ([]domain.BuildModule, error) {
	cmd := exec.CommandContext(ctx, a.goBin(), "list", "-json", "-deps", "./...") // #nosec G204 -- binary path is either "go" (hardcoded) or caller-supplied and trusted
	cmd.Dir = root
	cmd.Env = listEnv(root)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			return nil, fmt.Errorf("go list: %w\n%s", err, exitErr.Stderr)
		}
		return nil, fmt.Errorf("go list: %w", err)
	}

	pkgs, err := parseGoListOutput(out)
	if err != nil {
		return nil, err
	}

	// Which module each external package belongs to, and which packages the main
	// module's own non-test files import — the latter only to mark directness,
	// never to decide membership.
	pkgToMod := make(map[string]string, len(pkgs))
	mods := make(map[string]domain.BuildModule)
	var mainImports []string
	for _, pkg := range pkgs {
		if pkg.Standard || pkg.Module == nil {
			continue
		}
		if pkg.Module.Main {
			mainImports = append(mainImports, pkg.Imports...)
			continue
		}
		pkgToMod[pkg.ImportPath] = pkg.Module.Path
		if _, seen := mods[pkg.Module.Path]; !seen {
			mods[pkg.Module.Path] = domain.BuildModule{Path: pkg.Module.Path, Version: pkg.Module.Version}
		}
	}
	for _, imp := range mainImports {
		if modPath, ok := pkgToMod[imp]; ok {
			m := mods[modPath]
			m.Direct = true
			mods[modPath] = m
		}
	}

	out2 := make([]domain.BuildModule, 0, len(mods))
	for _, m := range mods {
		out2 = append(out2, m)
	}
	sort.Slice(out2, func(i, j int) bool { return out2[i].Path < out2[j].Path })
	return out2, nil
}

func parseGoListOutput(data []byte) ([]goListPackage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var pkgs []goListPackage
	for {
		var pkg goListPackage
		if err := dec.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("parsing go list output: %w", err)
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs, nil
}

// Ensure Analyser implements both projections at compile time.
var (
	_ ports.ImportAnalyser    = (*Analyser)(nil)
	_ ports.BuildModuleLister = (*Analyser)(nil)
)
