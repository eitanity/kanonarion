package staticcha

import (
	"archive/zip"
	"context"
	"fmt"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

func (a *Analyser) loadAndBuildSSA(ctx context.Context, fset *token.FileSet, tempDir string, coord fetchdomain.ModuleCoordinate, targetPkgPaths []string) (prog *ssa.Program, targetSSAPkgs []*ssa.Package, allLoadErrs []string, err error) {
	prog = ssa.NewProgram(fset, ssa.BuilderMode(0))

	// Step 2: Load ALL types.Packages (NeedTypes) but NO ASTs.
	cfgTypes := &packages.Config{
		Mode:    packages.NeedName | packages.NeedTypes | packages.NeedImports | packages.NeedDeps,
		Dir:     tempDir,
		Context: ctx,
		Tests:   false,
	}
	if _, err := packages.Load(cfgTypes, "./..."); err != nil {
		return nil, nil, nil, fmt.Errorf("types load: %w", err)
	}
	a.logMem(ctx, "types_loaded")

	// Step 3: Batched Syntax Loading for target packages.
	batchSize := 20
	for i := 0; i < len(targetPkgPaths); i += batchSize {
		end := i + batchSize
		if end > len(targetPkgPaths) {
			end = len(targetPkgPaths)
		}

		batchPatterns := targetPkgPaths[i:end]
		cfgFull := &packages.Config{
			Mode:    packages.NeedName | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedFiles | packages.NeedImports | packages.NeedDeps,
			Dir:     tempDir,
			Context: ctx,
			Fset:    fset,
			Tests:   false,
		}

		// Aggressive GC tuning for the batch load
		oldGOGC := os.Getenv("GOGC")
		_ = os.Setenv("GOGC", "30")
		batchPkgs, bErr := packages.Load(cfgFull, batchPatterns...)
		_ = os.Setenv("GOGC", oldGOGC)

		if bErr != nil {
			allLoadErrs = append(allLoadErrs, fmt.Sprintf("batch %d load failed: %v", i/batchSize, bErr))
			continue
		}

		for _, p := range batchPkgs {
			for _, e := range p.Errors {
				allLoadErrs = append(allLoadErrs, e.Error())
			}

			if p.Types == nil {
				continue
			}

			// Ensure all dependencies (transitive) are registered first
			packages.Visit([]*packages.Package{p}, nil, func(dp *packages.Package) {
				if dp.Types != nil && prog.Package(dp.Types) == nil {
					prog.CreatePackage(dp.Types, nil, nil, true)
				}
			})

			// Create the target package with syntax and build it.
			// Both steps can panic: CreatePackage on nil TypesInfo entries,
			// Build on unregistered imports. createAndBuildSSAPackageSafe
			// recovers from either.
			ssaPkg, berr := createAndBuildSSAPackageSafe(prog, p)
			if berr != nil {
				allLoadErrs = append(allLoadErrs, fmt.Sprintf("SSA construction panic for %s: %v", p.PkgPath, berr))
				continue
			}
			if ssaPkg == nil {
				continue
			}
			targetSSAPkgs = append(targetSSAPkgs, ssaPkg)

			// Discard heavy AST data immediately
			p.Syntax = nil
			p.TypesInfo = nil
		}

		runtime.GC()
		a.logMem(ctx, fmt.Sprintf("batch_%d_processed", i/batchSize))
	}

	return prog, targetSSAPkgs, allLoadErrs, nil
}

// extractModuleZip extracts files from a Go module proxy zip to destDir,
// stripping the modulePrefix ("module@version/") from every entry.
func extractModuleZip(zipPath string, modulePrefix, destDir string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("opening zip: %w", err)
	}
	defer func() {
		_ = zr.Close()
	}()
	for _, f := range zr.File {
		rel := strings.TrimPrefix(f.Name, modulePrefix)
		if rel == "" || rel == f.Name {
			continue
		}
		// Guard against path traversal.
		if strings.Contains(rel, "..") {
			continue
		}
		destPath := filepath.Join(destDir, filepath.FromSlash(rel))
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(destPath, 0o750); err != nil { //nolint:gosec // temp dir owned by current user
				return fmt.Errorf("creating dir %s: %w", rel, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(destPath), 0o750); err != nil { //nolint:gosec // temp dir owned by current user
			return fmt.Errorf("creating parent for %s: %w", rel, err)
		}
		if err := extractZipEntry(f, destPath); err != nil {
			return fmt.Errorf("extracting %s: %w", rel, err)
		}
	}
	return nil
}
func extractZipEntry(f *zip.File, destPath string) (retErr error) {
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("opening zip entry: %w", err)
	}
	defer func() {
		if cerr := rc.Close(); cerr != nil && retErr == nil {
			retErr = cerr
		}
	}()
	out, err := os.Create(destPath) /* #nosec G304 -- destPath sanitized against traversal in extractModuleZip */
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer func() {
		if cerr := out.Close(); cerr != nil && retErr == nil {
			retErr = cerr
		}
	}()
	if _, err := io.Copy(out, rc); err != nil { /* #nosec G110 -- zip sourced from Go module proxy, size already bounded by fetch stage */
		return fmt.Errorf("writing file content: %w", err)
	}
	return nil
}

// createAndBuildSSAPackageSafe calls prog.CreatePackage and then Build,
// recovering from any panic either step raises. Two distinct panics are known:
// - CreatePackage: nil dereference when TypesInfo contains nil-typed declarations
// - Build: "unsatisfied import" when a dependency's *types.Package was not
// registered with the program (happens when a dep had nil Types during loading)
//
// Returns (nil, nil) if CreatePackage returns nil (package already registered).
func createAndBuildSSAPackageSafe(prog *ssa.Program, p *packages.Package) (pkg *ssa.Package, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("%v", r)
		}
	}()
	pkg = prog.CreatePackage(p.Types, p.Syntax, p.TypesInfo, true)
	if pkg != nil {
		pkg.Build()
	}
	return pkg, nil
}
