package staticcha

import (
	"archive/zip"
	"context"
	"fmt"
	"go/token"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// loadAndBuildSSA type-checks every target package in one go/packages call and
// builds SSA for it.
//
// The single call is a correctness requirement, not a convenience. go/packages
// mints a fresh set of *types.Package objects per Load, and go/types compares
// types by pointer identity: a concrete type from one Load never satisfies
// types.Implements against an interface from another. Loading the target set in
// batches therefore populated the ssa.Program with one copy of most packages per
// batch, and CHA's implements relation — which is how every interface dispatch
// is bound — silently failed across the seam. Whether a port method resolved its
// callers came down to whether the interface and its implementer happened to
// land in the same batch, which is why a store adapter could return callers for
// one method and RESOLVED-ABSENT for its sibling. The batching also cost more
// than it saved: each batch re-type-checked the whole transitive dependency set
// from scratch, and the ssa.Program retained every duplicate for the life of the
// analysis.
//
// Test files are part of the target set. A module's fakes and table-driven
// callers are a large, systematic share of what a signature change has to
// touch, and omitting them made "no callers" a confident false negative for
// every test-only consumer. The outcome of that decision is recorded on the
// result so a query can state it rather than imply coverage it does not have.
func (a *Analyser) loadAndBuildSSA(ctx context.Context, fset *token.FileSet, tempDir string, coord coordinate.ModuleCoordinate, targetPkgPaths []string) (ssaBuildResult, error) {
	res := ssaBuildResult{
		Prog:      ssa.NewProgram(fset, ssa.BuilderMode(0)),
		TestPkgs:  map[*ssa.Package]bool{},
		TestScope: domain.TestScopeAnalysed,
	}

	// failedSet accumulates target package import paths whose typecheck or SSA
	// construction failed. It is the machine-readable companion to LoadErrs:
	// verdicts over the resulting Partial graph are caveated per package, not by
	// node/edge totals.
	failedSet := make(map[string]bool)
	markFailed := func(pkgPath string) {
		if pkgPath != "" {
			failedSet[pkgPath] = true
		}
	}

	if len(targetPkgPaths) == 0 {
		return res, nil
	}

	const fullMode = packages.NeedName | packages.NeedSyntax | packages.NeedTypes |
		packages.NeedTypesInfo | packages.NeedFiles | packages.NeedImports | packages.NeedDeps

	load := func(withTests bool) ([]*packages.Package, error) {
		cfg := &packages.Config{
			Mode:    fullMode,
			Dir:     tempDir,
			Context: ctx,
			Env:     isolatedModuleEnv(),
			Fset:    fset,
			Tests:   withTests,
		}
		// Aggressive GC tuning: the ASTs of the whole target module are live at
		// once between the load returning and the last package being built.
		oldGOGC := os.Getenv("GOGC")
		_ = os.Setenv("GOGC", "30")
		pkgs, lErr := packages.Load(cfg, targetPkgPaths...)
		_ = os.Setenv("GOGC", oldGOGC)
		if lErr != nil {
			return nil, fmt.Errorf("syntax load: %w", lErr)
		}
		return pkgs, nil
	}

	loaded, lErr := load(true)
	if lErr != nil {
		// Loading with tests is not viable for this module. Retry without them
		// rather than lose the graph entirely — but record the exclusion, so the
		// query layer names the axis it could not measure instead of reporting a
		// clean absence over it.
		a.logger.WarnContext(ctx, "callgraph_test_scope_excluded",
			slog.String("module", coord.Path()),
			slog.String("error", lErr.Error()),
		)
		res.TestScope = domain.TestScopeExcluded
		res.TestScopeDetail = "loading the module with test files failed: " + lErr.Error()
		var retryErr error
		loaded, retryErr = load(false)
		if retryErr != nil {
			return res, retryErr
		}
	}
	a.logMem(ctx, "syntax_loaded")

	// Pass 1: register every target package from syntax. This must complete
	// before any Build, and before the type-only dependency sweep below: a
	// target registered type-only (because a sibling target imports it) would be
	// the copy that sibling's build binds to, and its method bodies would be
	// invisible for the rest of the analysis.
	//
	// With tests enabled go/packages returns up to three packages per target:
	// the production package, the internal test variant (same import path, extra
	// _test.go files), and the external test package. The synthetic test-binary
	// main is skipped — it is generated code, and its package main would
	// otherwise make every library look like an application to the rooting rule.
	var built []*ssa.Package
	for _, p := range loaded {
		if isSyntheticTestMain(p) {
			continue
		}
		for _, e := range p.Errors {
			res.LoadErrs = append(res.LoadErrs, e.Error())
		}
		if len(p.Errors) > 0 {
			markFailed(p.PkgPath)
		}
		if p.Types == nil {
			markFailed(p.PkgPath)
			continue
		}
		if res.Prog.Package(p.Types) != nil {
			// Already registered from syntax: the pattern list named this
			// package twice.
			continue
		}
		testPkg := isTestPackage(p)
		// A test variant is registered but not importable: production code never
		// imports it, and leaving the importable slot to the production package
		// keeps ImportedPackage answering with the package consumers see.
		ssaPkg, cerr := createSSAPackageSafe(res.Prog, p, !testPkg)
		if cerr != nil {
			res.LoadErrs = append(res.LoadErrs, fmt.Sprintf("SSA package creation panic for %s: %v", p.PkgPath, cerr))
			markFailed(p.PkgPath)
			continue
		}
		built = append(built, ssaPkg)
		if testPkg {
			res.TestPkgs[ssaPkg] = true
		} else {
			res.TargetPkgs = append(res.TargetPkgs, ssaPkg)
		}
	}

	// Pass 2: register the transitive dependencies that are not targets. They
	// carry no syntax, so their method bodies are absent by design; the
	// single-implementer devirtualisation pass recovers the dispatch edges CHA
	// drops for them.
	for _, p := range loaded {
		packages.Visit([]*packages.Package{p}, nil, func(dp *packages.Package) {
			if dp.Types != nil && res.Prog.Package(dp.Types) == nil {
				res.Prog.CreatePackage(dp.Types, nil, nil, true)
			}
		})
	}
	a.logMem(ctx, "packages_registered")

	// Pass 3: build. Every package the builder can reach is registered now, so
	// no build resolves a callee through a placeholder.
	//
	// BodiesBuilt counts the packages that came through with bodies. It is the
	// difference between "we had types but no bodies" and "we had neither", and
	// that difference is only knowable here: downstream, a program with registered
	// packages and no built bodies is indistinguishable from one built from
	// metadata. Recording it is what gives CompletenessTypeOnly a producer.
	for _, ssaPkg := range built {
		if berr := buildSSAPackageSafe(ssaPkg); berr != nil {
			path := ""
			if ssaPkg.Pkg != nil {
				path = ssaPkg.Pkg.Path()
			}
			res.LoadErrs = append(res.LoadErrs, fmt.Sprintf("SSA construction panic for %s: %v", path, berr))
			markFailed(path)
			continue
		}
		res.BodiesBuilt++
	}
	// The ASTs and type info are held only until the packages that need them are
	// built; ssa keeps its own references while building and drops them after.
	for _, p := range loaded {
		p.Syntax = nil
		p.TypesInfo = nil
	}
	runtime.GC()
	a.logMem(ctx, "ssa_built")

	if len(failedSet) > 0 {
		res.FailedPkgs = make([]string, 0, len(failedSet))
		for p := range failedSet {
			res.FailedPkgs = append(res.FailedPkgs, p)
		}
		sort.Strings(res.FailedPkgs)
	}

	return res, nil
}

// ssaBuildResult is the outcome of loading and building a module's packages.
type ssaBuildResult struct {
	Prog *ssa.Program
	// TargetPkgs are the module's production packages. artifactKind reads only
	// these: a test binary's generated main must not make a library look like a
	// command.
	TargetPkgs []*ssa.Package
	// TestPkgs is the set of built packages that carry the module's _test.go
	// declarations — the internal test variants and the external test packages.
	TestPkgs map[*ssa.Package]bool
	// BodiesBuilt is how many of the registered packages had SSA construction
	// complete without panicking, i.e. how many carry function bodies. Zero with
	// a non-zero Registered() is the TYPE_ONLY state: the packages type-checked
	// and are known to the program, but no body was ever built from them.
	BodiesBuilt     int
	LoadErrs        []string
	FailedPkgs      []string
	TestScope       domain.TestScope
	TestScopeDetail string
}

// Registered returns every package registered from syntax, production and test
// alike. Registration means the package type-checked and its *types.Package
// joined the SSA program; it does not mean its bodies were built — see
// BodiesBuilt.
func (r ssaBuildResult) Registered() int { return len(r.TargetPkgs) + len(r.TestPkgs) }

// isSyntheticTestMain reports whether p is the test binary main go/packages
// synthesises for a package under test. Its import path is the package path
// with a ".test" suffix and it contains no source of the module's own.
func isSyntheticTestMain(p *packages.Package) bool {
	return strings.HasSuffix(p.PkgPath, ".test")
}

// isTestPackage reports whether p carries _test.go declarations: either the
// external test package (import path suffixed "_test") or the internal test
// variant, which go/packages distinguishes from the production package by ID
// while keeping the same import path.
func isTestPackage(p *packages.Package) bool {
	return strings.HasSuffix(p.PkgPath, "_test") || p.ID != p.PkgPath
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

// createSSAPackageSafe calls prog.CreatePackage, recovering from the known
// panic: a nil dereference when TypesInfo contains nil-typed declarations.
//
// Creation is separated from Build so every package in the analysis can be
// registered before any of them is built — see loadAndBuildSSA.
func createSSAPackageSafe(prog *ssa.Program, p *packages.Package, importable bool) (pkg *ssa.Package, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("%v", r)
		}
	}()
	return prog.CreatePackage(p.Types, p.Syntax, p.TypesInfo, importable), nil
}

// buildSSAPackageSafe calls Build on an already-created package, recovering from
// the known panic: "unsatisfied import" when a dependency's *types.Package was
// never registered with the program (a dep that had nil Types during loading).
func buildSSAPackageSafe(pkg *ssa.Package) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("%v", r)
		}
	}()
	if pkg != nil {
		pkg.Build()
	}
	return nil
}
