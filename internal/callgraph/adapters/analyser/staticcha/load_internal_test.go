package staticcha

import (
	"context"
	"fmt"
	"go/token"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"golang.org/x/tools/go/packages"
)

// TestLoadAndBuildSSA_OnePackagePerImportPath pins the invariant the port
// dispatch depends on: the SSA program holds exactly one package per import
// path, so exactly one *types.Package per path exists in the analysis.
//
// go/types decides interface satisfaction by pointer identity. A second copy of
// a package's types — which is what a second go/packages call produces — makes
// types.Implements false between a concrete type from one copy and an interface
// from the other, and CHA then emits no edge for the dispatch. Nothing in the
// resulting record says so: the query layer reports a confident RESOLVED-ABSENT.
// So this is checked structurally rather than only through a symptom, because
// the symptom is by nature invisible.
func TestLoadAndBuildSSA_OnePackagePerImportPath(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	const modPath = "example.com/loadmod"
	write("go.mod", "module "+modPath+"\n\ngo 1.21\n")
	// A chain of packages long enough that any batched loader would have to
	// split it, with each link importing the previous one so a split guarantees
	// a re-load of the earlier links as dependencies.
	const chain = 25
	for i := range chain {
		body := fmt.Sprintf("package p%02d\n\nfunc N() int { return %d }\n", i, i)
		if i > 0 {
			body = fmt.Sprintf("package p%02d\n\nimport prev %q\n\nfunc N() int { return prev.N() + %d }\n",
				i, fmt.Sprintf("%s/p%02d", modPath, i-1), i)
		}
		write(fmt.Sprintf("p%02d/p%02d.go", i, i), body)
	}

	coord, err := coordinate.NewModuleCoordinate(modPath, "v0.0.0")
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}

	a := New("0.1.0", "", slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	fset, cleanup, targets := loadTargets(t, a, dir, coord)
	defer cleanup()

	build, err := a.loadAndBuildSSA(context.Background(), fset, dir, coord, targets, isolatedModuleEnv())
	if err != nil {
		t.Skipf("go/packages could not load the test module: %v", err)
	}
	if build.Registered() == 0 {
		t.Skipf("no packages built; load errors: %v", build.LoadErrs)
	}

	// A package with test files is legitimately type-checked twice — as itself
	// and as its test variant — so the count is taken over production packages,
	// where a second copy can only be a second load.
	countByPath := make(map[string]int)
	for _, p := range build.TargetPkgs {
		if p != nil && p.Pkg != nil {
			countByPath[p.Pkg.Path()]++
		}
	}
	var dupes []string
	for path, n := range countByPath {
		if n > 1 {
			dupes = append(dupes, fmt.Sprintf("%s x%d", path, n))
		}
	}
	if len(dupes) > 0 {
		t.Fatalf("import paths registered more than once in the SSA program: %s", strings.Join(dupes, ", "))
	}
	if got := len(build.TargetPkgs); got != chain {
		t.Errorf("built %d target packages, want %d", got, chain)
	}
}

// loadTargets discovers the module's own package paths the way analyseDir does,
// returning the shared FileSet the caller must reuse.
func loadTargets(t *testing.T, a *Analyser, dir string, coord coordinate.ModuleCoordinate) (fset *token.FileSet, cleanup func(), targets []string) {
	t.Helper()
	fset = token.NewFileSet()
	envCleanup, err := a.setupGoEnv(context.Background())
	if err != nil {
		t.Skipf("no usable Go environment: %v", err)
	}
	pkgsMeta, err := packages.Load(&packages.Config{
		Mode:    packages.NeedName | packages.NeedImports | packages.NeedDeps,
		Dir:     dir,
		Context: context.Background(),
		Env:     isolatedModuleEnv(),
		Tests:   false,
	}, "./...")
	if err != nil {
		envCleanup()
		t.Skipf("meta load failed: %v", err)
	}
	packages.Visit(pkgsMeta, nil, func(p *packages.Package) {
		if p.PkgPath == coord.Path() || strings.HasPrefix(p.PkgPath, coord.Path()+"/") {
			targets = append(targets, p.PkgPath)
		}
	})
	return fset, envCleanup, targets
}
