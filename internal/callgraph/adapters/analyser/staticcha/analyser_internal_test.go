package staticcha

import (
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// TestBuildSSAPackageSafe_RecoversPanic verifies that buildSSAPackageSafe
// recovers from the panic that x/tools/go/ssa raises when an imported package is
// not registered with the SSA program before Build is called.
func TestBuildSSAPackageSafe_RecoversPanic(t *testing.T) {
	tmpDir := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(tmpDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	write("go.mod", "module example.com/testmod\n\ngo 1.21\n")
	write("pkgb/pkgb.go", "package pkgb\n\ntype Value int\n")
	write("pkga/pkga.go", `package pkga

import "example.com/testmod/pkgb"

// Get returns a pkgb.Value, ensuring the import is used at the types level.
func Get() pkgb.Value { return 42 }
`)

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedSyntax | packages.NeedTypes |
			packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps,
		Dir:   tmpDir,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./pkga")
	if err != nil {
		t.Skipf("packages.Load failed (no Go env?): %v", err)
	}
	if len(pkgs) == 0 || pkgs[0].Types == nil {
		t.Skip("go/packages could not load test module; skipping")
	}
	pkga := pkgs[0]

	// Create an SSA program but deliberately omit registering pkga's imports.
	// This reproduces the condition where a transitive dependency's
	// *types.Package is absent from the program — triggering the Build panic.
	fset := token.NewFileSet()
	prog := ssa.NewProgram(fset, ssa.BuilderMode(0))

	// Without the fix, Build panics; with it we get a descriptive error.
	ssaPkg, cerr := createSSAPackageSafe(prog, pkga, true)
	if cerr != nil {
		t.Fatalf("creating SSA package: %v", cerr)
	}
	gotErr := buildSSAPackageSafe(ssaPkg)
	if gotErr == nil {
		t.Fatal("expected an error from unregistered import, got nil")
	}
	if !strings.Contains(gotErr.Error(), "unsatisfied import") {
		t.Errorf("expected 'unsatisfied import' in error message, got: %v", gotErr)
	}
}

// TestBuildSSAPackageSafe_NoErrorOnSuccess verifies that create-then-build
// returns nil when all imports are registered.
func TestBuildSSAPackageSafe_NoErrorOnSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(tmpDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	write("go.mod", "module example.com/testmod\n\ngo 1.21\n")
	write("pkgb/pkgb.go", "package pkgb\n\ntype Value int\n")
	write("pkga/pkga.go", `package pkga

import "example.com/testmod/pkgb"

func Get() pkgb.Value { return 42 }
`)

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedSyntax | packages.NeedTypes |
			packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps,
		Dir:   tmpDir,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./pkga")
	if err != nil {
		t.Skipf("packages.Load failed (no Go env?): %v", err)
	}
	if len(pkgs) == 0 || pkgs[0].Types == nil {
		t.Skip("go/packages could not load test module; skipping")
	}

	fset := token.NewFileSet()
	prog := ssa.NewProgram(fset, ssa.BuilderMode(0))

	// Register all transitive dependencies before building — the correct path.
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.Types != nil && prog.Package(p.Types) == nil {
			prog.CreatePackage(p.Types, nil, nil, true)
		}
	})

	ssaPkg, err := createSSAPackageSafe(prog, pkgs[0], true)
	if err != nil {
		t.Fatalf("unexpected error creating SSA package: %v", err)
	}
	if ssaPkg == nil {
		t.Fatal("expected non-nil SSA package")
	}
	if err := buildSSAPackageSafe(ssaPkg); err != nil {
		t.Fatalf("unexpected error with all deps registered: %v", err)
	}
}

// TestArtifactKind_SkipsIncompletePackages covers the defensive guards in
// artifactKind: a batch of SSA packages can contain a nil entry (a package that
// failed to build) and a partially-initialised one. Neither may panic, and
// neither counts as evidence of a command.
func TestArtifactKind_SkipsIncompletePackages(t *testing.T) {
	if got := artifactKind(nil); got != domain.ArtifactLibrary {
		t.Errorf("artifactKind(nil) = %q, want library", got)
	}
	pkgs := []*ssa.Package{nil, {}}
	if got := artifactKind(pkgs); got != domain.ArtifactLibrary {
		t.Errorf("artifactKind = %q, want library", got)
	}
}

// TestArtifactKind_MainPackageWithoutMainFunc pins the "defines func main"
// half of the rule: a package merely named main is not a command until it has
// a main function to enter.
func TestArtifactKind_MainPackageWithoutMainFunc(t *testing.T) {
	prog := ssa.NewProgram(token.NewFileSet(), ssa.BuilderMode(0))
	pkg := prog.CreatePackage(types.NewPackage("example.com/cmd/x", "main"), nil, nil, false)
	if got := artifactKind([]*ssa.Package{pkg}); got != domain.ArtifactLibrary {
		t.Errorf("artifactKind = %q, want library for a main package with no func main", got)
	}
}
