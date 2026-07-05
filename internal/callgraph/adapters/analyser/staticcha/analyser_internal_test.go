package staticcha

import (
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// TestCreateAndBuildSSAPackageSafe_RecoversPanic verifies that
// createAndBuildSSAPackageSafe recovers from the panic that x/tools/go/ssa
// raises when an imported package is not registered with the SSA program
// before Build is called.
func TestCreateAndBuildSSAPackageSafe_RecoversPanic(t *testing.T) {
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
	_, gotErr := createAndBuildSSAPackageSafe(prog, pkga)
	if gotErr == nil {
		t.Fatal("expected an error from unregistered import, got nil")
	}
	if !strings.Contains(gotErr.Error(), "unsatisfied import") {
		t.Errorf("expected 'unsatisfied import' in error message, got: %v", gotErr)
	}
}

// TestCreateAndBuildSSAPackageSafe_NoErrorOnSuccess verifies that
// createAndBuildSSAPackageSafe returns nil when all imports are registered.
func TestCreateAndBuildSSAPackageSafe_NoErrorOnSuccess(t *testing.T) {
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

	ssaPkg, err := createAndBuildSSAPackageSafe(prog, pkgs[0])
	if err != nil {
		t.Fatalf("unexpected error with all deps registered: %v", err)
	}
	if ssaPkg == nil {
		t.Fatal("expected non-nil SSA package")
	}
}
