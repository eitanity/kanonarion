package govulncheck

import (
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// A module zip nests its content under a "path@version/" prefix, so the
// extraction root is not the module root. Writing go.mod at the extraction root
// would describe a directory holding no Go source, and govulncheck would match
// no packages.
func TestModuleRoot_DescendsZipPrefixToTheSourceDirectory(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "github.com", "boltdb", "bolt@v1.3.1")
	if err := os.MkdirAll(src, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "db.go"), []byte("package bolt\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := moduleRoot(root)
	if err != nil {
		t.Fatalf("moduleRoot: %v", err)
	}
	if got != src {
		t.Errorf("moduleRoot() = %q, want %q", got, src)
	}
}

// A module whose root holds no Go source of its own still roots at the first
// level that branches, not at the deepest single-child directory.
func TestModuleRoot_StopsWhereTheTreeBranches(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "example.com", "mod@v1.0.0")
	for _, pkg := range []string{"alpha", "beta"} {
		if err := os.MkdirAll(filepath.Join(base, pkg), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	got, err := moduleRoot(root)
	if err != nil {
		t.Fatalf("moduleRoot: %v", err)
	}
	if got != base {
		t.Errorf("moduleRoot() = %q, want %q", got, base)
	}
}

func TestWriteSynthesisedGoMod_WritesToTheModuleRoot(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "github.com", "boltdb", "bolt@v1.3.1")
	if err := os.MkdirAll(src, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// The source must import the dependency: requires are selected from what the
	// module actually imports, not from the whole build list.
	if err := os.WriteFile(filepath.Join(src, "db.go"), []byte("package bolt\n\nimport _ \"example.com/dep/sub\"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	coord := coordinate.ModuleCoordinate{Path: "github.com/boltdb/bolt", Version: "v1.3.1"}
	dir, skipped, err := writeSynthesisedGoMod(root, coord, "go1.26.5", map[coordinate.ModuleCoordinate]struct{}{
		{Path: "example.com/dep", Version: "v0.3.0"}:    {},
		{Path: "example.com/unused", Version: "v9.9.9"}: {},
	})
	if err != nil {
		t.Fatalf("writeSynthesisedGoMod: %v", err)
	}
	if len(skipped) != 0 {
		t.Errorf("skipped = %v, want none: every file in this fixture parses", skipped)
	}
	if dir != src {
		t.Errorf("returned scan dir = %q, want %q", dir, src)
	}
	content, err := os.ReadFile(filepath.Join(src, "go.mod")) //nolint:gosec // path built from t.TempDir
	if err != nil {
		t.Fatalf("reading synthesised go.mod: %v", err)
	}
	for _, want := range []string{"module github.com/boltdb/bolt", "go 1.26.5", "example.com/dep v0.3.0"} {
		if !strings.Contains(string(content), want) {
			t.Errorf("synthesised go.mod missing %q, got:\n%s", want, content)
		}
	}
	if strings.Contains(string(content), "example.com/unused") {
		t.Errorf("an unimported build-list entry must not be required, got:\n%s", content)
	}
}

// Synthesis runs only when the zip carried no go.mod. Refusing to overwrite
// keeps that guarantee checkable here rather than resting on the caller, so a
// future caller cannot silently replace a published module's own requirements.
func TestWriteSynthesisedGoMod_RefusesToOverwriteAnExistingGoMod(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "example.com", "mod@v1.0.0")
	if err := os.MkdirAll(src, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	original := "module example.com/mod\n\ngo 1.19\n"
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte(original), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	coord := coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
	if _, _, err := writeSynthesisedGoMod(root, coord, "go1.26.5", nil); err == nil {
		t.Fatal("expected an error when a go.mod already exists")
	}
	after, err := os.ReadFile(filepath.Join(src, "go.mod")) //nolint:gosec // path built from t.TempDir
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	if string(after) != original {
		t.Errorf("existing go.mod was modified:\n%s", after)
	}
}

func TestCollectImports_SkipsStdlibAndTestFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "inner"), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	write := func(rel, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, rel), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	write("a.go", "package a\n\nimport (\n\t\"fmt\"\n\t\"os/exec\"\n\t\"github.com/gorilla/css/scanner\"\n)\n")
	write("inner/b.go", "package b\n\nimport \"golang.org/x/net/html\"\n")
	// Test-only imports must not become requirements: govulncheck does not load
	// test files, so a test helper absent from the build list would otherwise
	// fail a module whose real packages resolve.
	write("a_test.go", "package a\n\nimport \"gotest.tools/v3/assert\"\n")

	got, skipped := collectImports(root)
	if len(skipped) != 0 {
		t.Errorf("skipped = %v, want none: every file in this fixture parses", skipped)
	}
	want := []string{"github.com/gorilla/css/scanner", "golang.org/x/net/html"}
	if len(got) != len(want) {
		t.Fatalf("collectImports() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("collectImports()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// An unparseable file must not fail the scan: it contributes no imports, the
// rest of the module still does, and the file is returned so the caller can
// report that the require set was built from less than the whole module.
func TestCollectImports_ToleratesUnparseableFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "broken.go"), []byte("this is not go"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "ok.go"), []byte("package a\n\nimport \"example.com/dep\"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, skipped := collectImports(root)
	if len(got) != 1 || got[0] != "example.com/dep" {
		t.Errorf("collectImports() = %v, want [example.com/dep]", got)
	}
	if len(skipped) != 1 || filepath.Base(skipped[0]) != "broken.go" {
		t.Errorf("skipped = %v, want the unparseable broken.go reported, not dropped", skipped)
	}
}

// TestImportPathsFromFile_UnquotableLiteralIsReported is the regression for the
// last silent drop in the import collector. A parsed file's import path is
// normally a valid Go string literal, so this branch is defensive — but a path
// that cannot be unquoted removes a requirement from the synthesised go.mod
// exactly as an unparseable file does, and must be reported for the same reason:
// the resulting resolution failure has to be attributable to a named cause.
func TestImportPathsFromFile_UnquotableLiteralIsReported(t *testing.T) {
	f := &ast.File{
		Name: ast.NewIdent("a"),
		Imports: []*ast.ImportSpec{
			{Path: &ast.BasicLit{Kind: token.STRING, Value: `"example.com/good"`}},
			{Path: &ast.BasicLit{Kind: token.STRING, Value: `"example.com/bad\q"`}},
			{Path: &ast.BasicLit{Kind: token.STRING, Value: `"fmt"`}},
		},
	}

	paths, bad := importPathsFromFile(f)
	if len(paths) != 1 || paths[0] != "example.com/good" {
		t.Errorf("paths = %v, want just the readable non-stdlib import", paths)
	}
	if len(bad) != 1 || !strings.Contains(bad[0], "bad") {
		t.Errorf("unreadable = %v, want the unquotable literal reported, not dropped", bad)
	}
}
