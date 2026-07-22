package govulncheck

import (
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
	dir, err := writeSynthesisedGoMod(root, coord, "go1.26.5", map[coordinate.ModuleCoordinate]struct{}{
		{Path: "example.com/dep", Version: "v0.3.0"}:    {},
		{Path: "example.com/unused", Version: "v9.9.9"}: {},
	})
	if err != nil {
		t.Fatalf("writeSynthesisedGoMod: %v", err)
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
	if _, err := writeSynthesisedGoMod(root, coord, "go1.26.5", nil); err == nil {
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

	got := collectImports(root)
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

// An unparseable file must not fail the scan; it contributes no imports and the
// toolchain names whatever it cannot resolve.
func TestCollectImports_ToleratesUnparseableFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "broken.go"), []byte("this is not go"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "ok.go"), []byte("package a\n\nimport \"example.com/dep\"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := collectImports(root)
	if len(got) != 1 || got[0] != "example.com/dep" {
		t.Errorf("collectImports() = %v, want [example.com/dep]", got)
	}
}
