package localsource_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/stdlib/adapters/localsource"
)

func writeGoRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "LICENSE"), "BSD-3-Clause text")
	mustWrite(t, filepath.Join(root, "src", "fmt", "print.go"), "package fmt\n")
	mustWrite(t, filepath.Join(root, "src", "runtime", "proc.go"), "package runtime\n")
	return root
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSourceFS_ExposesSrcTree(t *testing.T) {
	root := writeGoRoot(t)
	fsys, err := localsource.New().SourceFS(root)
	if err != nil {
		t.Fatalf("SourceFS: %v", err)
	}
	data, err := fs.ReadFile(fsys, "fmt/print.go")
	if err != nil {
		t.Fatalf("reading through SourceFS: %v", err)
	}
	if string(data) != "package fmt\n" {
		t.Errorf("unexpected content: %q", data)
	}
}

func TestSourceFS_MissingSrcIsError(t *testing.T) {
	if _, err := localsource.New().SourceFS(t.TempDir()); err == nil {
		t.Error("expected error when $GOROOT/src is absent")
	}
}

func TestLicenseText_ReadsLicense(t *testing.T) {
	root := writeGoRoot(t)
	data, err := localsource.New().LicenseText(root)
	if err != nil {
		t.Fatalf("LicenseText: %v", err)
	}
	if string(data) != "BSD-3-Clause text" {
		t.Errorf("unexpected LICENSE content: %q", data)
	}
}

func TestLicenseText_MissingIsError(t *testing.T) {
	if _, err := localsource.New().LicenseText(t.TempDir()); err == nil {
		t.Error("expected error when $GOROOT/LICENSE is absent")
	}
}
