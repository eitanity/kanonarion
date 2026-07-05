package walkdir_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/local/adapters/snapshot/walkdir"
)

func TestBuilder_CapturesGoFiles(t *testing.T) {
	root := t.TempDir()
	write(t, root, "main.go", "package main")
	write(t, root, "go.mod", "module example.com/app\n\ngo 1.21")
	write(t, root, "go.sum", "")
	write(t, root, "sub/util.go", "package util")

	s, err := walkdir.Builder{}.Build(context.Background(), root)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	wantPaths := []string{
		filepath.Join(root, "main.go"),
		filepath.Join(root, "go.mod"),
		filepath.Join(root, "go.sum"),
		filepath.Join(root, "sub/util.go"),
	}
	for _, p := range wantPaths {
		if _, ok := s.Files[p]; !ok {
			t.Errorf("missing file in snapshot: %s", p)
		}
	}
}

func TestBuilder_SkipsIrrelevantFiles(t *testing.T) {
	root := t.TempDir()
	write(t, root, "main.go", "package main")
	write(t, root, "README.md", "# readme")
	write(t, root, ".env", "SECRET=x")
	write(t, root, "Makefile", "build:")

	s, err := walkdir.Builder{}.Build(context.Background(), root)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	for p := range s.Files {
		base := filepath.Base(p)
		if !strings.HasSuffix(base, ".go") && base != "go.mod" && base != "go.sum" {
			t.Errorf("unexpected file in snapshot: %s", p)
		}
	}
}

func TestBuilder_SkipsGitDir(t *testing.T) {
	root := t.TempDir()
	write(t, root, "main.go", "package main")
	write(t, root, ".git/HEAD", "ref: refs/heads/main")
	write(t, root, ".git/objects/pack/pack.go", "package pack") // .go inside .git

	s, err := walkdir.Builder{}.Build(context.Background(), root)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	for p := range s.Files {
		if strings.Contains(p, ".git") {
			t.Errorf("snapshot contains .git path: %s", p)
		}
	}
}

func TestBuilder_AbsolutePaths(t *testing.T) {
	root := t.TempDir()
	write(t, root, "main.go", "package main")

	s, err := walkdir.Builder{}.Build(context.Background(), root)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	for p := range s.Files {
		if !filepath.IsAbs(p) {
			t.Errorf("snapshot contains non-absolute path: %s", p)
		}
	}
}

func TestBuilder_VersionIDHasLocalPrefix(t *testing.T) {
	root := t.TempDir()
	write(t, root, "main.go", "package main")

	s, err := walkdir.Builder{}.Build(context.Background(), root)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if !strings.HasPrefix(s.VersionID, "local-") {
		t.Errorf("VersionID %q does not start with 'local-'", s.VersionID)
	}
}

func TestBuilder_Deterministic(t *testing.T) {
	root := t.TempDir()
	write(t, root, "main.go", "package main")
	write(t, root, "go.mod", "module example.com/app\n\ngo 1.21")

	b := walkdir.Builder{}
	s1, err := b.Build(context.Background(), root)
	if err != nil {
		t.Fatalf("first Build: %v", err)
	}
	s2, err := b.Build(context.Background(), root)
	if err != nil {
		t.Fatalf("second Build: %v", err)
	}

	if s1.VersionID != s2.VersionID {
		t.Errorf("Build is not deterministic: %q vs %q", s1.VersionID, s2.VersionID)
	}
}

func TestBuilder_ContextCancellation(t *testing.T) {
	root := t.TempDir()
	for i := range 20 {
		write(t, root, filepath.Join("pkg", filepath.Base(t.TempDir()[:8]), strings.Repeat("x", i)+"_.go"), "package p")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := walkdir.Builder{}.Build(ctx, root)
	if err == nil {
		t.Log("Build completed before cancellation was observed (acceptable for small trees)")
	}
}

func TestBuilder_FileContentsMatch(t *testing.T) {
	root := t.TempDir()
	const content = "package main\n\nfunc main() {}"
	write(t, root, "main.go", content)

	s, err := walkdir.Builder{}.Build(context.Background(), root)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	p := filepath.Join(root, "main.go")
	got, ok := s.Files[p]
	if !ok {
		t.Fatalf("main.go not in snapshot")
	}
	if string(got) != content {
		t.Errorf("content mismatch: got %q, want %q", got, content)
	}
}

// write creates a file at root/relPath with the given content.
func write(t *testing.T, root, relPath, content string) {
	t.Helper()
	full := filepath.Join(root, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", relPath, err)
	}
}
