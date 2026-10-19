package gotoolchain_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/walk/adapters/buildlist/gotoolchain"
)

// writeFiles writes path -> content under root.
func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
}

// Inside a go.work the build list names every member with its directory and
// the go.work directory; outside one it names neither. Offline: no module in
// either tree has a dependency to fetch.
func TestResolve_ReportsWorkspaceMembersAndWorkDir(t *testing.T) {
	t.Setenv("GOWORK", "")
	t.Setenv("GOFLAGS", "")
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.work":  "go 1.22\n\nuse (\n\t./a\n\t./b\n)\n",
		"a/go.mod": "module example.com/ws/a\n\ngo 1.22\n",
		"a/a.go":   "package a\n",
		"b/go.mod": "module example.com/ws/b\n\ngo 1.22\n",
		"b/b.go":   "package b\n",
	})
	r := gotoolchain.New("", nil)

	bl, err := r.Resolve(t.Context(), filepath.Join(root, "a"))
	if err != nil {
		t.Fatalf("Resolve in the workspace: %v", err)
	}
	if bl.WorkDir != root {
		t.Errorf("WorkDir = %q, want %q", bl.WorkDir, root)
	}
	dirs := map[string]string{}
	for _, m := range bl.Modules {
		if m.Main {
			dirs[m.Path] = m.Dir
		}
	}
	if dirs["example.com/ws/b"] != filepath.Join(root, "b") || dirs["example.com/ws/a"] != filepath.Join(root, "a") {
		t.Errorf("main modules = %v, want both members with their directories", dirs)
	}
	if got, werr := r.Workspace(t.Context(), filepath.Join(root, "a")); werr != nil || got != root {
		t.Errorf("Workspace = %q, %v; want %q", got, werr, root)
	}

	solo := t.TempDir()
	writeFiles(t, solo, map[string]string{"go.mod": "module example.com/solo\n\ngo 1.22\n"})
	bl, err = r.Resolve(t.Context(), solo)
	if err != nil {
		t.Fatalf("Resolve outside a workspace: %v", err)
	}
	if bl.WorkDir != "" {
		t.Errorf("WorkDir = %q outside a workspace, want empty", bl.WorkDir)
	}
	if got, werr := r.Workspace(t.Context(), solo); werr != nil || got != "" {
		t.Errorf("Workspace = %q, %v outside a workspace; want empty", got, werr)
	}
}
