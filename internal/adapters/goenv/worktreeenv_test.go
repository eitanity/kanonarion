package goenv_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
)

// check asserts one producer's output against the posture of the given name.
func checkPosture(t *testing.T, name string, base, got []string) {
	t.Helper()
	p, ok := goenv.For(name)
	if !ok {
		t.Fatalf("no posture named %q is stated", name)
	}
	for _, v := range goenv.Verify(p, base, got) {
		t.Error(v)
	}
}

// workTree writes a minimal buildable module at a fresh directory, plus a
// go.work naming it when workspace is true.
func workTree(t *testing.T, workspace bool) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	write("go.mod", "module example.com/tree\n\ngo 1.21\n")
	write("a.go", "package tree\n\n// Answer is the tree's only symbol.\nconst Answer = 42\n")
	if workspace {
		write("go.work", "go 1.21\n\nuse .\n")
	}
	return dir
}

func TestWorktree_TreeWithNoWorkspaceIsPinned(t *testing.T) {
	base := []string{"PATH=/usr/bin"}

	checkPosture(t, "worktree", base, goenv.Worktree(base, workTree(t, false)))
}

// TestWorktree_TreeWithAWorkspaceHonoursIt is the contract loadenv.go states and
// the code contradicted: the workspace is a local tree's real build
// configuration, and -mod=mod is the flag workspace mode refuses.
func TestWorktree_TreeWithAWorkspaceHonoursIt(t *testing.T) {
	base := []string{"PATH=/usr/bin"}

	checkPosture(t, "worktree-workspace", base, goenv.Worktree(base, workTree(t, true)))
}

// TestWorktree_InheritedWorkOffIsNotAWorkspace pins the go command's own
// resolution order: GOWORK decides when it is set, and off means there is no
// workspace whatever the directory contains.
func TestWorktree_InheritedWorkOffIsNotAWorkspace(t *testing.T) {
	base := []string{"PATH=/usr/bin", "GOWORK=off"}

	checkPosture(t, "worktree", base, goenv.Worktree(base, workTree(t, true)))
}

// TestWorktree_WorkspaceTreeResolves measures the two halves against the real
// toolchain rather than asserting about flags: the child must see the workspace,
// and it must load under the flag this posture pins.
func TestWorktree_WorkspaceTreeResolves(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("the go toolchain is not on PATH; this test measures real resolution")
	}
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOWORK", "")
	dir := workTree(t, true)
	env := goenv.Worktree(os.Environ(), dir)

	run := func(args ...string) (string, error) {
		cmd := exec.Command("go", args...) // #nosec G204 -- fixed binary, literal arguments
		cmd.Dir = dir
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}

	got, err := run("env", "GOWORK")
	if err != nil {
		t.Fatalf("go env GOWORK: %v\n%s", err, got)
	}
	if want := filepath.Join(dir, "go.work"); got != want {
		t.Errorf("the child resolved GOWORK=%q, want %q — a working tree's workspace is its build", got, want)
	}

	if out, err := run("list", "./..."); err != nil {
		t.Fatalf("a working tree under a workspace failed to load: %v\n%s", err, out)
	}
}

// TestWorktree_LeavesAnIncompleteTreeUntouched is the hazard this posture's
// -mod=readonly closes: the go command satisfies a missing go.sum entry from the
// module cache without a download, so GOPROXY=off does not stop a command asked
// only to measure the tree from editing it.
func TestWorktree_LeavesAnIncompleteTreeUntouched(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("the go toolchain is not on PATH; this test measures real resolution")
	}
	version := selectedVersion(t, "golang.org/x/mod")
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOWORK", "")

	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	gosum := filepath.Join(dir, "go.sum")
	for name, content := range map[string]string{
		"go.mod": "module example.com/incomplete\n\ngo 1.21\n\nrequire golang.org/x/mod " + version + "\n",
		"a.go":   "package incomplete\n\nimport \"golang.org/x/mod/semver\"\n\nvar _ = semver.Canonical\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	before, err := os.ReadFile(gomod) // #nosec G304 -- written by this test into its own t.TempDir()
	if err != nil {
		t.Fatalf("reading the fixture go.mod: %v", err)
	}

	cmd := exec.Command("go", "list", "-deps", "./...")
	cmd.Dir = dir
	cmd.Env = goenv.Worktree(os.Environ(), dir)
	out, err := cmd.CombinedOutput()

	if err == nil {
		t.Error("a tree with no go.sum entry loaded cleanly: the analysis supplied what the tree was missing")
	} else if !strings.Contains(string(out), "missing go.sum entry") {
		t.Errorf("the failure does not name the gap:\n%s", out)
	}
	after, err := os.ReadFile(gomod) // #nosec G304 -- written by this test into its own t.TempDir()
	if err != nil {
		t.Fatalf("reading go.mod back: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("go.mod was rewritten by the analysis:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if _, err := os.Stat(gosum); err == nil {
		written, _ := os.ReadFile(gosum) // #nosec G304 -- written by the child into this test's t.TempDir()
		t.Errorf("the analysis wrote a go.sum into the tree it was asked to measure:\n%s", written)
	}
}

// selectedVersion is the version of path this repository's own build resolves,
// which is therefore already in the module cache and needs no download.
func selectedVersion(t *testing.T, path string) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Version}}", path).Output() // #nosec G204 -- fixed binary, literal arguments
	if err != nil {
		t.Skipf("cannot resolve %s from this module: %v", path, err)
	}
	return strings.TrimSpace(string(out))
}
