package staticcha

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
}

func digest(t *testing.T, dir string) string {
	t.Helper()
	d, err := worktreeDigest(dir)
	if err != nil {
		t.Fatalf("worktreeDigest: %v", err)
	}
	return d
}

// TestWorktreeDigest_IgnoresVersionControlMetadata: .git changes on every commit,
// fetch and index refresh without the analysed source changing at all. A digest
// that moved with it would report a different tree on every git operation, and
// the ledger would accumulate a generation per `git status`.
func TestWorktreeDigest_IgnoresVersionControlMetadata(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "go.mod"), "module example.com/m\n")
	write(t, filepath.Join(dir, "a.go"), "package m\n")
	before := digest(t, dir)

	write(t, filepath.Join(dir, ".git", "HEAD"), "ref: refs/heads/other\n")
	write(t, filepath.Join(dir, ".git", "index.go"), "package fake\n")
	if after := digest(t, dir); after != before {
		t.Fatal("version-control metadata moved the worktree digest")
	}
}

// TestWorktreeDigest_TracksTheFilesThatDecideTheGraph. Each of these is a change
// the analysis would see, so each must move the digest; a digest that missed one
// would identify two different trees as the same and let the ledger compose them.
func TestWorktreeDigest_TracksTheFilesThatDecideTheGraph(t *testing.T) {
	t.Parallel()
	base := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		write(t, filepath.Join(dir, "go.mod"), "module example.com/m\n")
		write(t, filepath.Join(dir, "go.sum"), "")
		write(t, filepath.Join(dir, "pkg", "a.go"), "package pkg\n")
		return dir
	}

	cases := []struct {
		name  string
		apply func(t *testing.T, dir string)
	}{
		{"editing a source file", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "pkg", "a.go"), "package pkg\n\nfunc F() {}\n")
		}},
		{"adding a source file", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "pkg", "b.go"), "package pkg\n")
		}},
		{"editing go.mod", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "go.mod"), "module example.com/m\n\ngo 1.24\n")
		}},
		{"editing go.sum", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "go.sum"), "example.com/x v1.0.0 h1:abc=\n")
		}},
		{"renaming a source file", func(t *testing.T, dir string) {
			if err := os.Rename(filepath.Join(dir, "pkg", "a.go"), filepath.Join(dir, "pkg", "renamed.go")); err != nil {
				t.Fatalf("Rename: %v", err)
			}
		}},
		{"moving a source file to another package", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "other", "a.go"), "package pkg\n")
			if err := os.Remove(filepath.Join(dir, "pkg", "a.go")); err != nil {
				t.Fatalf("Remove: %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := base(t)
			before := digest(t, dir)
			tc.apply(t, dir)
			if after := digest(t, dir); after == before {
				t.Fatalf("%s did not change the worktree digest", tc.name)
			}
		})
	}
}

// TestWorktreeDigest_IgnoresFilesTheAnalysisNeverReads keeps the digest from
// churning on artefacts that have nothing to do with the graph.
func TestWorktreeDigest_IgnoresFilesTheAnalysisNeverReads(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "go.mod"), "module example.com/m\n")
	write(t, filepath.Join(dir, "a.go"), "package m\n")
	before := digest(t, dir)

	write(t, filepath.Join(dir, "README.md"), "# hello\n")
	write(t, filepath.Join(dir, "build", "output.bin"), "\x00\x01")
	if after := digest(t, dir); after != before {
		t.Fatal("a non-Go file moved the worktree digest")
	}
}

// TestWorktreeDigest_IsStableAcrossLocation: two copies of one tree at different
// paths are the same tree. This is the reason the absolute path is not the
// identity — it is wrong in both directions, and this is the half a path-based
// scheme gets wrong by calling one tree two.
func TestWorktreeDigest_IsStableAcrossLocation(t *testing.T) {
	t.Parallel()
	build := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		write(t, filepath.Join(dir, "go.mod"), "module example.com/m\n")
		write(t, filepath.Join(dir, "pkg", "a.go"), "package pkg\n\nfunc F() {}\n")
		return dir
	}
	if a, b := digest(t, build(t)), digest(t, build(t)); a != b {
		t.Fatalf("two copies of one tree hashed differently: %s vs %s", a, b)
	}
}

// TestWorktreeDigest_UnreadableTreeIsAnError, not a partial digest.
//
// A digest computed over less than the tree would identify two different trees as
// one, which is exactly what the digest exists to prevent — so failing loudly is
// the only safe answer.
func TestWorktreeDigest_UnreadableTreeIsAnError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits do not deny access")
	}
	dir := t.TempDir()
	write(t, filepath.Join(dir, "go.mod"), "module example.com/m\n")
	secret := filepath.Join(dir, "pkg", "a.go")
	write(t, secret, "package pkg\n")
	if err := os.Chmod(secret, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(secret, 0o600) })

	if _, err := worktreeDigest(dir); err == nil {
		t.Fatal("an unreadable source file produced a digest instead of an error")
	}
}
