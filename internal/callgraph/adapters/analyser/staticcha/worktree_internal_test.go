package staticcha

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
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

// analyseTree runs AnalyseDir over dir and returns the digest the record carries.
// The digest is what the ANALYSIS says it read, so it has to be taken from a real
// load rather than from the file lister: the two disagree exactly where this
// matters.
func analyseTree(t *testing.T, dir, modulePath string) string {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate(modulePath, coordinate.LocalVersion)
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	rec, err := quietAnalyser().AnalyseDir(context.Background(), dir, coord)
	if err != nil {
		t.Fatalf("AnalyseDir: %v", err)
	}
	if rec.WorktreeDigest == "" {
		t.Fatalf("AnalyseDir recorded no tree digest (status %s: %s)", rec.OverallStatus, rec.FailureDetail)
	}
	return rec.WorktreeDigest
}

// TestWorktreeDigest_MovesWhenOutOfRootSymlinkTargetChanges is the collision the
// digest exists to prevent: source reached through a symlink whose target sits
// outside the analysed root is read by the loader and analysed, so two trees that
// differ only in that target are two trees.
//
// A filesystem walk cannot see it — a symlink is not a regular file, so the walk
// skips the link and never reaches the target — which is why the digest is taken
// from the loader's own file list.
func TestWorktreeDigest_MovesWhenOutOfRootSymlinkTargetChanges(t *testing.T) {
	outside := t.TempDir()
	target := filepath.Join(outside, "shared.go")
	write(t, target, "package pkg\n\n// Shared is reached through a link.\nfunc Shared() string { return \"a\" }\n")

	dir := t.TempDir()
	write(t, filepath.Join(dir, "go.mod"), "module example.com/symout\n\ngo 1.24\n")
	write(t, filepath.Join(dir, "pkg", "keep.go"), "package pkg\n\n// Keep anchors the package.\nfunc Keep() {}\n")
	if err := os.Symlink(target, filepath.Join(dir, "pkg", "shared.go")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	before := analyseTree(t, dir, "example.com/symout")
	write(t, target, "package pkg\n\n// Shared is reached through a link.\nfunc Shared() string { return \"b\" }\n")
	if after := analyseTree(t, dir, "example.com/symout"); after == before {
		t.Fatalf("editing an out-of-root symlink target left the digest at %s: "+
			"the analysis read different code and the ledger recorded the same tree", before)
	}
}

// TestWorktreeDigest_IgnoresFilesTheLoaderNeverReads. The digest describes the
// bytes that were ANALYSED. A file the loader never opens cannot change the graph,
// so a digest that moved with it would mint a generation recording the identical
// graph and — under a tree-scoped read — make the caller's own tree look foreign.
func TestWorktreeDigest_IgnoresFilesTheLoaderNeverReads(t *testing.T) {
	cases := []struct {
		name  string
		apply func(t *testing.T, dir string)
	}{
		{"a .go file under testdata", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "pkg", "testdata", "fixture.go"), "package fixture\n\nvar V = 2\n")
		}},
		{"a build-tag-excluded file", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "pkg", "excluded.go"),
				"//go:build never_set_by_any_build\n\npackage pkg\n\nvar Excluded = 2\n")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			write(t, filepath.Join(dir, "go.mod"), "module example.com/unread\n\ngo 1.24\n")
			write(t, filepath.Join(dir, "pkg", "a.go"), "package pkg\n\n// Use does nothing.\nfunc Use() {}\n")
			write(t, filepath.Join(dir, "pkg", "testdata", "fixture.go"), "package fixture\n\nvar V = 1\n")
			write(t, filepath.Join(dir, "pkg", "excluded.go"),
				"//go:build never_set_by_any_build\n\npackage pkg\n\nvar Excluded = 1\n")

			before := analyseTree(t, dir, "example.com/unread")
			tc.apply(t, dir)
			if after := analyseTree(t, dir, "example.com/unread"); after != before {
				t.Fatalf("%s moved the digest: %s -> %s", tc.name, before, after)
			}
		})
	}
}

// TestAnalysedDigest_IsStableAcrossLocation is the location half at the analysis
// level: two copies of one tree, analysed at different paths, are one tree. It is
// the property that stops the digest degenerating into the absolute path, which
// would call one tree two.
func TestAnalysedDigest_IsStableAcrossLocation(t *testing.T) {
	build := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		write(t, filepath.Join(dir, "go.mod"), "module example.com/located\n\ngo 1.24\n")
		write(t, filepath.Join(dir, "pkg", "a.go"), "package pkg\n\n// Use does nothing.\nfunc Use() {}\n")
		return dir
	}
	a, b := analyseTree(t, build(t), "example.com/located"), analyseTree(t, build(t), "example.com/located")
	if a != b {
		t.Fatalf("two copies of one tree hashed differently: %s vs %s", a, b)
	}
}

// TestAnalysedDigest_FallsBackWhenTheLoadResolvedNothing. A load that resolved no
// files still produced a record, and a worktree record with no digest merges
// silently with every other checkout of the module path. The fallback says so in
// the value: it carries its own scheme, so nothing compares it with a digest over
// what was actually analysed.
func TestAnalysedDigest_FallsBackWhenTheLoadResolvedNothing(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "go.mod"), "module example.com/broken\n\ngo 1.24\n\nrequire !!!unparseable\n")
	write(t, filepath.Join(dir, "pkg", "a.go"), "package pkg\n")

	got := analyseTree(t, dir, "example.com/broken")
	if !strings.HasPrefix(got, scannedDigestScheme) {
		t.Fatalf("a load that resolved nothing produced %q, want the %q scheme", got, scannedDigestScheme)
	}
}

// TestTreeIdentity_AnswersWithoutAnalysing is what makes reuse affordable: the
// question "is this the tree that record was taken of" has to be answerable in
// the time a directory walk takes, or asking it costs what the analysis it saves
// would have.
func TestTreeIdentity_AnswersWithoutAnalysing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "go.mod"), "module example.com/m\n\ngo 1.24\n")
	write(t, filepath.Join(dir, "a.go"), "package m\n\nfunc A() {}\n")

	a := &Analyser{}
	first, err := a.TreeIdentity(context.Background(), dir)
	if err != nil {
		t.Fatalf("TreeIdentity: %v", err)
	}
	if first.IsZero() {
		t.Fatal("TreeIdentity established neither a root nor a digest")
	}
	if !strings.HasPrefix(first.ScanDigest, scannedDigestScheme) {
		t.Fatalf("digest %q does not carry the scheme that says how it was taken", first.ScanDigest)
	}
	// The scheme is not decoration: this digest must never be compared against one
	// taken over what a loader read, and the prefix is what keeps that visible.
	if strings.HasPrefix(first.ScanDigest, analysedDigestScheme) {
		t.Fatal("a scanned digest is claiming to describe what was analysed")
	}

	again, err := a.TreeIdentity(context.Background(), dir)
	if err != nil {
		t.Fatalf("TreeIdentity second call: %v", err)
	}
	if again != first {
		t.Fatalf("an unchanged tree identified differently on a second call: %+v vs %+v", again, first)
	}

	write(t, filepath.Join(dir, "a.go"), "package m\n\nfunc A() {}\n\nfunc B() {}\n")
	edited, err := a.TreeIdentity(context.Background(), dir)
	if err != nil {
		t.Fatalf("TreeIdentity after edit: %v", err)
	}
	if edited.ScanDigest == first.ScanDigest {
		t.Fatal("an edited tree identified as the tree before the edit; a run would reuse a graph of code that is gone")
	}
	if edited.Root != first.Root {
		t.Fatalf("root moved on an edit: %q then %q", first.Root, edited.Root)
	}
}

// TestWorktreeDigest_MovesWhenASymlinkedSourceFileChanges closes the hole the
// scanned digest would otherwise leave in the reuse decision.
//
// Source reached through a symlink is read and analysed, so a tree that differs
// only in the target's contents is a different tree. A run deciding whether to
// re-analyse from this digest would otherwise serve back a graph of code that has
// since been edited — the one outcome reuse must never produce.
func TestWorktreeDigest_MovesWhenASymlinkedSourceFileChanges(t *testing.T) {
	t.Parallel()
	outside := t.TempDir()
	target := filepath.Join(outside, "shared.go")
	write(t, target, "package pkg\n\nfunc Shared() string { return \"a\" }\n")

	dir := t.TempDir()
	write(t, filepath.Join(dir, "go.mod"), "module example.com/m\n")
	write(t, filepath.Join(dir, "pkg", "keep.go"), "package pkg\n")
	if err := os.Symlink(target, filepath.Join(dir, "pkg", "shared.go")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	before := digest(t, dir)

	write(t, target, "package pkg\n\nfunc Shared() string { return \"b\" }\n")
	if after := digest(t, dir); after == before {
		t.Fatal("editing the target of an in-tree symlink did not move the digest; a run would reuse a graph of the code before the edit")
	}
}

// TestWorktreeDigest_SurvivesALinkItCannotFollow: a dangling symlink and a link
// to a directory carry no source the loader can read through that path, and a
// tree containing one must still be identifiable — a digest that failed here
// would make an ordinary tree impossible to analyse rather than merely hard to
// hash.
func TestWorktreeDigest_SurvivesALinkItCannotFollow(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "go.mod"), "module example.com/m\n")
	write(t, filepath.Join(dir, "a.go"), "package m\n")
	if err := os.Symlink(filepath.Join(dir, "gone.go"), filepath.Join(dir, "dangling.go")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, err := worktreeDigest(dir); err != nil {
		t.Fatalf("a dangling symlink made the tree unidentifiable: %v", err)
	}
}
