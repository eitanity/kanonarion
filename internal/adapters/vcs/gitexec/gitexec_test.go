package gitexec_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/vcs/gitexec"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not in PATH")
	}
}

// setupRepo creates a bare git repo with one commit tagged v1.0.0 and returns
// the repo URL (file:// path) and the commit hash.
func setupRepo(t *testing.T) (repoURL, commit, tagRef string) {
	t.Helper()
	dir := t.TempDir()

	run := func(args ...string) string {
		cmd := exec.Command("git", args...) //nolint:gosec
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@test.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}

	run("init")
	run("config", "user.email", "test@test.com")
	run("config", "user.name", "test")

	// Create a file and commit.
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/m\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	run("add", ".")
	run("commit", "-m", "initial")
	commit = run("rev-parse", "HEAD")
	run("tag", "v1.0.0")

	return "file://" + dir, commit, "refs/tags/v1.0.0"
}

func TestClient_ResolveTag(t *testing.T) {
	requireGit(t)
	repoURL, commit, tagRef := setupRepo(t)

	// file:// is blocked by the default https-only policy; widen it for the
	// local fixture repo only.
	c := gitexec.NewWithProtocols("https:file")
	got, err := c.ResolveTag(context.Background(), repoURL, tagRef)
	if err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}
	if got != commit {
		t.Errorf("ResolveTag = %q, want %q", got, commit)
	}
}

func TestClient_CheckoutToDir(t *testing.T) {
	requireGit(t)
	repoURL, commit, _ := setupRepo(t)

	checkoutDir := t.TempDir()
	c := gitexec.NewWithProtocols("https:file")
	if err := c.CheckoutToDir(context.Background(), repoURL, commit, checkoutDir); err != nil {
		t.Fatalf("CheckoutToDir: %v", err)
	}

	// go.mod should be present.
	if _, err := os.Stat(filepath.Join(checkoutDir, "go.mod")); err != nil {
		t.Errorf("go.mod not found after checkout: %v", err)
	}
}

// withoutGit empties PATH so exec.LookPath("git") fails, simulating a host with
// no git binary installed without depending on the host's actual git presence.
func withoutGit(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", "")
}

func TestClient_ResolveTag_GitNotInstalled(t *testing.T) {
	withoutGit(t)

	c := gitexec.New()
	_, err := c.ResolveTag(context.Background(), "https://github.com/example/m", "refs/tags/v1.0.0")
	if !errors.Is(err, gitexec.ErrGitNotInstalled) {
		t.Fatalf("ResolveTag error = %v, want ErrGitNotInstalled", err)
	}
}

func TestClient_CheckoutToDir_GitNotInstalled(t *testing.T) {
	withoutGit(t)

	c := gitexec.New()
	err := c.CheckoutToDir(context.Background(), "https://github.com/example/m", strings.Repeat("a", 40), t.TempDir())
	if !errors.Is(err, gitexec.ErrGitNotInstalled) {
		t.Fatalf("CheckoutToDir error = %v, want ErrGitNotInstalled", err)
	}
}

// The error must name the --skip-vcs-verify escape hatch so a missing tool reads
// as actionable, must not leak the raw os/exec "executable file not found"
// string, and must wrap ports.ErrVCSToolMissing so the application layer can
// classify tooling-absence with errors.Is rather than string matching.
func TestErrGitNotInstalled_Actionable(t *testing.T) {
	msg := gitexec.ErrGitNotInstalled.Error()
	if !strings.Contains(msg, "--skip-vcs-verify") {
		t.Errorf("error message %q does not mention --skip-vcs-verify", msg)
	}
	if !strings.Contains(msg, "git not found in PATH") {
		t.Errorf("error message %q lacks the recognisable git-not-found text", msg)
	}
	if strings.Contains(msg, "executable file not found") {
		t.Errorf("error message %q leaks the raw os/exec string", msg)
	}
	if !errors.Is(gitexec.ErrGitNotInstalled, ports.ErrVCSToolMissing) {
		t.Error("ErrGitNotInstalled must wrap ports.ErrVCSToolMissing")
	}
}

// The default client restricts git to https, so a file:// fixture repo that
// works under NewWithProtocols must be refused by New — proving the transport
// allowlist is applied to every invocation, not just opt-in.
func TestClient_DefaultRejectsFileTransport(t *testing.T) {
	requireGit(t)
	repoURL, commit, tagRef := setupRepo(t)

	c := gitexec.New()
	if _, err := c.ResolveTag(context.Background(), repoURL, tagRef); err == nil {
		t.Error("ResolveTag over file:// should be blocked by the https-only policy")
	}
	if err := c.CheckoutToDir(context.Background(), repoURL, commit, t.TempDir()); err == nil {
		t.Error("CheckoutToDir over file:// should be blocked by the https-only policy")
	}
}

// setupRepoWithHistory creates a git repo with n commits and returns the repo
// URL plus the commit hashes oldest-first. The oldest commits are not the tip
// of any ref, so fetching them forces CheckoutToDir's fallback path (git
// refuses to serve a non-advertised SHA by default).
func setupRepoWithHistory(t *testing.T, n int) (repoURL string, commits []string) {
	t.Helper()
	dir := t.TempDir()

	run := func(args ...string) string {
		cmd := exec.Command("git", args...) //nolint:gosec
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@test.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}

	run("init")
	run("config", "user.email", "test@test.com")
	run("config", "user.name", "test")

	for i := range n {
		content := fmt.Sprintf("module example.com/m\n\ngo 1.21\n// rev %d\n", i)
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		run("add", ".")
		run("commit", "-m", fmt.Sprintf("rev %d", i))
		commits = append(commits, run("rev-parse", "HEAD"))
	}

	return "file://" + dir, commits
}

// forceProtocolV0 makes the adapter's git subprocesses speak protocol v0, in
// which upload-pack refuses non-advertised SHA wants by default. Modern git
// over protocol v2 happily serves any reachable SHA from a local repo, which
// would let the direct single-commit fetch succeed and never exercise the
// fallback path these tests exist to pin down. The vars flow through gitEnv's
// os.Environ passthrough; GITHUB_TOKEN is cleared because gitEnv would
// otherwise emit its own GIT_CONFIG_COUNT and override this one.
func forceProtocolV0(t *testing.T) {
	t.Helper()
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "protocol.version")
	t.Setenv("GIT_CONFIG_VALUE_0", "0")
}

// A commit reachable within the fallback depth cap must still check out when
// the single-commit fetch is refused — bounding the fallback must not break
// legitimate cross-verification.
func TestClient_CheckoutToDir_BoundedFallbackWithinDepth(t *testing.T) {
	requireGit(t)
	forceProtocolV0(t)
	repoURL, commits := setupRepoWithHistory(t, 3)

	c := gitexec.NewWithProtocols("https:file")
	c.SetFetchBounds(100, time.Minute)
	checkoutDir := t.TempDir()
	if err := c.CheckoutToDir(context.Background(), repoURL, commits[0], checkoutDir); err != nil {
		t.Fatalf("CheckoutToDir via bounded fallback: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(checkoutDir, "go.mod")) //nolint:gosec // path rooted in t.TempDir
	if err != nil {
		t.Fatalf("reading go.mod after checkout: %v", err)
	}
	if !strings.Contains(string(data), "rev 0") {
		t.Errorf("checkout content = %q, want the rev 0 revision", data)
	}
}

// A commit deeper than the fallback depth cap must fail closed with an
// explicit bound error instead of falling back to an unbounded full fetch —
// the DoS this bound exists to prevent.
func TestClient_CheckoutToDir_BoundedFallbackFailsClosedBeyondDepth(t *testing.T) {
	requireGit(t)
	forceProtocolV0(t)
	repoURL, commits := setupRepoWithHistory(t, 3)

	c := gitexec.NewWithProtocols("https:file")
	c.SetFetchBounds(1, time.Minute)
	err := c.CheckoutToDir(context.Background(), repoURL, commits[0], t.TempDir())
	if err == nil {
		t.Fatal("CheckoutToDir succeeded for a commit beyond the fallback depth cap; the fallback fetch is unbounded")
	}
	if !strings.Contains(err.Error(), "bounded fallback fetch") {
		t.Errorf("error %q does not name the bounded fallback fetch", err)
	}
}

// A remote that accepts the connection but never responds must not wedge
// cross-verification: every fetch attempt is bounded by the fetch timeout and
// the failure names the bound.
func TestClient_CheckoutToDir_FetchTimeoutOnStallingRemote(t *testing.T) {
	requireGit(t)

	// Listen but never accept: connections succeed at the kernel level (the
	// listen backlog) and git then waits forever for an HTTP response.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	c := gitexec.NewWithProtocols("http")
	c.SetFetchBounds(8, 500*time.Millisecond)

	start := time.Now()
	err = c.CheckoutToDir(context.Background(),
		"http://"+ln.Addr().String()+"/repo.git", strings.Repeat("a", 40), t.TempDir())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("CheckoutToDir against a stalling remote should fail")
	}
	if !strings.Contains(err.Error(), "fetch bound") {
		t.Errorf("error %q does not name the fetch bound", err)
	}
	// Two bounded attempts (direct + fallback) at 500ms each plus the
	// WaitDelay pipe grace per attempt, with generous headroom — the point is
	// "minutes, not the 10-minute test deadline".
	if elapsed > 45*time.Second {
		t.Errorf("CheckoutToDir took %s against a stalling remote; the fetch timeout is not enforced", elapsed)
	}
}

func TestParseLsRemoteOutput(t *testing.T) {
	commit := strings.Repeat("a", 40)
	ref := "refs/tags/v1.0.0"

	t.Run("match among multiple lines", func(t *testing.T) {
		out := []byte(strings.Repeat("b", 40) + "\trefs/heads/main\n" + commit + "\t" + ref + "\n")
		got, err := gitexec.ParseLsRemoteOutput(out, "https://example.com/r", ref)
		if err != nil {
			t.Fatalf("ParseLsRemoteOutput: %v", err)
		}
		if got != commit {
			t.Errorf("commit = %q, want %q", got, commit)
		}
	})

	t.Run("short hash rejected", func(t *testing.T) {
		_, err := gitexec.ParseLsRemoteOutput([]byte("abc\t"+ref), "https://example.com/r", ref)
		if err == nil || !strings.Contains(err.Error(), "unexpected commit hash length") {
			t.Errorf("err = %v, want commit-length error", err)
		}
	})

	t.Run("ref absent", func(t *testing.T) {
		_, err := gitexec.ParseLsRemoteOutput([]byte(commit+"\trefs/heads/main\n"), "https://example.com/r", ref)
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("err = %v, want not-found error", err)
		}
	})
}

func TestClient_ResolveTag_NotFound(t *testing.T) {
	requireGit(t)
	repoURL, _, _ := setupRepo(t)

	c := gitexec.New()
	_, err := c.ResolveTag(context.Background(), repoURL, "refs/tags/nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent ref")
	}
}
