package gitlsremote_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/eitanity/kanonarion/internal/stdlib/adapters/gitlsremote"
)

// The commit resolver is the VCS-anchor half of the standard-library chain of
// custody, so where it looks matters as much as what it returns. kanonarion is
// routinely run from inside a git repository, and repository-local .git/config
// is the one config file GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM do not govern.
// A url.<base>.insteadOf there would redirect this lookup to a mirror while the
// record still named the canonical Go repository as its anchor.
func TestResolveCommit_EnclosingRepoConfigDoesNotRewriteURL(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not in PATH")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	var connections atomic.Int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			_ = conn.Close()
		}
	}()

	// The rewrite target is https so the transport allowlist cannot be what
	// stops it — the only thing under test is whether the config applies at all.
	repo := t.TempDir()
	cmd := exec.Command("git", "init")
	cmd.Dir = repo
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	cfg := fmt.Sprintf("\n[url \"https://%s/\"]\n\tinsteadOf = https://kanonarion-test.invalid/\n", ln.Addr())
	// #nosec G304 -- the path is rooted in t.TempDir, not in any input
	f, err := os.OpenFile(filepath.Join(repo, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("opening repo config: %v", err)
	}
	if _, err := f.WriteString(cfg); err != nil {
		t.Fatalf("writing repo config: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing repo config: %v", err)
	}
	t.Setenv("HOME", t.TempDir())
	t.Chdir(repo)

	// Expected to fail: the host does not resolve, so the test performs no real
	// network egress. Where it failed to reach is the assertion.
	_, _ = gitlsremote.New().ResolveCommit(context.Background(),
		"https://kanonarion-test.invalid/go", "go1.24.0")

	if got := connections.Load(); got != 0 {
		t.Errorf("the rewritten host received %d connections; the enclosing repository's .git/config was applied", got)
	}
}

// A poisoned per-user config must not reach this resolver either.
func TestResolveCommit_PoisonedHomeConfigDoesNotRewriteURL(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not in PATH")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	var connections atomic.Int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			_ = conn.Close()
		}
	}()

	home := t.TempDir()
	cfg := fmt.Sprintf("[url \"https://%s/\"]\n\tinsteadOf = https://kanonarion-test.invalid/\n", ln.Addr())
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("writing poisoned .gitconfig: %v", err)
	}
	t.Setenv("HOME", home)

	_, _ = gitlsremote.New().ResolveCommit(context.Background(),
		"https://kanonarion-test.invalid/go", "go1.24.0")

	if got := connections.Load(); got != 0 {
		t.Errorf("the rewritten host received %d connections; the ambient ~/.gitconfig was applied", got)
	}
}
