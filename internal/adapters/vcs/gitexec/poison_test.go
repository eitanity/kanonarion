package gitexec_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/vcs/gitexec"
)

// The tests in this file drive the adapter with a hostile git configuration in
// place — the situation it is expected to survive, since cross-verification
// runs git over module source chosen by whoever published the module. Each of
// them fails against an adapter that inherits the ambient environment.

// gitRun runs git in dir with a clean, explicit environment, so fixture setup
// is never influenced by the poisoned HOME a test has installed for the
// adapter's benefit.
func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...) //nolint:gosec // fixture setup; args are literals
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@test.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@test.com",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// poisonHome writes cfg as the .gitconfig of a fresh scratch directory and
// installs it as HOME for the duration of the test. An adapter that lets git
// discover a per-user config will read exactly this file.
func poisonHome(t *testing.T, cfg string) string {
	t.Helper()
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("writing poisoned .gitconfig: %v", err)
	}
	t.Setenv("HOME", home)
	// Belt and braces on the caller's side too: a test that only set HOME would
	// pass against an adapter that happened to read XDG_CONFIG_HOME instead.
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
	xdgGit := filepath.Join(home, "xdg", "git")
	if err := os.MkdirAll(xdgGit, 0o700); err != nil {
		t.Fatalf("creating xdg git dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(xdgGit, "config"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("writing poisoned xdg config: %v", err)
	}
	return home
}

// repoWithAttributes builds a fixture repo carrying a .gitattributes of the
// caller's choosing, mirroring the fact that .gitattributes ships inside the
// repository and is therefore attacker-controlled.
func repoWithAttributes(t *testing.T, attributes string) (repoURL, commit string) {
	t.Helper()
	dir := t.TempDir()
	gitRun(t, dir, "init")
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", name, err)
		}
	}
	write("go.mod", "module example.com/m\n\ngo 1.21\n")
	if attributes != "" {
		write(".gitattributes", attributes)
	}
	gitRun(t, dir, "add", ".")
	gitRun(t, dir, "commit", "-m", "initial")
	return "file://" + dir, gitRun(t, dir, "rev-parse", "HEAD")
}

// A smudge filter is selected by the repository's own .gitattributes and only
// has to be *defined* in config for checkout to run it — any machine with
// git-lfs installed defines one. Checking out attacker-controlled content must
// not execute it.
func TestCheckoutToDir_SmudgeFilterFromPoisonedConfigDoesNotRun(t *testing.T) {
	requireGit(t)
	repoURL, commit := repoWithAttributes(t, "* filter=pwn\n")

	// The filter body lives in a script file rather than inline: git config
	// treats ";" as starting a comment, so an inline "touch X; cat" would be
	// truncated and the test would pass because the fixture was broken.
	sentinel := filepath.Join(t.TempDir(), "smudge-ran")
	script := filepath.Join(t.TempDir(), "pwn.sh")
	body := fmt.Sprintf("#!/bin/sh\ntouch %s\ncat\n", sentinel)
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { //nolint:gosec // an executable filter is the point of the fixture
		t.Fatalf("writing smudge script: %v", err)
	}
	poisonHome(t, "[filter \"pwn\"]\n\tsmudge = "+script+"\n\tclean = cat\n")

	checkoutDir := t.TempDir()
	c := gitexec.NewWithProtocols("https:file")
	if err := c.CheckoutToDir(context.Background(), repoURL, commit, checkoutDir); err != nil {
		t.Fatalf("CheckoutToDir: %v", err)
	}

	if _, err := os.Stat(sentinel); err == nil {
		t.Error("the smudge filter defined in the ambient git config ran during checkout")
	}
	// Fail-safe, not fail-broken: with no filter defined the content is taken
	// verbatim, so cross-verification still sees the real bytes.
	data, err := os.ReadFile(filepath.Join(checkoutDir, "go.mod")) //nolint:gosec // path rooted in t.TempDir
	if err != nil {
		t.Fatalf("reading go.mod after checkout: %v", err)
	}
	if !strings.Contains(string(data), "module example.com/m") {
		t.Errorf("go.mod content = %q, want the committed bytes", data)
	}
}

// core.hooksPath in an ambient config points checkout's post-checkout hook at a
// directory of the attacker's choosing. No hook may run.
func TestCheckoutToDir_HooksPathFromPoisonedConfigDoesNotRun(t *testing.T) {
	requireGit(t)
	repoURL, commit := repoWithAttributes(t, "")

	hookDir := t.TempDir()
	sentinel := filepath.Join(t.TempDir(), "hook-ran")
	hook := fmt.Sprintf("#!/bin/sh\ntouch %s\n", sentinel)
	if err := os.WriteFile(filepath.Join(hookDir, "post-checkout"), []byte(hook), 0o700); err != nil { //nolint:gosec // an executable hook is the point of the fixture
		t.Fatalf("writing post-checkout hook: %v", err)
	}
	poisonHome(t, "[core]\n\thooksPath = "+hookDir+"\n")

	c := gitexec.NewWithProtocols("https:file")
	if err := c.CheckoutToDir(context.Background(), repoURL, commit, t.TempDir()); err != nil {
		t.Fatalf("CheckoutToDir: %v", err)
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Error("the post-checkout hook from the ambient core.hooksPath ran")
	}
}

// url.<base>.insteadOf rewrites a fetch URL after the application layer has
// validated it against the VCS host allowlist. The rewritten host must never be
// contacted: bytes fetched from it would be cross-verified as though they came
// from the legitimate origin, corrupting the verdict silently.
func TestCheckoutToDir_InsteadOfRewriteDoesNotReachRewrittenHost(t *testing.T) {
	requireGit(t)

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

	// A .invalid host never resolves, so an un-rewritten fetch fails locally
	// and the test performs no real network egress either way. Any connection
	// the listener sees can only have come from the insteadOf rewrite.
	poisonHome(t, fmt.Sprintf(
		"[url \"http://%s/\"]\n\tinsteadOf = https://kanonarion-test.invalid/\n", ln.Addr()))

	c := gitexec.NewWithProtocols("https:http")
	c.SetFetchBounds(1, 5*time.Second)
	// The fetch is expected to fail — the host does not resolve. What matters
	// is where it failed to reach, not that it failed.
	_ = c.CheckoutToDir(context.Background(),
		"https://kanonarion-test.invalid/example/mod", strings.Repeat("a", 40), t.TempDir())

	if got := connections.Load(); got != 0 {
		t.Errorf("the rewritten host received %d connections; insteadOf from the ambient config bypassed the host allowlist", got)
	}
}

// runGitWithAdapterEnv runs git with exactly the environment and -c overrides
// the adapter hands its subprocesses, so assertions are about the production
// configuration rather than a re-creation of it.
func runGitWithAdapterEnv(t *testing.T, c *gitexec.Client, dir string, args ...string) string {
	t.Helper()
	home := t.TempDir()
	cmd := exec.Command("git", append(c.ConfigArgs(), args...)...) //nolint:gosec // binary hard-coded, args are literals
	cmd.Dir = dir
	cmd.Env = c.GitEnv(home, dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// The whole config surface must be closed: with a poisoned HOME, a poisoned
// XDG_CONFIG_HOME and inherited GIT_CONFIG_* variables all present, an
// invocation must read no configuration file outside its own directories.
func TestGitEnv_ReadsNoAmbientConfigFile(t *testing.T) {
	requireGit(t)

	poisoned := t.TempDir()
	globalFile := filepath.Join(poisoned, "poisoned-global")
	if err := os.WriteFile(globalFile, []byte("[core]\n\thooksPath = /poisoned\n"), 0o600); err != nil {
		t.Fatalf("writing poisoned global config: %v", err)
	}
	poisonHome(t, "[core]\n\tfsmonitor = /poisoned/fsmonitor\n")
	// Inherited GIT_CONFIG_* is the case an append-to-os.Environ() build cannot
	// close: the hostile value is present in the block before the override.
	t.Setenv("GIT_CONFIG_GLOBAL", globalFile)
	t.Setenv("GIT_CONFIG_SYSTEM", globalFile)
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
	t.Setenv("GIT_CONFIG_VALUE_0", "/poisoned")

	c := gitexec.New()
	out := runGitWithAdapterEnv(t, c, t.TempDir(), "config", "--list", "--show-origin")

	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		origin, _, ok := strings.Cut(line, "\t")
		if !ok {
			t.Errorf("unparseable config line %q", line)
			continue
		}
		if strings.HasPrefix(origin, "file:") {
			t.Errorf("git read configuration from %q; the config surface is not closed (line %q)", origin, line)
		}
	}
	if strings.Contains(out, "/poisoned") {
		t.Errorf("poisoned values survived into the effective config:\n%s", out)
	}
}

// The GITHUB_TOKEN credential is the one configuration entry the adapter means
// to inject. With config discovery neutralised it must be the only one in
// effect — asserted rather than left to inspection.
func TestGitEnv_TokenConfigIsTheOnlyConfigInEffect(t *testing.T) {
	requireGit(t)

	poisonHome(t, "[core]\n\thooksPath = /poisoned\n")
	t.Setenv("GITHUB_TOKEN", "fixture-token-not-a-credential")

	c := gitexec.New()
	out := runGitWithAdapterEnv(t, c, t.TempDir(), "config", "--list")

	// Keys alone cannot decide this: the adapter sets core.hooksPath itself, so
	// a poisoned core.hooksPath would hide behind an expected key. Assert on the
	// full key=value line.
	want := map[string]bool{
		"core.hookspath=/dev/null": true,
		"core.fsmonitor=":          true,
		"protocol.ext.allow=never": true,
		"http.https://github.com/.extraheader=Authorization: token fixture-token-not-a-credential": true,
	}
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		if !want[line] {
			t.Errorf("unexpected config in effect: %q; only the token entry and the adapter's own overrides should apply\n%s", line, out)
		}
	}
	if !strings.Contains(out, "extraheader=Authorization: token fixture-token-not-a-credential") {
		t.Errorf("the GITHUB_TOKEN header is not in effect:\n%s", out)
	}
}

// Neutralising the config must not change what cross-verification measures: a
// well-formed repository resolves to the same commit and yields the same tree.
func TestCheckoutToDir_WellFormedRepoUnchangedUnderPoisonedConfig(t *testing.T) {
	requireGit(t)
	repoURL, commit, tagRef := setupRepo(t)

	// Read the expected tree from the fixture with a clean git, before the
	// poisoned config is installed.
	fixtureDir := strings.TrimPrefix(repoURL, "file://")
	wantTree := gitRun(t, fixtureDir, "rev-parse", commit+"^{tree}")

	poisonHome(t, "[core]\n\thooksPath = /poisoned\n[filter \"pwn\"]\n\tsmudge = false\n")

	c := gitexec.NewWithProtocols("https:file")
	got, err := c.ResolveTag(context.Background(), repoURL, tagRef)
	if err != nil {
		t.Fatalf("ResolveTag under poisoned config: %v", err)
	}
	if got != commit {
		t.Errorf("ResolveTag = %q, want %q", got, commit)
	}

	checkoutDir := t.TempDir()
	if err := c.CheckoutToDir(context.Background(), repoURL, commit, checkoutDir); err != nil {
		t.Fatalf("CheckoutToDir under poisoned config: %v", err)
	}
	gotTree := gitRun(t, checkoutDir, "rev-parse", "HEAD^{tree}")
	if gotTree != wantTree {
		t.Errorf("checked-out tree = %q, want %q", gotTree, wantTree)
	}
}

// kanonarion is routinely run from inside a git repository — its own, or one a
// developer is inspecting. Repository-local .git/config is the one config file
// GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM do not govern, so an operation that
// needs no repository must not stand anywhere one can be found. Otherwise an
// insteadOf in the enclosing repo's config rewrites the URL after
// ValidateCloneURL has passed it, and the allowlist is bypassed exactly as it
// is via a poisoned ~/.gitconfig.
func TestResolveTag_EnclosingRepoConfigDoesNotRewriteURL(t *testing.T) {
	requireGit(t)

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

	// A repository whose own config carries the rewrite, with a clean HOME so
	// the only possible source is .git/config.
	repo := t.TempDir()
	gitRun(t, repo, "init")
	cfg := fmt.Sprintf("\n[url \"http://%s/\"]\n\tinsteadOf = https://kanonarion-test.invalid/\n", ln.Addr())
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

	c := gitexec.NewWithProtocols("https:http")
	// Expected to fail: the host does not resolve. Where it failed to reach is
	// the assertion.
	_, _ = c.ResolveTag(context.Background(),
		"https://kanonarion-test.invalid/example/mod", "refs/tags/v1.0.0")

	if got := connections.Load(); got != 0 {
		t.Errorf("the rewritten host received %d connections; the enclosing repository's .git/config was applied", got)
	}
}
