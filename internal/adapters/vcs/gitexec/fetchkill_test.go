package gitexec_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/adapters/vcs/gitexec"
	"code.eitanity.com/kanonarion/internal/fetch/ports"
)

// fakeGit puts a scripted `git` first on PATH that logs every invocation.
// ls-remote runs lsRemote and the single-commit fetch runs firstFetch (shell);
// a slow fetch takes the shallow lock first, the way a real git does, so a
// fallback that reused the directory would fail on it. Every other command
// succeeds.
func fakeGit(t *testing.T, lsRemote, firstFetch string) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "argv.log")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$*\" >> " + logPath + "\n" +
		"case \"$*\" in\n" +
		"  *' ls-remote '*) " + lsRemote + ";;\n" +
		"  *' init'*) mkdir -p .git; exit 0;;\n" +
		"  *' fetch --depth=1 '*) " + firstFetch + ";;\n" +
		"  *' fetch '*) if [ -e .git/shallow.lock ]; then echo \"fatal: Unable to create '.git/shallow.lock': File exists.\" >&2; exit 128; fi; exit 0;;\n" +
		"esac\n" +
		"exit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o700); err != nil { // #nosec G306 -- an executable stub must be executable
		t.Fatalf("writing git stub: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	permittedGit(t)
	return logPath
}

const slowFetch = "touch .git/shallow.lock; exec /bin/sleep 30"

func fetchCalls(t *testing.T, logPath string) int {
	t.Helper()
	n := 0
	for _, line := range spawns(t, logPath) {
		if strings.Contains(line, " fetch ") {
			n++
		}
	}
	return n
}

// A fetch killed at its bound returns the timeout as the cause and starts no
// further git in that directory: no fallback, no lock-file message.
func TestCheckoutToDir_FetchPastBoundIsNotRetriedInTheSameDirectory(t *testing.T) {
	logPath := fakeGit(t, "exit 0", slowFetch)
	c := gitexec.New()
	c.SetFetchBounds(8, 300*time.Millisecond)

	err := c.CheckoutToDir(context.Background(), "https://github.com/foo/bar", strings.Repeat("a", 40), t.TempDir())
	if !errors.Is(err, ports.ErrVCSRemoteTimeout) {
		t.Fatalf("err = %v, want it to wrap ports.ErrVCSRemoteTimeout", err)
	}
	if !strings.Contains(err.Error(), "exceeded the 300ms fetch bound") {
		t.Errorf("error %q does not name the bound", err)
	}
	if strings.Contains(err.Error(), "shallow.lock") {
		t.Errorf("error %q names the lock the killed git left behind", err)
	}
	if n := fetchCalls(t, logPath); n != 1 {
		t.Errorf("git fetch ran %d times, want 1: a killed fetch was followed by another", n)
	}
	got := spawns(t, logPath)
	if last := got[len(got)-1]; !strings.Contains(last, " fetch --depth=1 ") {
		t.Errorf("a git command ran after the killed fetch: %q", last)
	}
}

// A single-commit fetch that git itself refuses still falls back to the
// bounded fetch, and the checkout completes.
func TestCheckoutToDir_RefusedSingleCommitFetchStillFallsBack(t *testing.T) {
	logPath := fakeGit(t, "exit 0", "echo 'error: Server does not allow request for unadvertised object' >&2; exit 128")
	c := gitexec.New()
	c.SetFetchBounds(8, time.Minute)

	if err := c.CheckoutToDir(context.Background(), "https://github.com/foo/bar", strings.Repeat("a", 40), t.TempDir()); err != nil {
		t.Fatalf("CheckoutToDir: %v", err)
	}
	if n := fetchCalls(t, logPath); n != 2 {
		t.Errorf("git fetch ran %d times, want 2 (single-commit, then the fallback)", n)
	}
	got := spawns(t, logPath)
	if last := got[len(got)-1]; !strings.Contains(last, " checkout ") {
		t.Errorf("last git command = %q, want the checkout", last)
	}
}

// A fetch stopped because the caller's context ended is not retried, and the
// context's error is what comes back.
func TestCheckoutToDir_CancelledFetchIsNotRetried(t *testing.T) {
	logPath := fakeGit(t, "exit 0", slowFetch)
	c := gitexec.New()
	c.SetFetchBounds(8, time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(300*time.Millisecond, cancel)
	defer timer.Stop()

	err := c.CheckoutToDir(ctx, "https://github.com/foo/bar", strings.Repeat("a", 40), t.TempDir())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if errors.Is(err, ports.ErrVCSRemoteTimeout) {
		t.Errorf("a cancelled fetch was reported as a remote timeout: %v", err)
	}
	if n := fetchCalls(t, logPath); n != 1 {
		t.Errorf("git fetch ran %d times, want 1: a cancelled fetch was followed by another", n)
	}
}

// An ls-remote that outlives the bound returns the timeout, names the bound,
// and is the only git command run.
func TestResolveTag_LsRemotePastBoundTimesOut(t *testing.T) {
	logPath := fakeGit(t, "exec /bin/sleep 30", "exit 0")
	c := gitexec.New()
	c.SetFetchBounds(8, 300*time.Millisecond)

	start := time.Now()
	_, err := c.ResolveTag(context.Background(), "https://github.com/foo/bar", "refs/tags/v1.0.0")
	if !errors.Is(err, ports.ErrVCSRemoteTimeout) {
		t.Fatalf("err = %v, want it to wrap ports.ErrVCSRemoteTimeout", err)
	}
	if !strings.Contains(err.Error(), "exceeded the 300ms fetch bound") {
		t.Errorf("error %q does not name the bound", err)
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Errorf("ResolveTag took %s against a stalling remote; the bound is not enforced", elapsed)
	}
	if got := spawns(t, logPath); len(got) != 1 || !strings.Contains(got[0], " ls-remote ") {
		t.Errorf("git invocations = %q, want the one ls-remote", got)
	}
}

// An ls-remote stopped because the caller's context ended returns the
// context's error, not the timeout.
func TestResolveTag_CancelledLsRemoteReturnsTheContextError(t *testing.T) {
	fakeGit(t, "exec /bin/sleep 30", "exit 0")
	c := gitexec.New()
	c.SetFetchBounds(8, time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(300*time.Millisecond, cancel)
	defer timer.Stop()

	_, err := c.ResolveTag(ctx, "https://github.com/foo/bar", "refs/tags/v1.0.0")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if errors.Is(err, ports.ErrVCSRemoteTimeout) {
		t.Errorf("a cancelled ls-remote was reported as a remote timeout: %v", err)
	}
}
