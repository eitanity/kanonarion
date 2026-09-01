//go:build unix

package childproc

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// alive reports whether pid still exists (signal 0 probes without delivering).
func alive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

// waitGone polls until pid disappears or the budget runs out. Process teardown
// after a group kill is asynchronous, so a single probe would be flaky.
func waitGone(t *testing.T, pid int, budget time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if !alive(pid) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return !alive(pid)
}

// readPIDFile waits for path to contain a complete PID line and returns it.
func readPIDFile(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path) // #nosec G304 -- path is a test temp file
		if err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				pid, convErr := strconv.Atoi(s)
				if convErr == nil {
					return pid
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("grandchild pid file %s never appeared", path)
	return 0
}

func TestRunCapturesStderrAndExitStatus(t *testing.T) {
	t.Run("exit 0 returns nil error and empty stderr", func(t *testing.T) {
		stderr, err := Run(t.Context(), "/bin/sh", "-c", "exit 0")
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if len(stderr) != 0 {
			t.Errorf("expected empty stderr, got %q", stderr)
		}
	})

	t.Run("non-zero exit returns error with stderr", func(t *testing.T) {
		stderr, err := Run(t.Context(), "/bin/sh", "-c", "echo captured >&2; exit 3")
		if err == nil {
			t.Fatal("expected non-nil error for exit 3")
		}
		if !strings.Contains(string(stderr), "captured") {
			t.Errorf("stderr = %q, want it to contain 'captured'", stderr)
		}
	})

	t.Run("context cancellation terminates the child", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		if _, err := Run(ctx, "/bin/sleep", "60"); err == nil {
			t.Fatal("expected error from killed child")
		}
	})
}

// TestCancellationKillsGrandchildren is the behaviour os/exec does not give:
// exec.CommandContext signals the direct child only, so a grandchild the child
// spawned outlives the cancel. The child here execs sleep in the background and
// then sleeps itself; after cancellation both must be gone.
func TestCancellationKillsGrandchildren(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	script := "/bin/sleep 60 & echo $! > " + pidFile + "; /bin/sleep 60"

	ctx, cancel := context.WithCancel(t.Context())
	cmd := CommandContext(ctx, "/bin/sh", "-c", script)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	grandchild := readPIDFile(t, pidFile)
	if !alive(grandchild) {
		t.Fatalf("grandchild %d not running before cancel", grandchild)
	}

	cancel()
	_ = cmd.Wait()

	if !waitGone(t, cmd.Process.Pid, 5*time.Second) {
		t.Errorf("child %d survived cancellation", cmd.Process.Pid)
	}
	if !waitGone(t, grandchild, 5*time.Second) {
		// Kill it so a failing test does not leave a 60s sleeper behind.
		_ = syscall.Kill(grandchild, syscall.SIGKILL)
		t.Errorf("grandchild %d survived cancellation of its parent's group", grandchild)
	}
}

// TestChildLeadsItsOwnProcessGroup pins the precondition the group kill relies
// on: the child's process-group id equals its own pid.
func TestChildLeadsItsOwnProcessGroup(t *testing.T) {
	cmd := CommandContext(t.Context(), "/bin/sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() { _ = killGroup(cmd); _ = cmd.Wait() }()

	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("getpgid: %v", err)
	}
	if pgid != cmd.Process.Pid {
		t.Errorf("pgid = %d, want the child's own pid %d", pgid, cmd.Process.Pid)
	}
	if pgid == syscall.Getpgrp() {
		t.Error("child shares the parent's process group; a group kill would hit the parent")
	}
}

// TestKillGroupOnUnstartedCommandIsNoop covers the cancel path racing a failed
// Start: there is no process to signal and no error to report.
func TestKillGroupOnUnstartedCommandIsNoop(t *testing.T) {
	cmd := CommandContext(t.Context(), "/bin/true")
	if err := killGroup(cmd); err != nil {
		t.Errorf("killGroup on unstarted command = %v, want nil", err)
	}
}

// TestCommandContextPreservesCallerFields checks the wrapper only adds
// lifetime hardening: output capture, Dir and Env stay the caller's.
func TestCommandContextPreservesCallerFields(t *testing.T) {
	dir := t.TempDir()
	cmd := CommandContext(t.Context(), "/bin/sh", "-c", "pwd; echo $KANON_TEST_VAR")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "KANON_TEST_VAR=set-by-caller")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	got := string(out)
	if !strings.Contains(got, "set-by-caller") {
		t.Errorf("output %q missing caller Env value", got)
	}
	// macOS resolves TempDir through /private, so compare on the suffix.
	if !strings.Contains(got, filepath.Base(dir)) {
		t.Errorf("output %q does not reflect caller Dir %s", got, dir)
	}
	if cmd.WaitDelay != 0 {
		t.Errorf("WaitDelay = %v, want the caller's zero value", cmd.WaitDelay)
	}
}

// TestRunSetsWaitDelay records that Run, unlike CommandContext, bounds the
// post-exit pipe wait — a child that leaks its stderr to a surviving
// grandchild must not block the caller forever.
func TestRunSetsWaitDelay(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "holder.pid")
	// The backgrounded sleep inherits stderr and holds the pipe open after the
	// direct child exits. Without WaitDelay, Run would block until it finishes.
	script := "/bin/sleep 30 & echo $! > " + pidFile + "; echo done >&2; exit 0"

	start := time.Now()
	stderr, err := Run(t.Context(), "/bin/sh", "-c", script)
	elapsed := time.Since(start)

	grandchild := readPIDFile(t, pidFile)
	defer func() { _ = syscall.Kill(grandchild, syscall.SIGKILL) }()

	if elapsed > WaitDelay+5*time.Second {
		t.Errorf("Run blocked for %v on an inherited pipe; WaitDelay is %v", elapsed, WaitDelay)
	}
	if err != nil && !strings.Contains(err.Error(), "WaitDelay") && !strings.Contains(err.Error(), "wait") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(stderr), "done") {
		t.Errorf("stderr = %q, want it to contain 'done'", stderr)
	}
}
