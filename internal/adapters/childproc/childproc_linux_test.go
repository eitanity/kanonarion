//go:build linux

package childproc

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// helperPIDFileEnv switches the test binary into helper mode: it spawns a
// hardened child, publishes that child's pid, and then kills itself.
const helperPIDFileEnv = "KANON_CHILDPROC_HELPER_PIDFILE"

func TestHardenSetsParentDeathSignal(t *testing.T) {
	cmd := CommandContext(t.Context(), "/bin/true")
	if cmd.SysProcAttr == nil {
		t.Fatal("SysProcAttr is nil; no parent-death signal requested")
	}
	if cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Errorf("Pdeathsig = %v, want SIGKILL", cmd.SysProcAttr.Pdeathsig)
	}
	if !cmd.SysProcAttr.Setpgid {
		t.Error("Setpgid = false; the child would share the parent's group")
	}
}

// TestChildDiesWhenParentIsKilled reproduces the reported failure: the parent
// is SIGKILLed, so no user-space watcher — including the one
// exec.CommandContext installs — ever runs. Only the kernel's parent-death
// signal can reap the child, and it must.
func TestChildDiesWhenParentIsKilled(t *testing.T) {
	if os.Getenv(helperPIDFileEnv) != "" {
		runSuicidalParent(t)
		return
	}

	pidFile := filepath.Join(t.TempDir(), "child.pid")
	helper := exec.Command(os.Args[0], "-test.run=TestChildDiesWhenParentIsKilled", "-test.v") // #nosec G204 G702 -- re-execs this very test binary; the args are literals
	helper.Env = append(os.Environ(), helperPIDFileEnv+"="+pidFile)
	if err := helper.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}

	child := readPIDFile(t, pidFile)
	defer func() { _ = syscall.Kill(child, syscall.SIGKILL) }()

	// The helper SIGKILLs itself once the pid is published.
	_ = helper.Wait()
	if !waitGone(t, helper.Process.Pid, 5*time.Second) {
		t.Fatalf("helper parent %d did not die", helper.Process.Pid)
	}

	if !waitGone(t, child, 10*time.Second) {
		t.Errorf("child %d outlived its SIGKILLed parent", child)
	}
}

// runSuicidalParent is the helper half of TestChildDiesWhenParentIsKilled. It
// must not clean up: an orderly exit would defeat the point.
func runSuicidalParent(t *testing.T) {
	t.Helper()
	pidFile := os.Getenv(helperPIDFileEnv)

	// context.Background, not t.Context: the test framework's cancellation must
	// not be what kills this child.
	cmd := CommandContext(context.Background(), "/bin/sleep", "120")
	if err := cmd.Start(); err != nil {
		t.Fatalf("helper: start child: %v", err)
	}
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil { // #nosec G703 -- pidFile is this test's own temp path, passed through the environment
		t.Fatalf("helper: write pid file: %v", err)
	}

	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
	select {} // unreachable; the signal is not catchable
}
