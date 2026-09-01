//go:build linux

package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The helper half of TestGoListChildDiesWithAKilledParent runs in a re-exec of
// this test binary. It is switched on by the first variable and reports the two
// children it started through the other two.
const (
	goListOrphanHelperEnv   = "KANON_CLI_GOLIST_ORPHAN_HELPER"
	goListOrphanHardenedPID = "KANON_CLI_GOLIST_ORPHAN_HARDENED_PIDFILE"
	goListOrphanControlPID  = "KANON_CLI_GOLIST_ORPHAN_CONTROL_PIDFILE"
)

// fakeGo writes a stand-in `go` at dir/go that publishes its own pid and then
// blocks. A real `go list ./...` over a large tree runs for minutes, which is
// what makes the orphan worth preventing and what makes it useless as a test
// fixture: the child has to be long-lived on purpose, not by luck.
func fakeGo(t *testing.T, dir, pidFile string) string {
	t.Helper()
	path := filepath.Join(dir, "go")
	script := "#!/bin/sh\necho $$ > " + pidFile + "\nexec sleep 120\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 G703 -- a test fixture under this test's own temp dir that must be executable
		t.Fatalf("writing fake go at %s: %v", path, err)
	}
	return path
}

// awaitPID waits for path to hold a complete pid and returns it.
func awaitPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path) // #nosec G304 G703 -- path is this test's own temp file
		if err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				if pid, cerr := strconv.Atoi(s); cerr == nil {
					return pid
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no pid ever appeared at %s", path)
	return 0
}

// processAlive reports whether pid still exists; signal 0 probes without
// delivering.
func processAlive(pid int) bool { return syscall.Kill(pid, 0) == nil }

// awaitGone polls until pid disappears or the budget runs out. Teardown after a
// parent-death signal is asynchronous, so a single probe would be flaky.
func awaitGone(pid int, budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return !processAlive(pid)
}

// TestGoListChildDiesWithAKilledParent measures the behaviour this file's
// context plumbing exists for, on the production path rather than at the call
// site.
//
// The parent is SIGKILLed. Nothing in user space runs when that happens: no
// deferred cleanup, no signal handler, and not the watcher goroutine
// exec.CommandContext installs — so a context is not what saves the child here,
// and neither is the CLI's signal.NotifyContext. Only PR_SET_PDEATHSIG, which
// childproc asks the kernel for, reaps it.
//
// Both children are started in the same helper process, from the same fake `go`
// on PATH, and differ only in which constructor built them. The unhardened one
// is the control: it is still running after its parent is gone, which is what
// runGoList did before, and it is the reason the assertion on the hardened one
// means anything.
func TestGoListChildDiesWithAKilledParent(t *testing.T) {
	if os.Getenv(goListOrphanHelperEnv) != "" {
		runGoListOrphanHelper(t)
		return
	}

	tmp := t.TempDir()
	hardenedPIDFile := filepath.Join(tmp, "hardened.pid")
	controlPIDFile := filepath.Join(tmp, "control.pid")

	helper := exec.Command(os.Args[0], "-test.run=TestGoListChildDiesWithAKilledParent", "-test.v") // #nosec G204 G702 -- re-execs this very test binary; the args are literals
	helper.Env = append(os.Environ(),
		goListOrphanHelperEnv+"=1",
		goListOrphanHardenedPID+"="+hardenedPIDFile,
		goListOrphanControlPID+"="+controlPIDFile,
	)
	if err := helper.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}

	hardened := awaitPID(t, hardenedPIDFile)
	control := awaitPID(t, controlPIDFile)
	defer func() {
		_ = syscall.Kill(hardened, syscall.SIGKILL)
		_ = syscall.Kill(control, syscall.SIGKILL)
	}()

	_ = helper.Wait()
	if !awaitGone(helper.Process.Pid, 10*time.Second) {
		t.Fatalf("helper parent %d did not die", helper.Process.Pid)
	}

	// The control first: if it were already gone the measurement would say
	// nothing about the hardening, only that something else killed both.
	if !processAlive(control) {
		t.Fatalf("the unhardened control child %d is already gone; "+
			"this measurement cannot distinguish the hardening from whatever killed it", control)
	}
	if !awaitGone(hardened, 15*time.Second) {
		t.Errorf("the `go list` child %d outlived its SIGKILLed parent", hardened)
	}
	if !processAlive(control) {
		t.Errorf("the unhardened control child %d died too; the two constructors are no longer being compared", control)
	}
}

// runGoListOrphanHelper is the helper half. It must not clean up after itself
// beyond the store directory: an orderly exit would defeat the point.
func runGoListOrphanHelper(t *testing.T) {
	t.Helper()

	hardenedDir := t.TempDir()
	controlDir := t.TempDir()
	fakeGo(t, hardenedDir, os.Getenv(goListOrphanHardenedPID))
	controlGo := fakeGo(t, controlDir, os.Getenv(goListOrphanControlPID))

	// runGoList resolves "go" through PATH, so the stand-in has to be found
	// there rather than passed in: the production path takes no binary argument.
	t.Setenv("PATH", hardenedDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	// context.Background, not t.Context: the test framework's cancellation must
	// not be what kills either child.
	go func() { _, _ = runGoList(context.Background(), hardenedDir, []string{"list", "./..."}) }()

	control := exec.CommandContext(context.Background(), controlGo, "list", "./...") // #nosec G204 -- controlGo is this test's own fixture path
	control.Dir = controlDir
	if err := control.Start(); err != nil {
		t.Fatalf("helper: start control child: %v", err)
	}

	awaitPID(t, os.Getenv(goListOrphanHardenedPID))
	awaitPID(t, os.Getenv(goListOrphanControlPID))

	// TestMain made a store directory this process will never unwind; remove it
	// before the signal, since nothing after the signal runs.
	if store := os.Getenv("KANONARION_STORE"); store != "" {
		_ = os.RemoveAll(store) // #nosec G703 -- the temp store directory TestMain itself created
	}

	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
	select {} // unreachable; SIGKILL is not catchable
}
