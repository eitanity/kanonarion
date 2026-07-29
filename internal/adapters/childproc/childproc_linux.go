//go:build linux

package childproc

import (
	"os/exec"
	"syscall"
)

// harden puts the child in its own process group and asks the kernel to
// SIGKILL it the moment its parent dies.
//
// Pdeathsig is tied to the parent *thread* that forked the child rather than
// the parent process, so in principle a Go runtime thread exiting could deliver
// the signal early. The spawning goroutine is not locked to its thread, which
// leaves the child on an ordinary M — the runtime parks those rather than
// tearing them down — and the alternative is the orphan this package exists to
// prevent.
func harden(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
}
