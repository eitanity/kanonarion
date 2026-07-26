//go:build unix && !linux

package childproc

import (
	"os/exec"
	"syscall"
)

// harden puts the child in its own process group. Only Linux exposes a
// parent-death signal, so elsewhere group-wide cancellation is the whole of the
// protection.
func harden(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}
