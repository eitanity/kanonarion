//go:build unix

package childproc

import (
	"os/exec"
	"syscall"
)

// killGroup SIGKILLs the child's whole process group, so grandchildren the
// child spawned die with it. It falls back to killing the process alone if the
// group signal fails — the group may already be gone, or the process may have
// started before Setpgid took effect.
func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err == nil {
		return nil
	}
	return cmd.Process.Kill() //nolint:wrapcheck // os.Process.Kill's error is reported verbatim by exec's cancellation
}
