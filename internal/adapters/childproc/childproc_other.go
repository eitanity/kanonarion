//go:build !unix

package childproc

import "os/exec"

// harden is a no-op on platforms with neither process groups nor a
// parent-death signal; cancellation there is what the os/exec default gives.
func harden(_ *exec.Cmd) {}

// killGroup kills the direct child only, which is all the platform offers.
func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill() //nolint:wrapcheck // os.Process.Kill's error is reported verbatim by exec's cancellation
}
