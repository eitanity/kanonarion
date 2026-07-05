package local

import (
	"bytes"
	"context"
	"os/exec"
)

// OsSubprocessExecutor runs a subprocess using the OS exec package.
// The binary path is resolved once at construction via [os.Executable] and
// reused for every call.
type OsSubprocessExecutor struct {
	binary string
}

// NewOsSubprocessExecutor constructs an OsSubprocessExecutor using the
// already-resolved binary path. Callers must resolve os.Executable themselves
// and pass the result so construction can propagate the error.
func NewOsSubprocessExecutor(binary string) OsSubprocessExecutor {
	return OsSubprocessExecutor{binary: binary}
}

// Execute runs binary with args under ctx. It captures stderr and returns it
// alongside any error. A non-zero exit code results in a non-nil error
// (typically *exec.ExitError). Context cancellation/deadline propagates as-is.
func (e OsSubprocessExecutor) Execute(ctx context.Context, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, e.binary, args...) // #nosec G204 -- binary resolved from os.Executable; args constructed from internal coord strings only
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stderr.Bytes(), err
}
