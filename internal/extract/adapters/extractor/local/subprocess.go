package local

import (
	"context"

	"github.com/eitanity/kanonarion/internal/adapters/childproc"
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
//
// The child runs through childproc: these are callgraph extractions whose SSA
// closure can hold several GB, so they must die with this process rather than
// outliving it as orphans.
func (e OsSubprocessExecutor) Execute(ctx context.Context, args []string) ([]byte, error) {
	return childproc.Run(ctx, e.binary, args...) //nolint:wrapcheck // the caller classifies the raw exec error (exit status, context deadline); wrapping it here would rewrite the text those classifiers read
}
