package local

import (
	"context"
	"io"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/childproc"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
)

// OsSubprocessExecutor runs a subprocess using the OS exec package.
// The binary path is resolved once at construction via [os.Executable] and
// reused for every call.
type OsSubprocessExecutor struct {
	binary string
	bounds childproc.Bounds
}

// NewOsSubprocessExecutor constructs an OsSubprocessExecutor using the
// already-resolved binary path. Callers must resolve os.Executable themselves
// and pass the result so construction can propagate the error.
//
// ceiling is the wall-clock backstop for one child; zero takes the default. The
// deadline that normally ends a wedged child is the stall window, not this one —
// see cgports.DefaultStallWindow.
func NewOsSubprocessExecutor(binary string, ceiling time.Duration, progress io.Writer) OsSubprocessExecutor {
	if ceiling <= 0 {
		ceiling = cgports.DefaultCeiling
	}
	return OsSubprocessExecutor{
		binary: binary,
		bounds: childproc.Bounds{
			Stall:          cgports.DefaultStallWindow,
			Ceiling:        ceiling,
			ProgressPrefix: cgports.ProgressPrefix,
			Progress:       progress,
		},
	}
}

// Execute runs binary with args under ctx. It captures stderr and returns it
// alongside any error. A non-zero exit code results in a non-nil error
// (typically *exec.ExitError). Context cancellation/deadline propagates as-is.
//
// The child runs through childproc: these are callgraph extractions whose SSA
// closure can hold several GB, so they must die with this process rather than
// outliving it as orphans — and they are bounded by the progress they report
// rather than by elapsed time, because a large module under a busy worker pool
// takes longer without having stopped.
func (e OsSubprocessExecutor) Execute(ctx context.Context, args []string) ([]byte, error) {
	return childproc.RunBounded(ctx, e.bounds, e.binary, args...) //nolint:wrapcheck // the caller classifies the raw exec error (exit status, deadline sentinel); wrapping it here would rewrite the text those classifiers read
}
