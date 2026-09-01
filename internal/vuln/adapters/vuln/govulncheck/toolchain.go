package govulncheck

import (
	"context"
	"fmt"
	"io"
	"os/exec"

	"github.com/eitanity/kanonarion/internal/adapters/childproc"
	"github.com/eitanity/kanonarion/internal/adapters/goenv"
)

// stderrLimit is how much of a child's own account of a failure is kept. The
// whole of it reaches an ErrorDetail a reader is shown, so it is bounded for the
// same reason every other stored diagnostic is.
const stderrLimit = 2048

// scanChildResult is what one govulncheck child left behind for the caller to
// render: what it said, how it exited, and what its output parsed to.
//
// detail is the child's own account of the failure, or — when nothing on this
// host could serve the Go the module asks for — kanonarion's account of why it
// refused, which names the pinner the go command's own sentence cannot.
type scanChildResult struct {
	detail   string
	waitErr  error
	parseErr error
}

// runGoChild runs one plain Go child of a scan operation in dir, and runs it
// again under a toolchain already unpacked on this host when it refuses for want
// of a newer Go than the installed one.
//
// The combined output is returned on both legs because both callers log it, and
// because it is also where the go command writes the refusal this decision is
// keyed on.
func runGoChild(ctx context.Context, tc *goenv.Toolchains, base []string, dir string, args ...string) ([]byte, error) {
	for {
		cmd := childproc.CommandContext(ctx, "go", args...) // #nosec G204 -- args are literals and paths this package derived
		cmd.Dir = dir
		cmd.Env = tc.Apply(base)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return out, nil
		}
		retry, refusal := tc.Escalate(string(out))
		if refusal != "" {
			return out, fmt.Errorf("%w\n%s", err, refusal) //nolint:wrapcheck // the caller names the command it ran; wrapping here would say it twice
		}
		if !retry {
			return out, err //nolint:wrapcheck // as above
		}
	}
}

// runGovulncheck runs the scan's govulncheck child, streaming its stdout to
// parse, and runs it again under a toolchain already unpacked on this host when
// the go command refuses for want of a newer Go than the installed one.
//
// The two scan entry points share it because they share the failure that made it
// necessary. Their environment pins the toolchain so no scan child can download
// one, which also refuses a toolchain sitting unpacked on the same disk: a module
// whose go directive is ahead of the installed toolchain recorded a failed scan
// on a host that had what it needed. goenv.Toolchains decides that once for the
// whole operation and this runs the child again under its answer.
//
// build makes the child afresh on each attempt because an exec.Cmd cannot be
// started twice, and parse consumes its stdout because each caller parses the
// stream into the shape its own result carries. The returned error is reserved
// for a child that would not start at all, which is not an analysis outcome.
func runGovulncheck(
	tc *goenv.Toolchains,
	base []string,
	build func(env []string) *exec.Cmd,
	parse func(io.Reader) error,
) (scanChildResult, error) {
	for {
		cmd := build(tc.Apply(base))
		stderr := &limitWriter{limit: stderrLimit}
		cmd.Stderr = stderr
		pr, pw := io.Pipe()
		cmd.Stdout = pw

		if err := cmd.Start(); err != nil {
			_ = pw.Close()
			return scanChildResult{}, fmt.Errorf("start govulncheck: %w", err)
		}

		waitErrCh := make(chan error, 1)
		go func() {
			waitErrCh <- cmd.Wait()
			_ = pw.Close() /* #nosec G104 -- pipe close in goroutine, error not actionable */
		}()

		parseErr := parse(pr)
		// Drain before closing so the writer goroutine reaches cmd.Wait() and
		// waitErr is settled: a scan that died mid-stream must be classified as the
		// failure it is, not as the truncated parse it also produced. The channel
		// receive is the synchronisation edge that publishes the goroutine's write
		// to this goroutine.
		_, _ = io.Copy(io.Discard, pr)
		_ = pr.Close()
		waitErr := <-waitErrCh

		if waitErr == nil {
			return scanChildResult{parseErr: parseErr}, nil
		}
		detail := stderr.String()
		retry, refusal := tc.Escalate(detail)
		if refusal != "" {
			return scanChildResult{detail: refusal, waitErr: waitErr, parseErr: parseErr}, nil
		}
		if !retry {
			return scanChildResult{detail: detail, waitErr: waitErr, parseErr: parseErr}, nil
		}
	}
}

// ranToolchain reports the Go version a scan's children actually ran under,
// given the toolchain decision the operation took and the directory they ran in.
//
// It re-asks the go command rather than reporting the toolchain the escalation
// picked, for the reason the stamp exists at all: the version is asked of the
// environment the children were handed, so it names what ran rather than what
// was chosen. previous is kept when the question cannot be answered, since a
// stamp that was measured is better than one lost to a failed query.
func ranToolchain(ctx context.Context, tc *goenv.Toolchains, base []string, dir, previous string) string {
	if tc.Selected() == "" {
		return previous
	}
	if v := toolchainGoVersion(ctx, dir, tc.Apply(base)); v != "" {
		return v
	}
	return previous
}
