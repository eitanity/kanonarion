package childproc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/modcache"
)

// Errors a bounded child ends with. They are sentinels because the two are
// different facts about the run and a reader acts on them differently: a stalled
// subprocess stopped, one at the ceiling was still working when it was stopped.
var (
	// ErrStalled means the child reported no progress for the whole stall window.
	ErrStalled = errors.New("child made no progress")
	// ErrCeiling means the child was still reporting progress when the wall-clock
	// backstop expired.
	ErrCeiling = errors.New("child exceeded the wall-clock ceiling")
)

// Bounds is how long a child may run and how it says it is still working.
//
// Two deadlines rather than one, because a single wall clock cannot tell a stalled
// child from a working one and this package exists to bound the first. Stall is
// the instrument: it measures silence. Ceiling is the backstop that still holds
// when a child reports progress forever.
type Bounds struct {
	// Stall is how long the child may go without writing a progress line before
	// it is killed. Zero disables stall detection, leaving Ceiling alone in force.
	Stall time.Duration
	// Ceiling bounds the whole run whatever the child reports. Zero disables it,
	// leaving the caller's context alone in force.
	Ceiling time.Duration
	// ProgressPrefix is what a progress line starts with. A stderr line carrying
	// it resets the stall clock; every other line is captured and nothing more.
	ProgressPrefix string
	// Progress receives each progress line, unchanged, so the operator sees what
	// the parent is deciding on. Nil discards.
	Progress io.Writer
	// MemoryCeiling is how much memory the child may hold before it stops itself,
	// in bytes. Zero hands it no ceiling. It is carried to the child in
	// MemoryCeilingEnv, which is the only route into a process that has not
	// started yet; what the child does with it is EnforceMemoryCeiling.
	MemoryCeiling uint64
}

// RunBounded runs name with args as a hardened child under b, capturing stderr
// and returning it alongside the exec error.
//
// A kill wraps ErrStalled or ErrCeiling so the caller can say which deadline
// ended the run; every other error is the child's own and is returned unwrapped,
// because the callers classify raw exec errors and wrapping would rewrite the
// text those classifiers read.
func RunBounded(ctx context.Context, b Bounds, name string, args ...string) ([]byte, error) {
	runCtx := ctx
	if b.Ceiling > 0 {
		var cancelCeiling context.CancelFunc
		runCtx, cancelCeiling = context.WithTimeout(ctx, b.Ceiling)
		defer cancelCeiling()
	}
	// The stall detector needs its own cancellation: the ceiling context must
	// stay distinguishable afterwards, and a deadline cannot be brought forward.
	childCtx, kill := context.WithCancel(runCtx)
	defer kill()

	watch := &progressWatch{
		prefix: b.ProgressPrefix,
		sink:   b.Progress,
		last:   time.Now(),
	}

	cmd := CommandContext(childCtx, name, args...)
	cmd.WaitDelay = WaitDelay
	cmd.Stderr = watch
	// Appended to this process's own environment rather than replacing it: the
	// child needs every other variable it would have inherited, and os/exec
	// keeps the last value for a duplicated key, so a value handed to this
	// process does not outrank the one it hands on.
	var extra []string
	if b.MemoryCeiling > 0 {
		extra = append(extra, fmt.Sprintf("%s=%d", MemoryCeilingEnv, b.MemoryCeiling))
	}
	scratch, removeScratch := childScratch()
	defer removeScratch()
	if scratch != "" {
		extra = append(extra, scratchEnv(scratch)...)
	}
	if len(extra) > 0 {
		cmd.Env = append(os.Environ(), extra...)
	}

	done := make(chan struct{})
	if b.Stall > 0 && b.ProgressPrefix != "" {
		go watch.stopWhenSilent(done, kill, b.Stall)
	}

	err := cmd.Run()
	close(done)

	// A deadline is only reported when the child actually failed. Both detectors
	// race the child's own exit: a kill fired microseconds after a clean exit
	// would otherwise turn a completed analysis into a coverage gap.
	if err == nil {
		return watch.Bytes(), nil
	}
	switch {
	case watch.stalled():
		return watch.Bytes(), fmt.Errorf("%w for %s: %w", ErrStalled, b.Stall, err)
	case b.Ceiling > 0 && errors.Is(runCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil:
		return watch.Bytes(), fmt.Errorf("%w of %s: %w", ErrCeiling, b.Ceiling, err)
	case errors.Is(ctx.Err(), context.Canceled):
		// The caller's cancellation killed the child. Without it on the error a
		// caller reads the SIGKILL as the operating system ending the analysis.
		return watch.Bytes(), cancelledChild{err: err, stop: ctx.Err()}
	}
	return watch.Bytes(), err //nolint:wrapcheck // the caller classifies the raw exec error (exit status, cancellation); wrapping it here would rewrite the text those classifiers read
}

// progressWatch is the child's stderr: it notices the lines that say the
// analysis moved on, and keeps everything else as the failure detail.
//
// Progress lines are deliberately NOT kept. They are narration the parent has
// already shown the operator; folding twenty of them into the diagnostic a
// failed stage carries would bury the child's actual account of what went wrong.
//
// It is one type rather than a buffer plus a scanner because both ends run
// concurrently — the copying goroutine writes while the watchdog reads the last
// progress time, and WaitDelay lets Wait return while a write is still in
// flight.
type progressWatch struct {
	prefix string
	sink   io.Writer

	mu      sync.Mutex
	buf     bytes.Buffer
	partial bytes.Buffer
	last    time.Time
	killed  bool
}

func (w *progressWatch) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.prefix == "" {
		w.buf.Write(p) //nolint:errcheck // bytes.Buffer.Write never returns an error
		return len(p), nil
	}
	w.partial.Write(p) //nolint:errcheck // as above
	for {
		line, err := w.partial.ReadString('\n')
		if err != nil {
			// An unterminated tail: put it back and wait for the rest. A line is only
			// classifiable once the child has finished writing it.
			w.partial.Reset()
			w.partial.WriteString(line) //nolint:errcheck // as above
			break
		}
		if !strings.HasPrefix(line, w.prefix) {
			w.buf.WriteString(line) //nolint:errcheck // as above
			continue
		}
		w.last = time.Now()
		if w.sink != nil {
			_, _ = fmt.Fprint(w.sink, line)
		}
	}
	return len(p), nil
}

// Bytes returns what the child wrote to stderr other than its progress lines,
// including an unterminated last line — a subprocess stopped mid-sentence still said
// something.
func (w *progressWatch) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := bytes.Clone(w.buf.Bytes())
	if tail := w.partial.String(); tail != "" && !strings.HasPrefix(tail, w.prefix) {
		out = append(out, tail...)
	}
	return out
}

func (w *progressWatch) stalled() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.killed
}

// stopWhenSilent stops the subprocess once stall has passed with no progress line.
//
// It polls rather than arming a timer per line because the lines arrive on the
// copying goroutine and rescheduling a timer from there would put the kill
// decision in the write path. A tenth of the window is close enough: the number
// being enforced is minutes.
func (w *progressWatch) stopWhenSilent(done <-chan struct{}, kill context.CancelFunc, stall time.Duration) {
	tick := stall / 10
	if tick <= 0 {
		tick = time.Millisecond
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case now := <-t.C:
			w.mu.Lock()
			silent := now.Sub(w.last) >= stall
			if silent {
				w.killed = true
			}
			w.mu.Unlock()
			if silent {
				kill()
				return
			}
		}
	}
}

// ScratchPrefix names the directory a parent makes for each child's temporary
// files. `store clean` sweeps it: a parent killed outright leaves it behind.
const ScratchPrefix = "kanonarion-child-"

// childScratch makes the directory a child uses as its temp root, and returns
// it with the function that removes it.
//
// The parent owns it because the child cannot be relied on to clean up: a
// cancelled child is killed with SIGKILL, so its own deferred removals never
// run. Removing the root after Wait reclaims whatever it wrote, read-only
// module-cache trees included. A root that cannot be made leaves the child on
// the inherited temp dir, as before.
func childScratch() (string, func()) {
	dir, err := os.MkdirTemp("", ScratchPrefix+"*")
	if err != nil {
		return "", func() {}
	}
	return dir, func() { _ = modcache.Remove(dir) }
}

// scratchEnv points every temp-dir variable a child may consult at dir: TMPDIR
// for Go and the tools it runs on Unix, TMP and TEMP on Windows.
func scratchEnv(dir string) []string {
	return []string{"TMPDIR=" + dir, "TMP=" + dir, "TEMP=" + dir}
}

// Scratch is the temp root RunBounded gives its child, for a caller that builds
// its own command: env points the child's temp-dir variables at it, and remove,
// called after the child has exited, reclaims what a killed child left there.
// With no root to make, env is empty and the child keeps the inherited temp dir.
func Scratch() (env []string, remove func()) {
	dir, removeDir := childScratch()
	if dir == "" {
		return nil, removeDir
	}
	return scratchEnv(dir), removeDir
}

// cancelledChild is a child's exit error together with the cancellation that
// caused it. It reads as the exit error, whose text callers classify, and it is
// also the cancellation.
type cancelledChild struct{ err, stop error }

func (e cancelledChild) Error() string   { return e.err.Error() }
func (e cancelledChild) Unwrap() []error { return []error{e.err, e.stop} }
