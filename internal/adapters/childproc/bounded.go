package childproc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
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
