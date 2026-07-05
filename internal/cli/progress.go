package cli

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// progressInterval is the minimum wall-clock gap between two heartbeat lines.
// Sized so a multi-minute cold walk emits a handful of lines (proof of life)
// rather than a per-module firehose, while a warm run shorter than the interval
// prints nothing at all.
const progressInterval = 20 * time.Second

// newWalkProgressReporter returns a ProgressReporter that writes a throttled
// heartbeat to stderr, or nil (reporting disabled) when any of the following
// hold:
//   - the caller passed --no-progress;
//   - preferences.progress is false;
//   - the log level already streams per-module fetch lines (info/debug), which
//     makes the heartbeat redundant.
//
// The heartbeat is always written to stderr, never stdout, so --json output is
// unaffected regardless of this setting.
func newWalkProgressReporter(stderr io.Writer, noProgress bool, cfg configdomain.Config, level string) walkports.ProgressReporter {
	if noProgress || !cfg.Preferences.Progress {
		return nil
	}
	switch strings.ToLower(level) {
	case "info", "debug":
		return nil
	}
	return newStderrProgressReporter(stderr, progressInterval, time.Now)
}

// stderrProgressReporter writes a single throttled progress line to an output
// stream (stderr in production). It is safe for concurrent use. The clock is
// injected so the throttle is deterministically testable.
type stderrProgressReporter struct {
	w        io.Writer
	interval time.Duration
	now      func() time.Time

	mu       sync.Mutex
	start    time.Time
	lastEmit time.Time
}

func newStderrProgressReporter(w io.Writer, interval time.Duration, now func() time.Time) *stderrProgressReporter {
	t := now()
	return &stderrProgressReporter{
		w:        w,
		interval: interval,
		now:      now,
		start:    t,
		lastEmit: t,
	}
}

// Advance emits at most one line per interval. The first call (at t≈start) is
// always within the interval and so stays silent; a line is printed only once
// the interval has elapsed, which keeps short/warm runs noise-free.
func (p *stderrProgressReporter) Advance(done int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	t := p.now()
	if t.Sub(p.lastEmit) < p.interval {
		return
	}
	p.lastEmit = t
	elapsed := t.Sub(p.start).Round(time.Second)
	_, _ = fmt.Fprintf(p.w, "walk progress: %d modules fetched (%s elapsed)\n", done, elapsed)
}
