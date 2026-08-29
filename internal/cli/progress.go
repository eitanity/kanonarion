package cli

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	extractports "github.com/eitanity/kanonarion/internal/extract/ports"
	staleports "github.com/eitanity/kanonarion/internal/staleness/ports"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// noProgressUsage is the one help string every --no-progress registration
// carries. It is stated once because the flag means one thing everywhere it
// appears, and a per-command copy is how the same flag ends up documented three
// different ways.
const noProgressUsage = "suppress stderr progress output (the throttled heartbeat and any per-module progress lines); results and warnings are unaffected"

// registerNoProgressFlag registers the shared --no-progress flag on cmd,
// binding it to p.
//
// Every long-running command that narrates its progress on stderr registers it
// through here, so the flag name, default and help string cannot drift apart —
// and, more importantly, so the set of commands that accept it is a decision
// made in one place rather than an accident of which command was written last.
// A caller who learned the flag on `walk` and reached for it on `vuln-scan` got
// "unknown flag" from exactly the command whose output most needs suppressing.
//
// A command that emits no progress does NOT register it: a flag that accepts an
// instruction it cannot carry out is worse than its absence, because the caller
// has no way to tell the two apart.
func registerNoProgressFlag(cmd *cobra.Command, p *bool) {
	cmd.Flags().BoolVar(p, "no-progress", false, noProgressUsage)
}

// progressWriter returns the stream progress narration should be written to:
// stderr normally, and a sink under --no-progress.
//
// Routing rather than branching at each write site is deliberate. The
// suppression must cover only the narration; the warnings and diagnostics that
// share stderr keep writing to stderr, so a suppressed run still reports what
// went wrong. Handing the narration a different writer makes that split
// structural instead of a condition every future write site has to remember.
func progressWriter(stderr io.Writer, noProgress bool) io.Writer {
	if noProgress {
		return io.Discard
	}
	return stderr
}

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
	return newStderrProgressReporter(stderr, progressInterval, time.Now, "walk progress: %d modules fetched (%s elapsed)\n")
}

// newExtractProgressReporter mirrors newWalkProgressReporter for the extract
// stage, which otherwise has no output at all between "Starting extraction"
// and completion — a multi-minute cold or large run looks hung with nothing
// to show it is still making progress.
func newExtractProgressReporter(stderr io.Writer, noProgress bool, cfg configdomain.Config, level string) extractports.ProgressReporter {
	if noProgress || !cfg.Preferences.Progress {
		return nil
	}
	switch strings.ToLower(level) {
	case "info", "debug":
		return nil
	}
	return newStderrProgressReporter(stderr, progressInterval, time.Now, "extract progress: %d modules processed (%s elapsed)\n")
}

// newStalenessProgressReporter mirrors the two above for the staleness probe,
// which is silent for as long as it waits: one module whose proxy lookup keeps
// failing transiently spends the better part of a minute inside a command the
// guide describes as taking about a second.
//
// It is gated identically — --no-progress, the config preference, and a log
// level that already streams the decorator's own retry lines — so the same
// instruction silences the same class of output everywhere, with no new flag.
func newStalenessProgressReporter(stderr io.Writer, noProgress bool, cfg configdomain.Config, level string) staleports.ProgressReporter {
	if noProgress || !cfg.Preferences.Progress {
		return nil
	}
	switch strings.ToLower(level) {
	case "info", "debug":
		return nil
	}
	return newStderrRetryReporter(stderr)
}

// stderrRetryReporter writes one line per retry to an output stream (stderr in
// production). It is safe for concurrent use: the newer-major probe resolves in
// bounded parallel rounds.
//
// It is deliberately NOT throttled like the heartbeat above. The heartbeat
// throttles a per-module firehose down to proof of life; a retry is the
// opposite — rare, at most three per module, and each one explains a wait the
// user is already sitting through. At the 20s heartbeat interval the whole
// 14-second retry schedule would elapse without printing anything, which is the
// silence this exists to end.
type stderrRetryReporter struct {
	w io.Writer

	mu sync.Mutex
}

func newStderrRetryReporter(w io.Writer) *stderrRetryReporter {
	return &stderrRetryReporter{w: w}
}

// RetryingLookup names the module, the attempt about to be made and the budget.
func (p *stderrRetryReporter) RetryingLookup(path string, attempt, maxAttempts int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, _ = fmt.Fprintf(p.w, "staleness progress: retrying %s (attempt %d of %d)\n", path, attempt, maxAttempts)
}

// stderrProgressReporter writes a single throttled progress line to an output
// stream (stderr in production). It is safe for concurrent use. The clock is
// injected so the throttle is deterministically testable.
type stderrProgressReporter struct {
	w        io.Writer
	interval time.Duration
	now      func() time.Time
	format   string

	mu       sync.Mutex
	start    time.Time
	lastEmit time.Time
}

func newStderrProgressReporter(w io.Writer, interval time.Duration, now func() time.Time, format string) *stderrProgressReporter {
	t := now()
	return &stderrProgressReporter{
		w:        w,
		interval: interval,
		now:      now,
		format:   format,
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
	_, _ = fmt.Fprintf(p.w, p.format, done, elapsed)
}
