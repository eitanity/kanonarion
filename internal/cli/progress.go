package cli

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
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
func (p *stderrProgressReporter) Advance(done int) { p.emit(done) }

// emit is Advance for a line carrying more than one count. counts fills the
// format's leading verbs and the elapsed time fills its last, so every reporter
// built on this one throttles identically and renders elapsed time identically
// — which is the reason the second shape of line was not given a second
// throttle of its own.
func (p *stderrProgressReporter) emit(counts ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	t := p.now()
	if t.Sub(p.lastEmit) < p.interval {
		return
	}
	p.lastEmit = t
	elapsed := t.Sub(p.start).Round(time.Second)
	_, _ = fmt.Fprintf(p.w, p.format, append(counts, elapsed)...)
}

// traversalProgressInterval is the gap between two call-graph traversal
// progress lines.
//
// It is five seconds where the heartbeat above is twenty, because the two
// narrate different waits. Twenty seconds is sized for a multi-minute cold
// walk, where a handful of lines is proof of life. A transitive edge query is a
// read the operator expects back in about a second, and the whole unbounded
// closure on this project's own graph returns in 13.3s — so at the heartbeat
// interval it would print nothing at all, and the silence this exists to end
// would be unbroken. At five seconds that run prints two lines, and a 3.6s
// bounded one still prints none.
//
// It is handed to the traversal on the request rather than kept as this
// reporter's own throttle. The traversal runs a ticker on it, so it narrates
// wherever the time is being spent — including inside a single store query that
// has not returned — where a throttle here could only decide what to do with a
// call the traversal had already chosen to make.
const traversalProgressInterval = 5 * time.Second

// traversalProgressReporter narrates a transitive call-graph traversal, one line
// per call, sharing stderrProgressReporter's line rendering and elapsed-time
// clock.
//
// It does NOT re-apply that type's throttle: the traversal's ticker is the only
// caller and already fires at traversalProgressInterval, so a second gate of the
// same width would only drop a line whenever a tick arrived a shade early. The
// same seeding would also have silenced the first line, which is the one that
// matters — a run still inside its first level is precisely the case this
// narration exists for.
//
// Advance is called from the traversal's narration goroutine; the embedded
// reporter's mutex is what makes that safe.
type traversalProgressReporter struct{ p *stderrProgressReporter }

// Advance names the depth being expanded and the symbols visited so far.
func (t traversalProgressReporter) Advance(depth, visited int) { t.p.emit(depth, visited) }

// newTraversalProgressReporter returns a reporter that writes traversal lines to
// stderr, or nil (reporting disabled) under --no-progress or
// preferences.progress = false.
//
// direction is "callers" or "callees" and becomes the line's house prefix, as
// "walk progress: " and "extract progress: " are for their stages.
//
// Unlike the walk and extract reporters it is NOT disabled at info/debug log
// level. That gate exists on those two because the log already streams a line
// per module there, which makes the heartbeat redundant; a traversal streams
// nothing at any level, so carrying the gate over would restore the silence at
// exactly the verbosity an operator raised to see more.
//
// It writes to stderr only, so --json stdout is byte-identical whether or not it
// is enabled.
//
// The zero interval leaves the line rendering and the elapsed clock in place and
// turns the throttle off; traversalProgressInterval reaches the traversal on the
// request instead.
func newTraversalProgressReporter(stderr io.Writer, noProgress bool, cfg configdomain.Config, direction string) cgports.TraversalProgressReporter {
	if noProgress || !cfg.Preferences.Progress {
		return nil
	}
	return traversalProgressReporter{p: newStderrProgressReporter(stderr, 0, time.Now,
		direction+" progress: depth %d, %d symbols visited (%s elapsed)\n")}
}
