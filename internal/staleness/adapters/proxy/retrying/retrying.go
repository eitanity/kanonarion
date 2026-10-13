// Package retrying decorates a staleness ports.LatestResolver so a lookup the
// proxy has not finished is asked again until it answers or its window closes.
//
// Asked about a cold path it must look up at the origin — typically an absent
// major in a large multi-module repository — the proxy holds the request for
// about a minute and then answers 200 with an empty body, or the adapter times
// out first. The proxy keeps working after the request ends, and a later ask
// gets the definitive answer: measured over 20 such paths, re-asked every ~25 s,
// 18 answered 404 within 240 s of the first ask. So the schedule is a window,
// not an attempt count: re-ask every SettleInterval until SettleWindow after the
// first attempt. The same window governs the single-path decorator and the
// settle pass a concurrent round runs (Settle).
//
// Classification lives in the fetch domain (domain.IsTransientFetchError), the
// same positive-match classifier the module download and checksum-database
// paths use. Everything it does not recognise fails on the first attempt —
// above all ports.ErrPathAbsent, the probe's ordinary definitive answer, which
// must keep costing exactly one request and no wait.
package retrying

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/staleness/ports"
)

const (
	// SettleInterval is the pause between asks of a path the proxy has not
	// finished (jittered over [d/2, d]).
	SettleInterval = 20 * time.Second
	// SettleWindow is how long after its first ask a path is still asked again.
	SettleWindow = 240 * time.Second
)

// Resolver wraps a ports.LatestResolver and re-asks transient lookup failures.
type Resolver struct {
	inner    ports.LatestResolver
	logger   *slog.Logger
	progress ports.ProgressReporter
	interval time.Duration
	window   time.Duration

	// now, sleep and jitter are seams: tests replace them to run the schedule
	// without real waiting or randomness.
	now    func() time.Time
	sleep  func(ctx context.Context, d time.Duration) error
	jitter func(d time.Duration) time.Duration
}

var (
	_ ports.LatestResolver = (*Resolver)(nil)
	_ ports.RoundResolver  = (*Resolver)(nil)
)

// Option configures a Resolver.
type Option func(*Resolver)

// WithProgress sets the reporter told about each retry and settle pass (nil
// disables it, which is the default).
func WithProgress(p ports.ProgressReporter) Option {
	return func(r *Resolver) {
		r.progress = p
	}
}

// WithSchedule replaces the shared interval and window (values not above zero
// are ignored). It exists for callers that cannot reach the test seams.
func WithSchedule(interval, window time.Duration) Option {
	return func(r *Resolver) {
		if interval > 0 {
			r.interval = interval
		}
		if window > 0 {
			r.window = window
		}
	}
}

// New wraps inner so transient lookup failures are re-asked on the settle
// schedule.
func New(inner ports.LatestResolver, logger *slog.Logger, opts ...Option) *Resolver {
	r := &Resolver{
		inner:    inner,
		logger:   logger,
		interval: SettleInterval,
		window:   SettleWindow,
		now:      time.Now,
		sleep:    sleepCtx,
		jitter:   fullJitter,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// LatestInfo asks for path, re-asking a transient failure every interval until
// it settles or the window after the first attempt closes. The error returned
// at the deadline is the underlying error unchanged.
//
// A retry is logged at DEBUG and announced to the progress reporter before its
// wait; a success that needed one is logged at INFO and a closed window at WARN.
func (r *Resolver) LatestInfo(ctx context.Context, path string) (ports.LatestInfo, error) {
	a := r.AskOnce(ctx, path)
	for a.Unsettled {
		delay, ok := r.nextDelay(a.FirstAsked)
		if !ok {
			r.exhausted(ctx, a)
			break
		}
		if r.progress != nil {
			r.progress.RetryingLookup(path, a.Attempts+1, r.now().Sub(a.FirstAsked), r.window)
		}
		r.logRetry(ctx, a, delay)
		if serr := r.sleep(ctx, delay); serr != nil {
			return a.Info, r.stopped(ctx, a, serr)
		}
		r.reask(ctx, &a)
	}
	return a.Info, a.Err //nolint:wrapcheck // deliberate pass-through of the wrapped resolver's error
}

// AskOnce asks for path exactly once. A transient failure comes back Unsettled
// for Settle to re-ask; nothing here waits.
func (r *Resolver) AskOnce(ctx context.Context, path string) ports.RoundAnswer {
	a := ports.RoundAnswer{Path: path, FirstAsked: r.now()}
	r.reask(ctx, &a)
	return a
}

// Settle re-asks the unsettled answers together, at most width at a time,
// every interval, until each settles or its window closes. Answers already
// settled are returned unchanged. The progress reporter hears once per call.
func (r *Resolver) Settle(ctx context.Context, pending []ports.RoundAnswer, width int) []ports.RoundAnswer {
	out := append([]ports.RoundAnswer(nil), pending...)
	open := unsettledIndexes(out)
	if len(open) == 0 {
		return out
	}
	if width < 1 {
		width = 1
	}
	if r.progress != nil {
		r.progress.SettlingLookups(len(open), r.interval, r.window)
	}
	r.logger.InfoContext(ctx, "staleness.latest.settling",
		slog.Int("pending", len(open)),
		slog.Int64("interval_ms", r.interval.Milliseconds()),
		slog.Int64("window_ms", r.window.Milliseconds()),
	)
	started, asked := r.now(), len(open)
	defer func() {
		r.logger.InfoContext(ctx, "staleness.latest.settled",
			slog.Int("pending", asked),
			slog.Int("unanswered", countFailed(out)),
			slog.Int64("elapsed_ms", r.now().Sub(started).Milliseconds()),
		)
	}()
	closed := make(map[int]bool)
	for len(open) > 0 {
		delay := r.jitter(r.interval)
		var due []int
		for _, i := range open {
			if r.withinWindow(out[i].FirstAsked, delay) {
				due = append(due, i)
				continue
			}
			r.exhausted(ctx, out[i])
			closed[i] = true
		}
		if len(due) == 0 {
			break
		}
		if serr := r.sleep(ctx, delay); serr != nil {
			for _, i := range due {
				out[i].Err = r.stopped(ctx, out[i], serr)
				out[i].Unsettled = false
			}
			break
		}
		r.reaskAll(ctx, out, due, width)
		open = slices.DeleteFunc(unsettledIndexes(out), func(i int) bool { return closed[i] })
	}
	return out
}

// reask makes one request for a.Path and records its outcome in a.
func (r *Resolver) reask(ctx context.Context, a *ports.RoundAnswer) {
	a.Attempts++
	info, err := r.inner.LatestInfo(ctx, a.Path)
	a.Info, a.Err = info, err
	a.Unsettled = err != nil && fetchdomain.IsTransientFetchError(err)
	if a.Attempts > 1 && (err == nil || errors.Is(err, ports.ErrPathAbsent)) {
		r.logger.InfoContext(ctx, "staleness.latest.retried",
			slog.String("module.path", a.Path),
			slog.Int("attempts", a.Attempts),
			slog.Bool("absent", err != nil),
			slog.Int64("elapsed_ms", r.now().Sub(a.FirstAsked).Milliseconds()),
		)
	}
}

// reaskAll re-asks out[i] for every i in due, at most width at a time.
func (r *Resolver) reaskAll(ctx context.Context, out []ports.RoundAnswer, due []int, width int) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, width)
	for _, i := range due {
		r.logRetry(ctx, out[i], 0)
		wg.Add(1)
		go func(a *ports.RoundAnswer) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r.reask(ctx, a)
		}(&out[i])
	}
	wg.Wait()
}

// nextDelay draws the wait before the next ask and reports whether that ask
// still falls inside the window opened at first.
func (r *Resolver) nextDelay(first time.Time) (time.Duration, bool) {
	delay := r.jitter(r.interval)
	return delay, r.withinWindow(first, delay)
}

// withinWindow reports whether an ask made delay from now is still inside the
// window opened at first.
func (r *Resolver) withinWindow(first time.Time, delay time.Duration) bool {
	return r.now().Add(delay).Sub(first) <= r.window
}

func (r *Resolver) logRetry(ctx context.Context, a ports.RoundAnswer, delay time.Duration) {
	r.logger.DebugContext(ctx, "staleness.latest.retry",
		slog.String("module.path", a.Path),
		slog.Int("attempt", a.Attempts),
		slog.Int64("backoff_ms", delay.Milliseconds()),
		slog.Int64("elapsed_ms", r.now().Sub(a.FirstAsked).Milliseconds()),
		slog.String("error", errString(a.Err)),
	)
}

// exhausted logs a path whose window closed with no definitive answer.
func (r *Resolver) exhausted(ctx context.Context, a ports.RoundAnswer) {
	r.logger.WarnContext(ctx, "staleness.latest.retries_exhausted",
		slog.String("module.path", a.Path),
		slog.Int("attempts", a.Attempts),
		slog.Int64("interval_ms", r.interval.Milliseconds()),
		slog.Int64("window_ms", r.window.Milliseconds()),
		slog.Int64("elapsed_ms", r.now().Sub(a.FirstAsked).Milliseconds()),
		slog.String("error", errString(a.Err)),
	)
}

// stopped wraps the error that prompted a retry the context cut short: a
// deliberate stop, not a closed window.
func (r *Resolver) stopped(ctx context.Context, a ports.RoundAnswer, serr error) error {
	r.logger.DebugContext(ctx, "staleness.latest.retry.aborted",
		slog.String("module.path", a.Path),
		slog.Int("attempt", a.Attempts),
		slog.String("reason", serr.Error()),
	)
	return stoppedRetry{err: a.Err, stop: serr}
}

func unsettledIndexes(as []ports.RoundAnswer) []int {
	var idx []int
	for i := range as {
		if as[i].Unsettled {
			idx = append(idx, i)
		}
	}
	return idx
}

// countFailed counts answers that ended without a definitive result.
func countFailed(as []ports.RoundAnswer) int {
	n := 0
	for _, a := range as {
		if a.Err != nil && (a.Unsettled || errors.As(a.Err, new(stoppedRetry))) {
			n++
		}
	}
	return n
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// fullJitter spreads a backoff interval over [d/2, d] so a sweep hitting an
// overloaded proxy does not resynchronise its retries on every wave.
func fullJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(half)+1)) // #nosec G404 -- backoff jitter, not a security decision
}

// sleepCtx waits for d, returning early with the context's error if it ends first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err() //nolint:wrapcheck // the context's own error is the answer
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err() //nolint:wrapcheck // the context's own error is the answer
	case <-t.C:
		return nil
	}
}

// stoppedRetry is the error that prompted a retry the context cut short. It
// reads as that error, which is what the caller asked about, and it is also the
// cancellation, so a caller can tell a stopped run from a failed lookup.
type stoppedRetry struct{ err, stop error }

func (e stoppedRetry) Error() string   { return e.err.Error() }
func (e stoppedRetry) Unwrap() []error { return []error{e.err, e.stop} }
