// Package retrying decorates a staleness ports.LatestResolver with bounded
// exponential-backoff retries for transient proxy failures.
//
// A single empty 200 from the module proxy used to cost a module its
// newer-major answer for the whole run. The lookup is not written when it
// fails — a failed lookup is not a cacheable fact — so nothing wrong is
// recorded, but the answer is simply lost, and a sweep is exactly where one
// short row of hundreds goes unnoticed. The condition is load-related: the same
// path asked again moments later answers cleanly.
//
// Classification lives in the fetch domain (domain.IsTransientFetchError), the
// same positive-match classifier the module download and checksum-database
// paths use. That is deliberate: a second classifier is how two surfaces come
// to disagree about what "transient" means. Everything it does not recognise
// fails on the first attempt — above all ports.ErrPathAbsent, which is the
// probe's ordinary answer for a major that does not exist and is a definitive
// negative, not a failure. Retrying it would make every module's last probe
// step the slowest part of a sweep.
package retrying

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/staleness/ports"
)

const (
	// defaultAttempts is the total number of tries, not the number of retries:
	// one initial attempt plus two retries.
	defaultAttempts = 3
	// defaultBaseDelay is the first backoff interval; it doubles per retry.
	defaultBaseDelay = 200 * time.Millisecond
	// maxBackoff caps the doubling so a raised attempt budget saturates rather
	// than overflowing the interval to a negative duration, which would collapse
	// the backoff to zero and turn the retry loop into a hot spin on the proxy.
	// The default budget (200ms then 400ms) never reaches it.
	maxBackoff = 5 * time.Second
)

// Resolver wraps a ports.LatestResolver and retries transient lookup failures.
type Resolver struct {
	inner     ports.LatestResolver
	logger    *slog.Logger
	attempts  int
	baseDelay time.Duration

	// sleep and jitter are seams: tests replace them to run the backoff
	// schedule without real waiting or randomness.
	sleep  func(ctx context.Context, d time.Duration) error
	jitter func(d time.Duration) time.Duration
}

var _ ports.LatestResolver = (*Resolver)(nil)

// Option configures a Resolver.
type Option func(*Resolver)

// WithAttempts sets the total number of attempts (values below 1 are ignored).
func WithAttempts(n int) Option {
	return func(r *Resolver) {
		if n >= 1 {
			r.attempts = n
		}
	}
}

// WithBaseDelay sets the first backoff interval (values below zero are ignored).
func WithBaseDelay(d time.Duration) Option {
	return func(r *Resolver) {
		if d >= 0 {
			r.baseDelay = d
		}
	}
}

// New wraps inner so transient lookup failures are retried with bounded
// exponential backoff.
func New(inner ports.LatestResolver, logger *slog.Logger, opts ...Option) *Resolver {
	r := &Resolver{
		inner:     inner,
		logger:    logger,
		attempts:  defaultAttempts,
		baseDelay: defaultBaseDelay,
		sleep:     sleepCtx,
		jitter:    fullJitter,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// LatestInfo delegates to the wrapped resolver, retrying transient failures
// until they succeed or the attempt budget is spent. The error returned after
// the final attempt is the underlying error unchanged, so a lookup that could
// not be made reports exactly what it reported before this decorator existed.
//
// Logging is levelled so each outcome is visible to the reader already watching
// for it: a retry at DEBUG, a success that needed one at INFO — it explains a
// sweep that took longer than its module count suggests — and an exhausted
// budget at WARN, so a genuinely unanswerable probe is distinguishable from one
// that was never asked twice.
func (r *Resolver) LatestInfo(ctx context.Context, path string) (ports.LatestInfo, error) {
	var (
		info         ports.LatestInfo
		err          error
		totalBackoff time.Duration
	)
	for attempt := 1; ; attempt++ {
		info, err = r.inner.LatestInfo(ctx, path)
		if err == nil {
			if attempt > 1 {
				r.logger.InfoContext(ctx, "staleness.latest.retried",
					slog.String("module.path", path),
					slog.Int("attempts", attempt),
					slog.Int64("backoff_total_ms", totalBackoff.Milliseconds()),
				)
			}
			return info, nil
		}
		// A definitive answer is the proxy's real answer about the path: it is
		// returned on sight, with no retry log at all. An absent major path is
		// the commonest error this decorator sees and it must stay free.
		if !fetchdomain.IsTransientFetchError(err) {
			return info, err //nolint:wrapcheck // deliberate pass-through of the wrapped resolver's error
		}
		if attempt >= r.attempts {
			r.logger.WarnContext(ctx, "staleness.latest.retries_exhausted",
				slog.String("module.path", path),
				slog.Int("attempts", attempt),
				slog.Int64("backoff_total_ms", totalBackoff.Milliseconds()),
				slog.String("error", err.Error()),
			)
			return info, err //nolint:wrapcheck // deliberate pass-through of the wrapped resolver's error
		}
		delay := r.jitter(r.backoffFor(attempt))
		r.logger.DebugContext(ctx, "staleness.latest.retry",
			slog.String("module.path", path),
			slog.Int("attempt", attempt),
			slog.Int("attempts.max", r.attempts),
			slog.Int64("backoff_ms", delay.Milliseconds()),
			slog.String("error", err.Error()),
		)
		if serr := r.sleep(ctx, delay); serr != nil {
			// The context ended during backoff — a deliberate stop, not an
			// exhausted budget. The lookup error that prompted the retry is what
			// the caller asked about, so that is what comes back.
			r.logger.DebugContext(ctx, "staleness.latest.retry.aborted",
				slog.String("module.path", path),
				slog.Int("attempt", attempt),
				slog.String("reason", serr.Error()),
			)
			return info, err //nolint:wrapcheck // deliberate pass-through of the wrapped resolver's error
		}
		totalBackoff += delay
	}
}

// backoffFor returns the pre-jitter interval before the given attempt's retry:
// baseDelay doubled once per attempt already spent, saturating at maxBackoff
// rather than overflowing.
func (r *Resolver) backoffFor(attempt int) time.Duration {
	d := r.baseDelay
	for i := 1; i < attempt; i++ {
		if d >= maxBackoff/2 {
			return maxBackoff
		}
		d *= 2
	}
	return d
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
