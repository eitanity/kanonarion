// Package retrying decorates a walkports.ModuleFetcher with bounded
// exponential-backoff retries for transient network failures.
//
// A single HTTP/2 stream reset from the module proxy mid-download used to
// degrade a real dependency to a fetch-failure node for a whole walk: the
// module is fine, the transfer was not, and the only signal was one WARN line
// on an otherwise successful run. Retrying transient errors before the failure
// is recorded matches the behaviour the go command already applies to the same
// conditions, so a fetch failure means the module genuinely could not be
// fetched rather than that the network hiccuped once.
//
// Classification lives in the fetch domain (domain.IsTransientFetchError):
// only recognised transient conditions are retried, and everything else —
// not-found, checksum mismatch, verification failure, cancellation — fails on
// the first attempt exactly as before.
package retrying

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

const (
	// defaultAttempts is the total number of tries, not the number of retries:
	// one initial attempt plus two retries.
	defaultAttempts = 3
	// defaultBaseDelay is the first backoff interval; it doubles per retry.
	defaultBaseDelay = 200 * time.Millisecond
	// maxBackoff caps the doubling. Without a cap a large attempt budget
	// overflows the interval to a negative duration, which would collapse the
	// backoff to zero and turn the retry loop into a hot spin on the proxy —
	// the opposite of what backing off is for. The default budget never reaches
	// the cap (200ms then 400ms); it exists for a raised budget, where a longer
	// ceiling would stall a whole worker pool on one unreachable module.
	maxBackoff = 5 * time.Second
)

// forceCapable mirrors the walker's own force-mode interface. It is declared
// here so the decorator can pass the capability through only when the wrapped
// fetcher actually has it — see New.
type forceCapable interface {
	WithForce(bool) walkports.ModuleFetcher
}

// Fetcher wraps a ModuleFetcher and retries transient fetch failures.
type Fetcher struct {
	inner     walkports.ModuleFetcher
	logger    *slog.Logger
	attempts  int
	baseDelay time.Duration

	// sleep and jitter are seams: tests replace them to run the backoff
	// schedule without real waiting or randomness.
	sleep  func(ctx context.Context, d time.Duration) error
	jitter func(d time.Duration) time.Duration
}

// forcingFetcher is the variant returned when the wrapped fetcher supports
// force mode. Keeping WithForce off the base type matters: the walker decides
// whether --force is honoured by type-asserting its fetcher, so a decorator
// that always advertised the capability would turn --force into a silent no-op
// over a fetcher that cannot do it.
type forcingFetcher struct {
	*Fetcher
}

// Option configures a Fetcher.
type Option func(*Fetcher)

// WithAttempts sets the total number of attempts (values below 1 are ignored).
func WithAttempts(n int) Option {
	return func(f *Fetcher) {
		if n >= 1 {
			f.attempts = n
		}
	}
}

// WithBaseDelay sets the first backoff interval (values below zero are ignored).
func WithBaseDelay(d time.Duration) Option {
	return func(f *Fetcher) {
		if d >= 0 {
			f.baseDelay = d
		}
	}
}

// New wraps inner so transient fetch failures are retried with bounded
// exponential backoff. The returned fetcher implements the walker's force-mode
// interface if and only if inner does.
func New(inner walkports.ModuleFetcher, logger *slog.Logger, opts ...Option) walkports.ModuleFetcher {
	f := &Fetcher{
		inner:     inner,
		logger:    logger,
		attempts:  defaultAttempts,
		baseDelay: defaultBaseDelay,
		sleep:     sleepCtx,
		jitter:    fullJitter,
	}
	for _, opt := range opts {
		opt(f)
	}
	if _, ok := inner.(forceCapable); ok {
		return &forcingFetcher{Fetcher: f}
	}
	return f
}

// EnsureFetched delegates to the wrapped fetcher, retrying transient failures
// until they succeed or the attempt budget is spent. The error returned after
// the final attempt is the underlying error unchanged, so the caller records
// the same walk.fetch.failed detail it would have recorded without retries.
//
// Logging is levelled so that every outcome is distinguishable at the level a
// reader of that outcome is already watching:
//   - per-attempt retries at DEBUG, so a flake that recovers adds no warn noise;
//   - a success that needed retries at INFO, because it explains the inflated
//     duration_ms the walker reports for that module at the same level;
//   - an exhausted budget at WARN, so a genuine fetch failure that burned every
//     attempt is not indistinguishable from one rejected on sight.
func (f *Fetcher) EnsureFetched(ctx context.Context, coord coordinate.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	var (
		res          walkports.ModuleFetchResult
		err          error
		totalBackoff time.Duration
	)
	for attempt := 1; ; attempt++ {
		res, err = f.inner.EnsureFetched(ctx, coord)
		if err == nil {
			if attempt > 1 {
				f.logger.InfoContext(ctx, "walk.fetch.retried",
					slog.String("module.path", coord.Path),
					slog.String("module.version", coord.Version),
					slog.Int("attempts", attempt),
					slog.Int64("backoff_total_ms", totalBackoff.Milliseconds()),
				)
			}
			return res, nil
		}
		// A permanent error is the module's real answer: fail on sight, with no
		// retry log at all, exactly as before this decorator existed.
		if !fetchdomain.IsTransientFetchError(err) {
			// Returned verbatim: the caller records the same walk.fetch.failed
			// detail it would have recorded with no retries in front of it.
			return res, err //nolint:wrapcheck // deliberate pass-through of the wrapped fetcher's error
		}
		if attempt >= f.attempts {
			// The walk.fetch.failed WARN that follows carries only the last error,
			// which reads identically to a first-attempt failure. This line is what
			// separates "the network was bad for a while" from "the module is bad".
			f.logger.WarnContext(ctx, "walk.fetch.retries_exhausted",
				slog.String("module.path", coord.Path),
				slog.String("module.version", coord.Version),
				slog.Int("attempts", attempt),
				slog.Int64("backoff_total_ms", totalBackoff.Milliseconds()),
				slog.String("error", err.Error()),
			)
			return res, err //nolint:wrapcheck // deliberate pass-through of the wrapped fetcher's error
		}
		delay := f.jitter(f.backoffFor(attempt))
		f.logger.DebugContext(ctx, "walk.fetch.retry",
			slog.String("module.path", coord.Path),
			slog.String("module.version", coord.Version),
			slog.Int("attempt", attempt),
			slog.Int("attempts.max", f.attempts),
			slog.Int64("backoff_ms", delay.Milliseconds()),
			slog.String("error", err.Error()),
		)
		if serr := f.sleep(ctx, delay); serr != nil {
			// The context ended during backoff — a deliberate stop, not an
			// exhausted budget, so it is recorded as its own outcome rather than
			// masquerading as either. Report the fetch error that prompted the
			// retry, not the wait's cancellation: the fetch is what the caller
			// asked about.
			f.logger.DebugContext(ctx, "walk.fetch.retry.aborted",
				slog.String("module.path", coord.Path),
				slog.String("module.version", coord.Version),
				slog.Int("attempt", attempt),
				slog.String("reason", serr.Error()),
			)
			return res, err //nolint:wrapcheck // deliberate pass-through of the wrapped fetcher's error
		}
		totalBackoff += delay
	}
}

// WithForce passes force mode through to the wrapped fetcher, keeping the retry
// behaviour in front of the force-mode clone.
func (f *forcingFetcher) WithForce(force bool) walkports.ModuleFetcher {
	fc, ok := f.inner.(forceCapable)
	if !ok {
		return f
	}
	clone := *f.Fetcher
	clone.inner = fc.WithForce(force)
	return &forcingFetcher{Fetcher: &clone}
}

// backoffFor returns the pre-jitter interval before the given attempt's retry:
// baseDelay doubled once per attempt already spent, saturating at maxBackoff
// rather than overflowing.
func (f *Fetcher) backoffFor(attempt int) time.Duration {
	d := f.baseDelay
	for i := 1; i < attempt; i++ {
		if d >= maxBackoff/2 {
			return maxBackoff
		}
		d *= 2
	}
	return d
}

// fullJitter spreads a backoff interval over [d/2, d) so concurrent workers
// retrying the same overloaded proxy do not resynchronise on every wave.
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
