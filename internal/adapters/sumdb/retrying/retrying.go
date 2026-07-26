// Package retrying decorates a ports.SumDBClient with bounded
// exponential-backoff retries for transient checksum-database lookup failures.
//
// A single 503 from sum.golang.org used to be indistinguishable from the
// database's real answer about a module: the adapter collapsed every lookup
// error into an unavailable result, the fetch recorded UnverifiedNoSumDB (or
// VerifiedByGoSum where a local go.sum entry happened to exist), returned no
// error, and the fact store cached that downgrade for every later run. The run
// then read as a finding about the dependency rather than as an unreliable
// measurement of it.
//
// The reason split on ports.SumDBResult is what makes retrying possible:
// only a failure-unavailable result is retried, and a policy answer —
// GOSUMDB=off, a GOPRIVATE/GONOSUMCHECK match, a response with no hash line —
// returns on the first attempt with no backoff and no warn, exactly as before.
// Classification of the failure itself lives in the fetch domain
// (domain.IsTransientFetchError), the same positive-match classifier the module
// download path uses, so a security error or any unrecognised condition fails on
// sight rather than being retried.
package retrying

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

const (
	// defaultAttempts is the total number of tries, not the number of retries:
	// one initial attempt plus two retries.
	defaultAttempts = 3
	// defaultBaseDelay is the first backoff interval; it doubles per retry.
	defaultBaseDelay = 200 * time.Millisecond
	// maxBackoff caps the doubling so a raised attempt budget saturates rather
	// than overflowing the interval to a negative duration — which would collapse
	// the backoff to zero and turn the retry loop into a hot spin on the checksum
	// database. The default budget (200ms then 400ms) never reaches it.
	maxBackoff = 5 * time.Second
)

// Client wraps a ports.SumDBClient and retries transient lookup failures.
type Client struct {
	inner     ports.SumDBClient
	logger    *slog.Logger
	attempts  int
	baseDelay time.Duration

	// sleep and jitter are seams: tests replace them to run the backoff
	// schedule without real waiting or randomness.
	sleep  func(ctx context.Context, d time.Duration) error
	jitter func(d time.Duration) time.Duration
}

// Option configures a Client.
type Option func(*Client)

// WithAttempts sets the total number of attempts (values below 1 are ignored).
func WithAttempts(n int) Option {
	return func(c *Client) {
		if n >= 1 {
			c.attempts = n
		}
	}
}

// WithBaseDelay sets the first backoff interval (values below zero are ignored).
func WithBaseDelay(d time.Duration) Option {
	return func(c *Client) {
		if d >= 0 {
			c.baseDelay = d
		}
	}
}

// New wraps inner so transient checksum-database lookup failures are retried
// with bounded exponential backoff.
func New(inner ports.SumDBClient, logger *slog.Logger, opts ...Option) *Client {
	c := &Client{
		inner:     inner,
		logger:    logger,
		attempts:  defaultAttempts,
		baseDelay: defaultBaseDelay,
		sleep:     sleepCtx,
		jitter:    fullJitter,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Lookup delegates to the wrapped client, retrying a failed lookup until it
// succeeds or the attempt budget is spent. The result returned after the final
// attempt is the wrapped client's own, so the caller records the same
// verification outcome it would have recorded without retries in front of it.
//
// Logging is levelled so each outcome is visible at the level a reader of that
// outcome is already watching:
//   - per-attempt retries at DEBUG, so a flake that recovers adds no warn noise;
//   - a recovered lookup at DEBUG for the same reason — the record it produces is
//     verified, and nothing about it needs an operator's attention;
//   - an exhausted budget at WARN, because the record that follows carries a
//     downgraded verification status that is a statement about the lookup, not
//     about the module, and at the default log level this line is the only thing
//     that says so.
func (c *Client) Lookup(ctx context.Context, coord coordinate.ModuleCoordinate) ports.SumDBResult {
	var (
		res          ports.SumDBResult
		totalBackoff time.Duration
	)
	for attempt := 1; ; attempt++ {
		res = c.inner.Lookup(ctx, coord)
		// An available result, or a settled policy answer, is the database's real
		// answer: return it with no retry log at all, exactly as before this
		// decorator existed.
		if !res.LookupFailed() {
			if attempt > 1 {
				c.logger.DebugContext(ctx, "sumdb.lookup.retried",
					slog.String("module.path", coord.Path),
					slog.String("module.version", coord.Version),
					slog.Int("attempts", attempt),
					slog.Int64("backoff_total_ms", totalBackoff.Milliseconds()),
				)
			}
			return res
		}
		if !fetchdomain.IsTransientFetchError(res.Err) {
			return res
		}
		if attempt >= c.attempts {
			// The downgraded record that follows reads identically whether the
			// lookup failed once or three times. This line is what separates "the
			// checksum database was unreachable for a while" from "this module has
			// no transparency-log entry".
			c.logger.WarnContext(ctx, "sumdb.lookup.retries_exhausted",
				slog.String("module.path", coord.Path),
				slog.String("module.version", coord.Version),
				slog.Int("attempts", attempt),
				slog.Int64("backoff_total_ms", totalBackoff.Milliseconds()),
				slog.String("reason", res.Reason),
			)
			return res
		}
		delay := c.jitter(c.backoffFor(attempt))
		c.logger.DebugContext(ctx, "sumdb.lookup.retry",
			slog.String("module.path", coord.Path),
			slog.String("module.version", coord.Version),
			slog.Int("attempt", attempt),
			slog.Int("attempts.max", c.attempts),
			slog.Int64("backoff_ms", delay.Milliseconds()),
			slog.String("error", res.Err.Error()),
		)
		if serr := c.sleep(ctx, delay); serr != nil {
			// The context ended during backoff — a deliberate stop, not an exhausted
			// budget, so it is recorded as its own outcome rather than masquerading
			// as either. The lookup result that prompted the retry is what the caller
			// asked about, so it is what comes back.
			c.logger.DebugContext(ctx, "sumdb.lookup.retry.aborted",
				slog.String("module.path", coord.Path),
				slog.String("module.version", coord.Version),
				slog.Int("attempt", attempt),
				slog.String("reason", serr.Error()),
			)
			return res
		}
		totalBackoff += delay
	}
}

// backoffFor returns the pre-jitter interval before the given attempt's retry:
// baseDelay doubled once per attempt already spent, saturating at maxBackoff
// rather than overflowing.
func (c *Client) backoffFor(attempt int) time.Duration {
	d := c.baseDelay
	for i := 1; i < attempt; i++ {
		if d >= maxBackoff/2 {
			return maxBackoff
		}
		d *= 2
	}
	return d
}

// fullJitter spreads a backoff interval over [d/2, d) so concurrent workers
// retrying the same overloaded database do not resynchronise on every wave.
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

// Ensure Client implements ports.SumDBClient at compile time.
var _ ports.SumDBClient = (*Client)(nil)
