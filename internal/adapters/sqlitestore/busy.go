package sqlitestore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	sqlitedriver "modernc.org/sqlite"
	sqlitelib "modernc.org/sqlite/lib"
)

// ContentionMarker is the sentence a write that ran out of retries always
// contains.
//
// It is a stated protocol rather than an incidental spelling, because the writer
// and the reader are usually different PROCESSES: a call-graph child persists its
// record and the parent that spawned it has nothing but the child's stderr to
// classify the failure from. Naming the sentence once is what stops the parent
// filing a lock it lost as a property of the module.
const ContentionMarker = "the store lock was held by another writer"

// ErrLockContended is what a write that exhausted its retry budget returns. It
// is a statement about this host at this moment — another writer held the
// single-writer lock — and never about the record being written.
var ErrLockContended = errors.New(ContentionMarker)

// The retry budget: five attempts, so four waits. Each attempt already waits up
// to busy_timeout (10s) inside SQLite before it reports the lock, so a contended
// write can spend the better part of a minute before it gives up.
//
// That is the trade, and it is the right way round: what is being protected is a
// completed call-graph analysis — several CPU-minutes in the observed case — and
// discarding that to save forty seconds of waiting costs far more than it saves.
// The budget is bounded so a genuinely wedged store still fails.
const (
	busyAttempts    = 8
	busyInitialWait = 100 * time.Millisecond
	busyMaxWait     = 5 * time.Second
)

// retries counts, for this process, how many write attempts were retried after
// losing the store lock. It is process-wide because the question an operator
// asks is about the run, not about one store handle, and a run holds several.
var retries atomic.Int64

// Retries reports how many write attempts this process retried for lock
// contention. Zero is the ordinary case and is what an uncontended run reports.
func Retries() int64 { return retries.Load() }

// ResetRetries zeroes the counter. It exists for tests and for a long-lived
// process that reports per run; a command reports once and exits.
func ResetRetries() { retries.Store(0) }

// AddRetries folds another process's count into this one's.
//
// A run's writes are not all made by the run's own process: the extraction stage
// persists each call graph from a child, and the forty-eight contention events
// that motivated the retry were nearly all theirs. A parent that reported only
// its own would say "none" for a run that waited repeatedly.
func AddRetries(n int64) {
	if n > 0 {
		retries.Add(n)
	}
}

// contentionNoticePrefix begins the line a process writes on stderr when it
// retried at least one write. It is how a child tells its parent, so the parent
// can report the run's total rather than its own share.
const contentionNoticePrefix = "kanonarion: store writes retried for lock contention: "

// ContentionNotice renders the line, or "" when nothing was retried. A run that
// never waited says nothing, which is what makes the line's presence meaningful.
func ContentionNotice(n int64) string {
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf("%s%d\n", contentionNoticePrefix, n)
}

// ContentionNoticeIn reads a child's total out of what it wrote to stderr.
func ContentionNoticeIn(stderr string) int64 {
	i := strings.LastIndex(stderr, contentionNoticePrefix)
	if i < 0 {
		return 0
	}
	rest := stderr[i+len(contentionNoticePrefix):]
	if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
		rest = rest[:nl]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// IsBusy reports whether err is SQLite refusing because another connection holds
// the lock.
//
// It asks the driver's own error rather than matching the message, on the same
// terms every other classification in this tree is structural: the text of
// "database is locked" is not a contract, and a store whose message changed
// would silently stop retrying. SQLITE_LOCKED joins SQLITE_BUSY because both say
// the same thing to a writer — someone else holds it, try again — and the
// extended result codes are masked off, since the low byte is the class.
func IsBusy(err error) bool {
	var serr *sqlitedriver.Error
	if !errors.As(err, &serr) {
		return false
	}
	switch serr.Code() & 0xff {
	case sqlitelib.SQLITE_BUSY, sqlitelib.SQLITE_LOCKED:
		return true
	default:
		return false
	}
}

// nextBusyWait doubles the wait up to the cap and spreads it.
//
// The spread is not decoration. Every writer here is a sibling process started
// at the same moment by one parent, so an unjittered schedule has them all wake
// together and collide again — which is how a queue of thirty-two writers
// starves the ones at the back however large the budget is.
func nextBusyWait(wait time.Duration) time.Duration {
	if wait *= 2; wait > busyMaxWait {
		wait = busyMaxWait
	}
	return wait
}

// jitter returns d spread over [d/2, 3d/2).
func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(rand.Int64N(int64(d))) // #nosec G404 -- spreading retry waits, not a secret
}

// retryOnBusyOpen is RetryOnBusy for a write made while the store is being
// opened, before any request context exists.
//
// It is separate rather than taking a manufactured context: migrate has no
// context in scope by design — see Migration.Fn — and inventing one there put a
// contextcheck failure on every Open call site.
func retryOnBusyOpen(what string, write func() error) error {
	wait := busyInitialWait
	for attempt := 1; ; attempt++ {
		err := write()
		if !IsBusy(err) {
			return err
		}
		if attempt >= busyAttempts {
			return fmt.Errorf("%w: %s gave up after %d attempts: %w", ErrLockContended, what, attempt, err)
		}
		retries.Add(1)
		time.Sleep(jitter(wait))
		wait = nextBusyWait(wait)
	}
}

// RetryOnBusy runs write, repeating it with bounded exponential backoff for as
// long as it fails because another writer holds the store lock.
//
// SQLITE_BUSY on a WAL store under concurrent writers is a transient condition,
// not a fault: the canonical response is to wait and try again. Before this,
// nothing in the tree treated it as retryable, so ten seconds of contention
// ended a stage and discarded whatever it was carrying — which made coverage a
// property of lock timing rather than of the module. Measured on a 172-module
// extraction: forty-eight contention events and one call-graph record lost.
//
// write must be re-runnable. Every caller is a transaction that rolls back on
// failure, so an attempt that lost the lock left nothing behind.
//
// what names the write for the log line and for the refusal, so a reader is told
// which record was at stake rather than that "a write" failed.
func RetryOnBusy(ctx context.Context, what string, write func(context.Context) error) error {
	wait := busyInitialWait
	for attempt := 1; ; attempt++ {
		err := write(ctx)
		if !IsBusy(err) {
			return err
		}
		if attempt >= busyAttempts {
			return fmt.Errorf("%w: %s gave up after %d attempts: %w", ErrLockContended, what, attempt, err)
		}
		retries.Add(1)
		slog.WarnContext(ctx, "store_write_retried_after_lock_contention",
			slog.String("write", what),
			slog.Int("attempt", attempt),
			slog.Duration("waiting", wait),
		)
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s: waiting to retry after lock contention: %w", what, ctx.Err())
		case <-time.After(jitter(wait)):
		}
		wait = nextBusyWait(wait)
	}
}
