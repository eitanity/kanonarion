package application

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// recordingFetcher wraps a walkports.ModuleFetcher to capture the first-call
// outcome (FromCache, duration_ms, FetchRecord, error) per coordinate. Used by
// the walker to surface accurate per-node fetch results in WalkOutcome.PerNodeResults
// even when the resolver did the actual fetch during graph resolution.
//
// Without recording, the walker would re-fetch every module after resolution to
// observe FromCache, but by then the resolver has already populated the cache —
// so re-fetched transitives are always reported as cache hits with duration 0,
// hiding the cold-fetch fraction of the walk.
//
// recordingFetcher is safe for concurrent use; the underlying fetcher must be
// likewise. Each coordinate is fetched at most once through this wrapper:
// later calls return the recorded outcome, and calls that OVERLAP the first
// wait for it rather than starting a second fetch of their own. A coordinate
// can reach one level twice — a module whose replace target is also an
// independent build-list entry occupies two nodes and so two fetch tasks — and
// without the in-flight wait both tasks would fetch, measure and append a
// second, redundant fact record for the same artefact.
//
// A panic in the underlying fetcher is recovered and recorded as a fetchOutcome
// with panicked=true. The error returned to the caller is a *panicError so the
// resolver still observes a fetch failure (and marks the graph node accordingly),
// while the walker can distinguish panics from regular fetch failures when
// building NodeResults.
type recordingFetcher struct {
	inner      walkports.ModuleFetcher
	stopwatch  fetchports.Stopwatch
	logger     *slog.Logger
	walkTarget coordinate.ModuleCoordinate
	progress   walkports.ProgressReporter // nil = no progress reporting

	mu       sync.Mutex
	outcomes map[coordinate.ModuleCoordinate]fetchOutcome
	inflight map[coordinate.ModuleCoordinate]*inflightFetch
}

// inflightFetch marks a coordinate whose fetch has started but not yet been
// recorded. done is closed once the outcome is in outcomes, so a waiter that
// observes the close is guaranteed to find it.
type inflightFetch struct {
	done chan struct{}
}

// fetchOutcome is the captured result of a single EnsureFetched call. Carries
// enough information for the walker to construct a NodeResult without
// re-fetching the module.
type fetchOutcome struct {
	record     fetchdomain.CompositeRecord
	fromCache  bool
	durationMs int64
	err        error
	panicked   bool
}

// panicError wraps a panic recovered from the underlying fetcher so callers can
// distinguish it from a regular fetch error via errors.As.
type panicError struct {
	msg string
}

func (e *panicError) Error() string { return e.msg }

func newRecordingFetcher(
	inner walkports.ModuleFetcher,
	stopwatch fetchports.Stopwatch,
	logger *slog.Logger,
	walkTarget coordinate.ModuleCoordinate,
	progress walkports.ProgressReporter,
) *recordingFetcher {
	return &recordingFetcher{
		inner:      inner,
		stopwatch:  stopwatch,
		logger:     logger,
		walkTarget: walkTarget,
		progress:   progress,
		outcomes:   make(map[coordinate.ModuleCoordinate]fetchOutcome),
		inflight:   make(map[coordinate.ModuleCoordinate]*inflightFetch),
	}
}

// EnsureFetched delegates to the inner fetcher on the first call per coordinate
// and records the outcome. Later calls for the same coordinate return the
// recorded outcome without re-calling the inner fetcher; a call that arrives
// while the first is still running waits for it and then returns that same
// outcome, so one coordinate is never fetched twice by one walk.
func (r *recordingFetcher) EnsureFetched(ctx context.Context, c coordinate.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	for {
		r.mu.Lock()
		if existing, ok := r.outcomes[c]; ok {
			r.mu.Unlock()
			return resultOf(existing)
		}
		if wait, ok := r.inflight[c]; ok {
			r.mu.Unlock()
			select {
			case <-wait.done:
				// The outcome is recorded; re-read it on the next pass.
				continue
			case <-ctx.Done():
				return walkports.ModuleFetchResult{}, fmt.Errorf("waiting for an in-flight fetch of %s: %w", c, ctx.Err())
			}
		}
		lead := &inflightFetch{done: make(chan struct{})}
		r.inflight[c] = lead
		r.mu.Unlock()
		return r.fetchAndRecord(ctx, c, lead)
	}
}

// resultOf converts a recorded outcome back into the fetcher's return pair.
func resultOf(out fetchOutcome) (walkports.ModuleFetchResult, error) {
	if out.err != nil {
		return walkports.ModuleFetchResult{}, out.err
	}
	return walkports.ModuleFetchResult{Record: out.record, FromCache: out.fromCache}, nil
}

// fetchAndRecord performs the one real fetch for c, records its outcome and
// releases any callers waiting on lead. The caller must have registered lead in
// r.inflight; this method always removes it and closes lead.done, so a waiter
// cannot be stranded even if the fetch path fails.
func (r *recordingFetcher) fetchAndRecord(ctx context.Context, c coordinate.ModuleCoordinate, lead *inflightFetch) (walkports.ModuleFetchResult, error) {
	out := fetchOutcome{}
	done := 0
	settled := false
	settle := func() {
		if settled {
			return
		}
		settled = true
		r.mu.Lock()
		// Preserve first-call wins: if a concurrent call already recorded this
		// coordinate, keep the earlier outcome (semantically equivalent since we
		// expect EnsureFetched to be deterministic for a given coordinate, but
		// keeps duration_ms reproducible).
		if _, exists := r.outcomes[c]; !exists {
			r.outcomes[c] = out
		}
		delete(r.inflight, c)
		done = len(r.outcomes)
		r.mu.Unlock()
		close(lead.done)
	}
	// Waiters block on lead.done, so it must be closed on every exit — including
	// a panic that escapes the fetch path — or the walk deadlocks instead of
	// reporting the failure.
	defer settle()

	lap := r.stopwatch.Start()
	r.logger.InfoContext(ctx, "walker.fetch.start",
		slog.String("module.path", c.Path()),
		slog.String("module.version", c.Version()),
		slog.String("walk.target", r.walkTarget.String()),
	)

	fr, err := r.callWithRecover(ctx, c)
	dur := lap.Elapsed().Milliseconds()

	out = fetchOutcome{
		record:     fr.Record,
		fromCache:  fr.FromCache,
		durationMs: dur,
		err:        err,
	}
	if _, ok := errors.AsType[*panicError](err); ok {
		out.panicked = true
	}

	// Record the outcome and release any waiters before reporting progress or
	// logging, so a caller blocked on this coordinate is not held up by them.
	settle()

	// Report progress once per distinct fetched module. The reporter throttles
	// and writes (e.g. a heartbeat line); reporting outside the lock keeps the
	// fetch path uncontended.
	if r.progress != nil {
		r.progress.Advance(done)
	}

	errType := ""
	switch {
	case out.panicked:
		errType = "internal_panic"
	case err != nil:
		errType = "fetch_failed"
	}
	r.logger.InfoContext(ctx, "walker.fetch.end",
		slog.String("module.path", c.Path()),
		slog.String("module.version", c.Version()),
		slog.String("walk.target", r.walkTarget.String()),
		slog.Bool("from_cache", out.fromCache),
		slog.Int64("duration_ms", dur),
		slog.String("error.type", errType),
	)

	return fr, err
}

// callWithRecover invokes the inner fetcher and converts any panic into a
// *panicError so it propagates as a regular fetch error (with stack info)
// instead of crashing the walk.
func (r *recordingFetcher) callWithRecover(ctx context.Context, c coordinate.ModuleCoordinate) (fr walkports.ModuleFetchResult, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			stack := debug.Stack()
			msg := fmt.Sprintf("panic: %v\n%s", rec, stack)
			r.logger.ErrorContext(ctx, "walker.fetch.panic",
				slog.String("module.path", c.Path()),
				slog.String("module.version", c.Version()),
				slog.String("detail", msg),
			)
			fr = walkports.ModuleFetchResult{}
			err = &panicError{msg: msg}
		}
	}()
	fr, err = r.inner.EnsureFetched(ctx, c)
	if err != nil {
		return fr, fmt.Errorf("inner fetcher: %w", err)
	}
	return fr, nil
}

// outcomeFor returns the recorded outcome for c, or (zero, false) if none was
// recorded (i.e. the resolver never fetched c).
func (r *recordingFetcher) outcomeFor(c coordinate.ModuleCoordinate) (fetchOutcome, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out, ok := r.outcomes[c]
	return out, ok
}
