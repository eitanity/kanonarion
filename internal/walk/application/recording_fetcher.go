package application

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"

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
// likewise. Each coordinate is fetched at most once through this wrapper;
// subsequent calls return the recorded outcome.
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
	walkTarget fetchdomain.ModuleCoordinate
	progress   walkports.ProgressReporter // nil = no progress reporting

	mu       sync.Mutex
	outcomes map[fetchdomain.ModuleCoordinate]fetchOutcome
}

// fetchOutcome is the captured result of a single EnsureFetched call. Carries
// enough information for the walker to construct a NodeResult without
// re-fetching the module.
type fetchOutcome struct {
	record     fetchdomain.FactRecord
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
	walkTarget fetchdomain.ModuleCoordinate,
	progress walkports.ProgressReporter,
) *recordingFetcher {
	return &recordingFetcher{
		inner:      inner,
		stopwatch:  stopwatch,
		logger:     logger,
		walkTarget: walkTarget,
		progress:   progress,
		outcomes:   make(map[fetchdomain.ModuleCoordinate]fetchOutcome),
	}
}

// EnsureFetched delegates to the inner fetcher on the first call per coordinate
// and records the outcome. Subsequent calls for the same coordinate return the
// recorded outcome without re-calling the inner fetcher.
func (r *recordingFetcher) EnsureFetched(ctx context.Context, c fetchdomain.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	r.mu.Lock()
	if existing, ok := r.outcomes[c]; ok {
		r.mu.Unlock()
		if existing.err != nil {
			return walkports.ModuleFetchResult{}, existing.err
		}
		return walkports.ModuleFetchResult{Record: existing.record, FromCache: existing.fromCache}, nil
	}
	r.mu.Unlock()

	lap := r.stopwatch.Start()
	r.logger.InfoContext(ctx, "walker.fetch.start",
		slog.String("module.path", c.Path),
		slog.String("module.version", c.Version),
		slog.String("walk.target", r.walkTarget.String()),
	)

	fr, err := r.callWithRecover(ctx, c)
	dur := lap.Elapsed().Milliseconds()

	out := fetchOutcome{
		record:     fr.Record,
		fromCache:  fr.FromCache,
		durationMs: dur,
		err:        err,
	}
	var pe *panicError
	if errors.As(err, &pe) {
		out.panicked = true
	}

	r.mu.Lock()
	// Preserve first-call wins: if a concurrent call already recorded this
	// coordinate, keep the earlier outcome (semantically equivalent since we
	// expect EnsureFetched to be deterministic for a given coordinate, but
	// keeps duration_ms reproducible).
	if _, exists := r.outcomes[c]; !exists {
		r.outcomes[c] = out
	}
	done := len(r.outcomes)
	r.mu.Unlock()

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
		slog.String("module.path", c.Path),
		slog.String("module.version", c.Version),
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
func (r *recordingFetcher) callWithRecover(ctx context.Context, c fetchdomain.ModuleCoordinate) (fr walkports.ModuleFetchResult, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			stack := debug.Stack()
			msg := fmt.Sprintf("panic: %v\n%s", rec, stack)
			r.logger.ErrorContext(ctx, "walker.fetch.panic",
				slog.String("module.path", c.Path),
				slog.String("module.version", c.Version),
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
func (r *recordingFetcher) outcomeFor(c fetchdomain.ModuleCoordinate) (fetchOutcome, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out, ok := r.outcomes[c]
	return out, ok
}
