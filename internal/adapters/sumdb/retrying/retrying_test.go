package retrying

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

var testCoord = coordinatetest.MustNew("golang.org/x/text", "v0.37.0")

func mustHash(t *testing.T, s string) fetchdomain.ModuleHash {
	t.Helper()
	h, err := fetchdomain.ParseModuleHash(s)
	if err != nil {
		t.Fatalf("ParseModuleHash(%q): %v", s, err)
	}
	return h
}

// availableResult is what a lookup that reached the transparency log returns.
func availableResult(t *testing.T) ports.SumDBResult {
	t.Helper()
	return ports.SumDBResult{
		Available: true,
		ZipHash:   mustHash(t, "h1:g0PjBGuJVh1yjjMUhCUXpUFsChmRVeHYnGXqDe6HNTU="),
	}
}

// failureResult is an unavailable-because-the-lookup-failed result carrying err
// for classification.
func failureResult(err error) ports.SumDBResult {
	return ports.SumDBResult{
		Available:      false,
		Reason:         fmt.Sprintf("sumdb lookup: %v", err),
		Unavailability: ports.SumDBUnavailabilityFailure,
		Err:            err,
	}
}

// policyResult is a settled policy answer: the database was not consulted, or
// answered without a hash line.
func policyResult(reason string) ports.SumDBResult {
	return ports.SumDBResult{
		Available:      false,
		Reason:         reason,
		Unavailability: ports.SumDBUnavailabilityPolicy,
	}
}

// scriptedClient returns results[i] on call i+1 and the final result forever
// after, so a test can script "fails N times then succeeds".
type scriptedClient struct {
	results []ports.SumDBResult
	calls   int
	// coords records the coordinate of every call, so a test can prove the retry
	// asked about the same module rather than silently dropping it.
	coords []coordinate.ModuleCoordinate
}

func (c *scriptedClient) Lookup(_ context.Context, coord coordinate.ModuleCoordinate) ports.SumDBResult {
	c.calls++
	c.coords = append(c.coords, coord)
	if c.calls <= len(c.results) {
		return c.results[c.calls-1]
	}
	return c.results[len(c.results)-1]
}

// newTestClient wraps inner with the backoff seams replaced: no real waiting, no
// randomness, and every requested delay recorded.
func newTestClient(t *testing.T, inner ports.SumDBClient, opts ...Option) (*Client, *[]time.Duration, *bytes.Buffer) {
	t.Helper()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	var delays []time.Duration
	c := New(inner, logger, opts...)
	c.jitter = func(d time.Duration) time.Duration { return d }
	c.sleep = func(_ context.Context, d time.Duration) error {
		delays = append(delays, d)
		return nil
	}
	return c, &delays, &logBuf
}

func transientStatusErr(code int) error {
	return &fetchdomain.ProxyStatusError{StatusCode: code, URL: "https://sum.golang.org/lookup/golang.org/x/text@v0.37.0"}
}

func TestAvailableResultOnFirstAttemptDoesNotRetry(t *testing.T) {
	inner := &scriptedClient{results: []ports.SumDBResult{availableResult(t)}}
	c, delays, logBuf := newTestClient(t, inner)

	res := c.Lookup(context.Background(), testCoord)
	if !res.Available {
		t.Fatalf("Lookup returned unavailable: %+v", res)
	}
	if inner.calls != 1 {
		t.Errorf("inner called %d times, want 1", inner.calls)
	}
	if len(*delays) != 0 {
		t.Errorf("backoff waits = %v, want none", *delays)
	}
	if strings.Contains(logBuf.String(), "sumdb.lookup.retry") {
		t.Errorf("retry logged on a successful first attempt: %s", logBuf.String())
	}
}

// TestPolicyUnavailableDoesNotRetry is the reason-split guard: every policy
// reason is the database's settled answer, so it returns immediately, spends no
// backoff, and produces nothing at warn.
func TestPolicyUnavailableDoesNotRetry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason string
	}{
		{"GOSUMDB off", "GOSUMDB=off"},
		{"GOPRIVATE match", "module matches GONOSUMCHECK/GOPRIVATE pattern"},
		{"no hash line", "sumdb returned no zip hash for module"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inner := &scriptedClient{results: []ports.SumDBResult{policyResult(tc.reason)}}
			c, delays, logBuf := newTestClient(t, inner)

			res := c.Lookup(context.Background(), testCoord)
			if res.Available {
				t.Error("policy result reported as available")
			}
			if res.Reason != tc.reason {
				t.Errorf("Reason = %q, want %q", res.Reason, tc.reason)
			}
			if res.LookupFailed() {
				t.Error("policy result classified as a lookup failure")
			}
			if inner.calls != 1 {
				t.Errorf("inner called %d times, want 1 (no retry for a policy answer)", inner.calls)
			}
			if len(*delays) != 0 {
				t.Errorf("backoff waits = %v, want none", *delays)
			}
			if logged := logBuf.String(); strings.Contains(logged, "level=WARN") {
				t.Errorf("policy answer logged at warn: %s", logged)
			}
		})
	}
}

// TestTransientFailureRetriesThenVerifies is the core of the fix: each transient
// failure class retries and, on a later attempt, produces the available result
// the module deserves rather than a downgrade.
func TestTransientFailureRetriesThenVerifies(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"sumdb 503", transientStatusErr(503)},
		{"sumdb 500", transientStatusErr(500)},
		{"sumdb 429", transientStatusErr(429)},
		{"connection reset", errors.New("fetching https://sum.golang.org/lookup/x: read tcp: connection reset by peer")},
		{"unexpected EOF", fmt.Errorf("reading sumdb response for /lookup/x: %w", io.ErrUnexpectedEOF)},
		{"http2 stream reset", errors.New("stream error: stream ID 7; INTERNAL_ERROR; received from peer")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inner := &scriptedClient{results: []ports.SumDBResult{
				failureResult(tc.err),
				availableResult(t),
			}}
			c, delays, logBuf := newTestClient(t, inner)

			res := c.Lookup(context.Background(), testCoord)
			if !res.Available {
				t.Fatalf("lookup still unavailable after a retry that should have succeeded: %+v", res)
			}
			if res.ZipHash != availableResult(t).ZipHash {
				t.Errorf("ZipHash = %v, want the wrapped client's hash", res.ZipHash)
			}
			if inner.calls != 2 {
				t.Errorf("inner called %d times, want 2", inner.calls)
			}
			if len(inner.coords) != 2 || inner.coords[1] != testCoord {
				t.Errorf("retry asked about %+v, want %+v", inner.coords, testCoord)
			}
			if len(*delays) != 1 || (*delays)[0] != defaultBaseDelay {
				t.Errorf("backoff waits = %v, want [%v]", *delays, defaultBaseDelay)
			}
			logged := logBuf.String()
			if !strings.Contains(logged, "level=DEBUG msg=sumdb.lookup.retry ") ||
				!strings.Contains(logged, "module.path=golang.org/x/text") ||
				!strings.Contains(logged, "attempt=1") {
				t.Errorf("retry not logged at debug with module and attempt: %s", logged)
			}
			// A lookup that recovered must add no warn noise: nothing needs an
			// operator's attention about a module that ended up verified.
			if strings.Contains(logged, "level=WARN") {
				t.Errorf("recovered lookup logged at warn: %s", logged)
			}
		})
	}
}

func TestBackoffDoublesPerRetry(t *testing.T) {
	err := transientStatusErr(503)
	inner := &scriptedClient{results: []ports.SumDBResult{
		failureResult(err), failureResult(err), availableResult(t),
	}}
	c, delays, _ := newTestClient(t, inner, WithAttempts(4))

	if res := c.Lookup(context.Background(), testCoord); !res.Available {
		t.Fatalf("lookup unavailable after two retries: %+v", res)
	}
	want := []time.Duration{defaultBaseDelay, 2 * defaultBaseDelay}
	if len(*delays) != len(want) || (*delays)[0] != want[0] || (*delays)[1] != want[1] {
		t.Errorf("backoff waits = %v, want %v", *delays, want)
	}
}

func TestBackoffSaturatesRatherThanOverflowing(t *testing.T) {
	c := New(&scriptedClient{results: []ports.SumDBResult{availableResult(t)}}, slog.New(slog.DiscardHandler))
	for _, attempt := range []int{40, 64, 1000} {
		if got := c.backoffFor(attempt); got != maxBackoff {
			t.Errorf("backoffFor(%d) = %v, want the %v cap (a negative or zero interval would hot-spin)", attempt, got, maxBackoff)
		}
	}
}

// TestExhaustedBudgetWarnsAndReturnsTheFailure is the never-silent guard: once
// the budget is spent the downgraded result is returned unchanged, and a WARN
// says the downgrade came from a failed lookup rather than from the module.
func TestExhaustedBudgetWarnsAndReturnsTheFailure(t *testing.T) {
	err := transientStatusErr(503)
	inner := &scriptedClient{results: []ports.SumDBResult{failureResult(err)}}
	c, delays, logBuf := newTestClient(t, inner)

	res := c.Lookup(context.Background(), testCoord)
	if res.Available {
		t.Fatal("lookup reported available after every attempt failed")
	}
	if !res.LookupFailed() {
		t.Error("exhausted result did not stay failure-unavailable, so the record would be cached")
	}
	if res.Reason != failureResult(err).Reason {
		t.Errorf("Reason = %q, want the wrapped client's reason unchanged", res.Reason)
	}
	if inner.calls != defaultAttempts {
		t.Errorf("inner called %d times, want %d", inner.calls, defaultAttempts)
	}
	if len(*delays) != defaultAttempts-1 {
		t.Errorf("backoff waits = %v, want %d", *delays, defaultAttempts-1)
	}
	logged := logBuf.String()
	if !strings.Contains(logged, "level=WARN msg=sumdb.lookup.retries_exhausted") {
		t.Errorf("exhausted budget not warned: %s", logged)
	}
	for _, want := range []string{
		"module.path=golang.org/x/text",
		"module.version=v0.37.0",
		fmt.Sprintf("attempts=%d", defaultAttempts),
		"reason=",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("exhaustion WARN missing %q: %s", want, logged)
		}
	}
}

// TestPermanentFailureDoesNotRetry covers the errors that are real answers about
// the database or the module: a misbehaving-server verdict and an unrecognised
// condition must fail on sight, since retrying only delays recording them.
func TestPermanentFailureDoesNotRetry(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"security error", errors.New("security error: misbehaving server")},
		{"malformed record", errors.New("parsing record: malformed record data")},
		{"404 not found", &fetchdomain.ProxyStatusError{StatusCode: 404, URL: "https://sum.golang.org/lookup/x"}},
		{"context canceled", fmt.Errorf("fetching lookup: %w", context.Canceled)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inner := &scriptedClient{results: []ports.SumDBResult{failureResult(tc.err), availableResult(t)}}
			c, delays, logBuf := newTestClient(t, inner)

			res := c.Lookup(context.Background(), testCoord)
			if res.Available {
				t.Error("a permanent failure was retried into an available result")
			}
			if inner.calls != 1 {
				t.Errorf("inner called %d times, want 1", inner.calls)
			}
			if len(*delays) != 0 {
				t.Errorf("backoff waits = %v, want none", *delays)
			}
			if logged := logBuf.String(); strings.Contains(logged, "sumdb.lookup.retry") {
				t.Errorf("permanent failure produced a retry log: %s", logged)
			}
		})
	}
}

// TestNilErrOnFailureIsNotRetried guards the classifier's contract at this
// boundary: a client that reports a failure without carrying the error gives
// nothing to classify, and an unclassifiable condition is permanent.
func TestNilErrOnFailureIsNotRetried(t *testing.T) {
	inner := &scriptedClient{results: []ports.SumDBResult{
		{Available: false, Reason: "sumdb lookup: something", Unavailability: ports.SumDBUnavailabilityFailure},
		availableResult(t),
	}}
	c, delays, _ := newTestClient(t, inner)

	if res := c.Lookup(context.Background(), testCoord); res.Available {
		t.Error("failure with no Err was retried")
	}
	if inner.calls != 1 {
		t.Errorf("inner called %d times, want 1", inner.calls)
	}
	if len(*delays) != 0 {
		t.Errorf("backoff waits = %v, want none", *delays)
	}
}

// TestUnsetUnavailabilityIsTreatedAsPolicy pins the default a SumDBClient that
// never sets the discriminator gets: the pre-existing no-retry behaviour, so
// adding the field cannot change any adapter that has not opted in.
func TestUnsetUnavailabilityIsTreatedAsPolicy(t *testing.T) {
	inner := &scriptedClient{results: []ports.SumDBResult{
		{Available: false, Reason: "no go.sum entry"},
		availableResult(t),
	}}
	c, delays, _ := newTestClient(t, inner)

	res := c.Lookup(context.Background(), testCoord)
	if res.LookupFailed() {
		t.Error("an unset Unavailability was read as a lookup failure")
	}
	if inner.calls != 1 || len(*delays) != 0 {
		t.Errorf("inner called %d times with waits %v, want 1 call and no waits", inner.calls, *delays)
	}
}

// TestContextEndingDuringBackoffAborts records the cancellation as its own
// outcome rather than as an exhausted budget, and returns the lookup result the
// caller asked about.
func TestContextEndingDuringBackoffAborts(t *testing.T) {
	err := transientStatusErr(503)
	inner := &scriptedClient{results: []ports.SumDBResult{failureResult(err)}}
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c := New(inner, logger)
	c.jitter = func(d time.Duration) time.Duration { return d }
	c.sleep = func(context.Context, time.Duration) error { return context.Canceled }

	res := c.Lookup(context.Background(), testCoord)
	if !res.LookupFailed() {
		t.Errorf("aborted lookup lost its failure discriminator: %+v", res)
	}
	if inner.calls != 1 {
		t.Errorf("inner called %d times, want 1", inner.calls)
	}
	logged := logBuf.String()
	if !strings.Contains(logged, "sumdb.lookup.retry.aborted") {
		t.Errorf("abort not logged: %s", logged)
	}
	if strings.Contains(logged, "retries_exhausted") {
		t.Errorf("cancellation reported as an exhausted budget: %s", logged)
	}
}

func TestOptionsRejectNonsenseValues(t *testing.T) {
	inner := &scriptedClient{results: []ports.SumDBResult{availableResult(t)}}
	c := New(inner, slog.New(slog.DiscardHandler), WithAttempts(0), WithBaseDelay(-time.Second))
	if c.attempts != defaultAttempts {
		t.Errorf("attempts = %d, want the %d default (0 must be ignored)", c.attempts, defaultAttempts)
	}
	if c.baseDelay != defaultBaseDelay {
		t.Errorf("baseDelay = %v, want the %v default (negative must be ignored)", c.baseDelay, defaultBaseDelay)
	}
}

func TestSleepCtxReturnsEarlyOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepCtx(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("sleepCtx = %v, want context.Canceled", err)
	}
	if err := sleepCtx(context.Background(), 0); err != nil {
		t.Errorf("sleepCtx(0) = %v, want nil", err)
	}
	if err := sleepCtx(context.Background(), time.Millisecond); err != nil {
		t.Errorf("sleepCtx(1ms) = %v, want nil", err)
	}
}

func TestFullJitterStaysWithinHalfOpenRange(t *testing.T) {
	if got := fullJitter(0); got != 0 {
		t.Errorf("fullJitter(0) = %v, want 0", got)
	}
	const d = 400 * time.Millisecond
	for range 200 {
		got := fullJitter(d)
		if got < d/2 || got > d {
			t.Fatalf("fullJitter(%v) = %v, outside [%v, %v]", d, got, d/2, d)
		}
	}
}
