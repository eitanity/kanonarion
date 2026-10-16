package retrying

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/staleness/ports"
)

// fakeClock stands in for time: sleeping advances it, and so does each request
// by reqCost, which models the adapter's own request timeout.
type fakeClock struct {
	mu      sync.Mutex
	t       time.Time
	reqCost time.Duration
	slept   []time.Duration
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) sleep(_ context.Context, d time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.slept = append(c.slept, d)
	c.t = c.t.Add(d)
	return nil
}

func (c *fakeClock) request() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(c.reqCost)
}

func (c *fakeClock) waits() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.slept...)
}

// withFakeClock puts r on a fake clock with jitter neutralised.
func withFakeClock(r *Resolver, reqCost time.Duration) *fakeClock {
	c := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), reqCost: reqCost}
	r.now = c.now
	r.sleep = c.sleep
	r.jitter = func(d time.Duration) time.Duration { return d }
	return c
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// scriptedResolver answers each path transiently for its first transient[path]
// asks, then with final[path] (a nil error is an answer). It advances clk per
// request when one is set.
type scriptedResolver struct {
	mu        sync.Mutex
	clk       *fakeClock
	transient map[string]int
	final     map[string]error
	calls     map[string]int
}

func newScripted(clk *fakeClock) *scriptedResolver {
	return &scriptedResolver{clk: clk, transient: map[string]int{}, final: map[string]error{}, calls: map[string]int{}}
}

func (s *scriptedResolver) LatestInfo(_ context.Context, path string) (ports.LatestInfo, error) {
	if s.clk != nil {
		s.clk.request()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[path]++
	if s.calls[path] <= s.transient[path] || s.transient[path] < 0 {
		return ports.LatestInfo{}, &fetchdomain.ProxyEmptyResponseError{Path: path}
	}
	if err := s.final[path]; err != nil {
		return ports.LatestInfo{}, err
	}
	return ports.LatestInfo{Version: "v2.1.0"}, nil
}

func (s *scriptedResolver) asked(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[path]
}

// The single-path schedule: a re-ask every interval until the window after the
// first attempt closes. With instant requests that is the first ask plus one
// per 20s up to and including 240s.
func TestSinglePathScheduleIsIntervalUntilWindow(t *testing.T) {
	r := New(nil, discardLogger())
	clk := withFakeClock(r, 0)
	inner := newScripted(clk)
	inner.transient["example.com/mod/v2"] = -1
	r.inner = inner

	if _, err := r.LatestInfo(context.Background(), "example.com/mod/v2"); err == nil {
		t.Fatal("a persistently empty proxy answered successfully")
	}
	if got := inner.asked("example.com/mod/v2"); got != 13 {
		t.Errorf("attempts = %d, want 13 (0s, 20s, ..., 240s)", got)
	}
	waits := clk.waits()
	if len(waits) != 12 {
		t.Fatalf("waits = %v, want 12 of 20s", waits)
	}
	for i, d := range waits {
		if d != SettleInterval {
			t.Errorf("wait %d = %v, want %v", i+1, d, SettleInterval)
		}
	}
}

// Requests that take the adapter's 10s timeout count against the window: the
// window runs from the first ask, not from the end of the last one.
func TestSinglePathWindowIncludesRequestTime(t *testing.T) {
	r := New(nil, discardLogger())
	clk := withFakeClock(r, 10*time.Second)
	inner := newScripted(clk)
	inner.transient["example.com/mod/v2"] = -1
	r.inner = inner

	_, _ = r.LatestInfo(context.Background(), "example.com/mod/v2") //nolint:errcheck // the subject is the schedule
	// Asks start at 0, 30, ..., 240s: nine of them.
	if got := inner.asked("example.com/mod/v2"); got != 9 {
		t.Errorf("attempts = %d, want 9", got)
	}
}

// A path the proxy finishes inside the window is answered, and the wait stops
// there.
func TestSinglePathAnswersWhenTheProxyFinishes(t *testing.T) {
	r := New(nil, discardLogger())
	clk := withFakeClock(r, 0)
	inner := newScripted(clk)
	inner.transient["example.com/mod/v2"] = 5
	r.inner = inner

	info, err := r.LatestInfo(context.Background(), "example.com/mod/v2")
	if err != nil || info.Version != "v2.1.0" {
		t.Fatalf("LatestInfo = %+v, %v; want v2.1.0", info, err)
	}
	if got := inner.asked("example.com/mod/v2"); got != 6 {
		t.Errorf("attempts = %d, want 6", got)
	}
	if got := len(clk.waits()); got != 5 {
		t.Errorf("waits = %d, want 5", got)
	}
}

// The exhaustion warning names the interval, the window and the elapsed time,
// so a reader can tell how long a probe waited against how long it could.
func TestExhaustionWarningNamesTheWindow(t *testing.T) {
	var buf bytes.Buffer
	r := New(nil, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	clk := withFakeClock(r, 10*time.Second)
	inner := newScripted(clk)
	inner.transient["example.com/mod/v2"] = -1
	r.inner = inner

	if _, err := r.LatestInfo(context.Background(), "example.com/mod/v2"); err == nil {
		t.Fatal("a persistently empty proxy answered successfully")
	}
	line := buf.String()
	for _, want := range []string{
		"staleness.latest.retries_exhausted",
		"module.path=example.com/mod/v2",
		"attempts=9",
		"interval_ms=20000",
		"window_ms=240000",
		"elapsed_ms=250000",
		"empty response",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("exhaustion warning %q does not contain %q", line, want)
		}
	}
	if strings.Count(line, "retries_exhausted") != 1 {
		t.Errorf("want exactly one exhaustion warning, got %q", line)
	}
}

// The non-zero control: a definitive 404 costs exactly one request and no wait.
func TestAbsentPathCostsOneRequestAndNoWait(t *testing.T) {
	r := New(nil, discardLogger())
	clk := withFakeClock(r, 0)
	inner := newScripted(clk)
	inner.final["example.com/mod/v9"] = fmt.Errorf("resolving: %w", ports.ErrPathAbsent)
	r.inner = inner

	_, err := r.LatestInfo(context.Background(), "example.com/mod/v9")
	if !errors.Is(err, ports.ErrPathAbsent) {
		t.Fatalf("error = %v, want ErrPathAbsent", err)
	}
	if got := inner.asked("example.com/mod/v9"); got != 1 {
		t.Errorf("requests = %d, want exactly 1", got)
	}
	if got := clk.waits(); len(got) != 0 {
		t.Errorf("slept %v on a definitive answer, want no sleep", got)
	}
}

// The timeout the ADAPTER imposes on its own request is re-asked like any other
// transient condition.
func TestAdapterTimeoutIsRetried(t *testing.T) {
	inner := &timingOutResolver{}
	r := New(inner, discardLogger())
	withFakeClock(r, 0)

	if _, err := r.LatestInfo(context.Background(), "example.com/mod/v2"); err == nil {
		t.Fatal("a resolver that always times out answered successfully")
	}
	if inner.calls < 2 {
		t.Errorf("attempts = %d, want the timeout re-asked", inner.calls)
	}
}

// The control for that: a CALLER cancellation still fails on sight.
func TestCallerCancellationIsNotRetried(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"caller cancelled", context.Canceled},
		{"caller deadline expired", context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inner := &erroringResolver{err: tc.err}
			r := New(inner, discardLogger())
			r.sleep = func(context.Context, time.Duration) error {
				t.Error("backoff slept for a caller cancellation")
				return nil
			}
			if _, err := r.LatestInfo(context.Background(), "example.com/mod/v2"); err == nil {
				t.Fatal("want the cancellation error, got nil")
			}
			if inner.calls != 1 {
				t.Errorf("attempts = %d, want exactly 1", inner.calls)
			}
		})
	}
}

// timingOutResolver answers every lookup with the adapter's own request
// timeout, wrapped the way the proxy client wraps it.
type timingOutResolver struct{ calls int }

func (f *timingOutResolver) LatestInfo(context.Context, string) (ports.LatestInfo, error) {
	f.calls++
	return ports.LatestInfo{}, fmt.Errorf("resolving example.com/mod/v2@latest: %w", &fetchdomain.ProxyRequestTimeoutError{
		URL:     "https://proxy.golang.org/example.com/mod/v2/@latest",
		Timeout: 10 * time.Second,
		Err:     context.DeadlineExceeded,
	})
}

// erroringResolver answers every lookup with a fixed error.
type erroringResolver struct {
	err   error
	calls int
}

func (f *erroringResolver) LatestInfo(context.Context, string) (ports.LatestInfo, error) {
	f.calls++
	return ports.LatestInfo{}, fmt.Errorf("resolving example.com/mod/v2@latest: %w", f.err)
}

// The context ending during the wait is a stop, not a closed window: the lookup
// error is reported with the cancellation, and no further ask is made.
func TestCancelledBackoffStopsRetrying(t *testing.T) {
	inner := newScripted(nil)
	inner.transient["example.com/mod/v2"] = -1
	r := New(inner, discardLogger())
	r.sleep = func(context.Context, time.Duration) error { return context.Canceled }

	_, err := r.LatestInfo(context.Background(), "example.com/mod/v2")
	if err == nil {
		t.Fatal("want the lookup error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("the cancellation is missing from the returned error: %v", err)
	}
	if got := inner.asked("example.com/mod/v2"); got != 1 {
		t.Errorf("attempts = %d, want 1", got)
	}
}

// fullJitter stays inside [d/2, d].
func TestJitterStaysInHalfToWhole(t *testing.T) {
	for range 1000 {
		if got := fullJitter(SettleInterval); got < SettleInterval/2 || got > SettleInterval {
			t.Fatalf("fullJitter(%v) = %v, outside [d/2, d]", SettleInterval, got)
		}
	}
	if got := fullJitter(0); got != 0 {
		t.Errorf("fullJitter(0) = %v, want 0", got)
	}
}
