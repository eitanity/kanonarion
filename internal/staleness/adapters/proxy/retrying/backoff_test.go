package retrying

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/staleness/ports"
)

// failingResolver answers every lookup with a transient empty response.
type failingResolver struct{ calls int }

func (f *failingResolver) LatestInfo(context.Context, string) (ports.LatestInfo, error) {
	f.calls++
	return ports.LatestInfo{}, &fetchdomain.ProxyEmptyResponseError{Path: "example.com/mod/v2"}
}

// The friction the retry adds is wall time on the failing path, so the schedule
// it waits is stated as a number rather than left to be inferred from the
// constants. Jitter is neutralised here; in production each wait is spread over
// [d/2, d], which halves the figure at worst and never exceeds it.
func TestBackoffScheduleIsBoundedAndStated(t *testing.T) {
	inner := &failingResolver{}
	var waited []time.Duration
	r := New(inner, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.sleep = func(_ context.Context, d time.Duration) error {
		waited = append(waited, d)
		return nil
	}
	r.jitter = func(d time.Duration) time.Duration { return d }

	if _, err := r.LatestInfo(context.Background(), "example.com/mod/v2"); err == nil {
		t.Fatal("a persistently empty proxy answered successfully")
	}
	if inner.calls != 4 {
		t.Errorf("attempts = %d, want 4", inner.calls)
	}
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second}
	if len(waited) != len(want) {
		t.Fatalf("waits = %v, want %v", waited, want)
	}
	var total time.Duration
	for i, d := range waited {
		if d != want[i] {
			t.Errorf("wait %d = %v, want %v", i+1, d, want[i])
		}
		total += d
	}
	// The number this pins: 14s un-jittered, once, per module whose probe never
	// answers, and half that at the low end of the jitter. Added to four
	// requests bounded at ten seconds each it comes to 54s, which is under the
	// ~56s a single lost probe costs today — so the raised budget buys attempts
	// without buying wall time. It is a deliberate rise from the 600ms that
	// expired inside the condition it was retrying.
	if total != 14*time.Second {
		t.Errorf("total backoff = %v, want 14s", total)
	}
	if got := r.backoffBudget(); got != total {
		t.Errorf("backoffBudget() = %v, want the schedule's own total %v", got, total)
	}
}

// The exhaustion warning has to name the budget, not just the attempt count: a
// reader looking at a probe that gave up needs to know how long it waited
// against how long it was ever going to wait.
func TestExhaustionWarningNamesTheBudget(t *testing.T) {
	inner := &failingResolver{}
	var buf bytes.Buffer
	r := New(inner, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	r.sleep = func(context.Context, time.Duration) error { return nil }
	r.jitter = func(d time.Duration) time.Duration { return d }

	if _, err := r.LatestInfo(context.Background(), "example.com/mod/v2"); err == nil {
		t.Fatal("a persistently empty proxy answered successfully")
	}
	line := buf.String()
	for _, want := range []string{
		"staleness.latest.retries_exhausted",
		"attempts=4",
		"attempts.max=4",
		"backoff_budget_ms=14000",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("exhaustion warning %q does not contain %q", line, want)
		}
	}
}

// The timeout the ADAPTER imposes on its own request is retried like any other
// transient condition. Before the classifier learned to tell it from a caller
// giving up, this failed on the first attempt — which is the case that matters
// most on a slow link, because a slow link is where timeouts happen.
func TestAdapterTimeoutIsRetried(t *testing.T) {
	inner := &timingOutResolver{}
	r := New(inner, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.sleep = func(context.Context, time.Duration) error { return nil }

	if _, err := r.LatestInfo(context.Background(), "example.com/mod/v2"); err == nil {
		t.Fatal("a resolver that always times out answered successfully")
	}
	if inner.calls != 4 {
		t.Errorf("attempts = %d, want the full 4-attempt budget", inner.calls)
	}
}

// The control for that change: a CALLER cancellation still fails on sight. This
// is the property the classifier's context guard exists to protect, and the one
// the timeout work risks.
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
			r := New(inner, slog.New(slog.NewTextHandler(io.Discard, nil)))
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

// The context ending during backoff is a stop, not an exhausted budget: the
// lookup error is reported and the remaining attempts are not spent.
func TestCancelledBackoffStopsRetrying(t *testing.T) {
	inner := &failingResolver{}
	r := New(inner, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.sleep = func(context.Context, time.Duration) error { return context.Canceled }

	if _, err := r.LatestInfo(context.Background(), "example.com/mod/v2"); err == nil {
		t.Fatal("want the lookup error, got nil")
	}
	if inner.calls != 1 {
		t.Errorf("attempts = %d, want 1", inner.calls)
	}
}
