package retrying

import (
	"context"
	"io"
	"log/slog"
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
	if inner.calls != 3 {
		t.Errorf("attempts = %d, want 3", inner.calls)
	}
	want := []time.Duration{200 * time.Millisecond, 400 * time.Millisecond}
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
	// The number this pins: 600ms un-jittered, once, per module whose probe
	// never answers. It is what a sweep pays for the answers it recovers.
	if total != 600*time.Millisecond {
		t.Errorf("total backoff = %v, want 600ms", total)
	}
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
