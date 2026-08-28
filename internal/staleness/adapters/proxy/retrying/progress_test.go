package retrying

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/staleness/ports"
)

// recordingProgress captures what a watcher would have been told.
type recordingProgress struct {
	mu    sync.Mutex
	lines []string
}

func (p *recordingProgress) RetryingLookup(path string, attempt, maxAttempts int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lines = append(p.lines, fmt.Sprintf("%s %d/%d", path, attempt, maxAttempts))
}

// A retry is announced as it happens, naming the module, the attempt about to
// be made and the budget it is bounded by.
//
// The failure is a FAKE transient one. A real one is a loaded proxy answering
// an empty 200, which cannot be summoned on demand and which a test that waits
// for it turns into a flake.
func TestRetryIsReportedToProgress(t *testing.T) {
	inner := &failingResolver{}
	prog := &recordingProgress{}
	r := New(inner, slog.New(slog.NewTextHandler(io.Discard, nil)), WithProgress(prog))
	var waited []time.Duration
	r.sleep = func(_ context.Context, d time.Duration) error {
		waited = append(waited, d)
		return nil
	}
	r.jitter = func(d time.Duration) time.Duration { return d }

	if _, err := r.LatestInfo(context.Background(), "example.com/mod/v2"); err == nil {
		t.Fatal("a persistently empty proxy answered successfully")
	}

	want := []string{
		"example.com/mod/v2 2/4",
		"example.com/mod/v2 3/4",
		"example.com/mod/v2 4/4",
	}
	if len(prog.lines) != len(want) {
		t.Fatalf("reported %v, want %v", prog.lines, want)
	}
	for i, line := range prog.lines {
		if line != want[i] {
			t.Errorf("report %d = %q, want %q", i+1, line, want[i])
		}
	}

	// The control on the budget: attaching a reporter changes the narration and
	// nothing else. Same four attempts, same 2s/4s/8s schedule as
	// TestBackoffScheduleIsBoundedAndStated pins without one.
	if inner.calls != 4 {
		t.Errorf("attempts = %d, want 4", inner.calls)
	}
	if got := fmt.Sprint(waited); got != fmt.Sprint([]time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second}) {
		t.Errorf("waits = %v, want 2s 4s 8s", waited)
	}
}

// answeringResolver answers on sight.
type answeringResolver struct{ calls int }

func (f *answeringResolver) LatestInfo(context.Context, string) (ports.LatestInfo, error) {
	f.calls++
	return ports.LatestInfo{Version: "v2.1.0"}, nil
}

// The control that matters most: a lookup that does not retry says nothing at
// all. Both an answer and a definitive absence go through the decorator
// silently, so a run with nothing slow in it narrates exactly what it narrated
// before this port existed.
func TestNoRetryReportsNothing(t *testing.T) {
	for _, tc := range []struct {
		name  string
		inner ports.LatestResolver
	}{
		{"answered on the first attempt", &answeringResolver{}},
		{"absent path, a definitive negative", &erroringResolver{err: ports.ErrPathAbsent}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prog := &recordingProgress{}
			r := New(tc.inner, slog.New(slog.NewTextHandler(io.Discard, nil)), WithProgress(prog))
			r.sleep = func(context.Context, time.Duration) error {
				t.Error("backoff slept on a lookup that should not retry")
				return nil
			}
			_, _ = r.LatestInfo(context.Background(), "example.com/mod/v2")
			if len(prog.lines) != 0 {
				t.Errorf("reported %v, want nothing", prog.lines)
			}
		})
	}
}
