package retrying

import (
	"context"
	"fmt"
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

func (p *recordingProgress) RetryingLookup(path string, attempt int, elapsed, window time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lines = append(p.lines, fmt.Sprintf("%s %d %v/%v", path, attempt, elapsed, window))
}

func (p *recordingProgress) SettlingLookups(pending int, interval, window time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lines = append(p.lines, fmt.Sprintf("settling %d every %v for %v", pending, interval, window))
}

func (p *recordingProgress) got() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.lines...)
}

// A retry is announced before its wait, naming the module, the attempt about to
// be made, the time spent so far and the window.
func TestRetryIsReportedToProgress(t *testing.T) {
	prog := &recordingProgress{}
	r := New(nil, discardLogger(), WithProgress(prog))
	clk := withFakeClock(r, 0)
	inner := newScripted(clk)
	inner.transient["example.com/mod/v2"] = 2
	r.inner = inner

	if _, err := r.LatestInfo(context.Background(), "example.com/mod/v2"); err != nil {
		t.Fatalf("LatestInfo: %v", err)
	}
	want := []string{
		"example.com/mod/v2 2 0s/4m0s",
		"example.com/mod/v2 3 20s/4m0s",
	}
	if got := prog.got(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("reported %v, want %v", got, want)
	}
}

// answeringResolver answers on sight.
type answeringResolver struct{ calls int }

func (f *answeringResolver) LatestInfo(context.Context, string) (ports.LatestInfo, error) {
	f.calls++
	return ports.LatestInfo{Version: "v2.1.0"}, nil
}

// A lookup that does not retry says nothing at all: an answer and a definitive
// absence both pass through silently.
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
			r := New(tc.inner, discardLogger(), WithProgress(prog))
			r.sleep = func(context.Context, time.Duration) error {
				t.Error("backoff slept on a lookup that should not retry")
				return nil
			}
			_, _ = r.LatestInfo(context.Background(), "example.com/mod/v2") //nolint:errcheck // one case answers and one is a negative; the subject is the progress
			if got := prog.got(); len(got) != 0 {
				t.Errorf("reported %v, want nothing", got)
			}
		})
	}
}
