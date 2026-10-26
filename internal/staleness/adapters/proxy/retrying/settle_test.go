package retrying

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/staleness/ports"
)

// askRound asks every path once, as a prefetch round does.
func askRound(r *Resolver, paths ...string) []ports.RoundAnswer {
	out := make([]ports.RoundAnswer, 0, len(paths))
	for _, p := range paths {
		out = append(out, r.AskOnce(context.Background(), p))
	}
	return out
}

func byPath(as []ports.RoundAnswer) map[string]ports.RoundAnswer {
	m := make(map[string]ports.RoundAnswer, len(as))
	for _, a := range as {
		m[a.Path] = a
	}
	return m
}

// A path the proxy has not finished is answered once it finishes: transient for
// three asks, then a definitive 404 the walk can stop on.
func TestSettleAnswersAPathTheProxyFinishesLate(t *testing.T) {
	r := New(nil, discardLogger())
	clk := withFakeClock(r, 0)
	inner := newScripted(clk)
	inner.transient["example.com/a/v2"] = 3
	inner.final["example.com/a/v2"] = fmt.Errorf("resolving: %w", ports.ErrPathAbsent)
	r.inner = inner

	round := askRound(r, "example.com/a/v2")
	if !round[0].Unsettled {
		t.Fatalf("first ask = %+v, want unsettled", round[0])
	}
	got := r.Settle(context.Background(), round, 4)[0]
	if got.Unsettled || !errors.Is(got.Err, ports.ErrPathAbsent) {
		t.Fatalf("settled = %+v, want a definitive ErrPathAbsent", got)
	}
	if n := inner.asked("example.com/a/v2"); n != 4 {
		t.Errorf("requests = %d, want 4", n)
	}
	if w := clk.waits(); fmt.Sprint(w) != fmt.Sprint([]time.Duration{SettleInterval, SettleInterval, SettleInterval}) {
		t.Errorf("waits = %v, want three of %v", w, SettleInterval)
	}
}

// A path still unsettled when its window closes stays a failure and is named in
// the exhaustion warning, once.
func TestSettleGivesUpAtTheWindow(t *testing.T) {
	var buf bytes.Buffer
	r := New(nil, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	clk := withFakeClock(r, 10*time.Second)
	inner := newScripted(clk)
	inner.transient["example.com/a/v2"] = -1
	r.inner = inner

	got := r.Settle(context.Background(), askRound(r, "example.com/a/v2"), 4)[0]
	if got.Err == nil || errors.Is(got.Err, ports.ErrPathAbsent) {
		t.Fatalf("answer = %+v, want the transient failure kept", got)
	}
	if n := inner.asked("example.com/a/v2"); n != 9 {
		t.Errorf("requests = %d, want 9 (asks at 0s, 30s, ..., 240s)", n)
	}
	if elapsed := clk.now().Sub(got.FirstAsked); elapsed > SettleWindow+10*time.Second {
		t.Errorf("settle ran %v past the first ask, want at most the window plus one request", elapsed)
	}
	line := buf.String()
	if strings.Count(line, "staleness.latest.retries_exhausted") != 1 {
		t.Fatalf("want one exhaustion warning, got %q", line)
	}
	for _, want := range []string{"module.path=example.com/a/v2", "window_ms=240000", "elapsed_ms=250000", "attempts=9"} {
		if !strings.Contains(line, want) {
			t.Errorf("exhaustion warning %q does not contain %q", line, want)
		}
	}
}

// The non-zero control: a definitive 404 on the first ask is one request, is
// not unsettled, and the settle pass adds no wait and says nothing.
func TestSettleLeavesADefinitiveFirstAnswerAlone(t *testing.T) {
	prog := &recordingProgress{}
	r := New(nil, discardLogger(), WithProgress(prog))
	clk := withFakeClock(r, 0)
	inner := newScripted(clk)
	inner.final["example.com/a/v2"] = fmt.Errorf("resolving: %w", ports.ErrPathAbsent)
	r.inner = inner

	round := askRound(r, "example.com/a/v2", "example.com/b/v2")
	got := byPath(r.Settle(context.Background(), round, 4))
	if !errors.Is(got["example.com/a/v2"].Err, ports.ErrPathAbsent) || got["example.com/b/v2"].Info.Version != "v2.1.0" {
		t.Fatalf("answers = %+v", got)
	}
	for _, p := range []string{"example.com/a/v2", "example.com/b/v2"} {
		if n := inner.asked(p); n != 1 {
			t.Errorf("%s requests = %d, want exactly 1", p, n)
		}
	}
	if w := clk.waits(); len(w) != 0 {
		t.Errorf("slept %v with nothing unsettled, want no sleep", w)
	}
	if l := prog.got(); len(l) != 0 {
		t.Errorf("reported %v with nothing unsettled, want nothing", l)
	}
}

// More unsettled paths than the width: they are re-asked together, never more
// than width at once, and the pass reports once.
func TestSettleReasksTogetherWithinTheWidth(t *testing.T) {
	const width = 2
	prog := &recordingProgress{}
	r := New(nil, discardLogger(), WithProgress(prog))
	clk := withFakeClock(r, 0)
	inner := newScripted(clk)
	var inFlight, peak atomic.Int64
	gate := &gatedResolver{inner: inner, inFlight: &inFlight, peak: &peak}
	r.inner = gate

	paths := []string{"example.com/a/v2", "example.com/b/v2", "example.com/c/v2", "example.com/d/v2", "example.com/e/v2"}
	for i, p := range paths {
		inner.transient[p] = i + 1
	}
	got := r.Settle(context.Background(), askRound(r, paths...), width)
	for _, a := range got {
		if a.Err != nil || a.Unsettled {
			t.Errorf("%s = %+v, want answered", a.Path, a)
		}
	}
	if p := peak.Load(); p > width {
		t.Errorf("peak concurrent re-asks = %d, want at most %d", p, width)
	}
	// One wait per pass over the set, not one per path: five paths settle in
	// the five passes the slowest of them needs.
	if w := clk.waits(); len(w) != 5 {
		t.Errorf("waits = %v, want 5", w)
	}
	if l := prog.got(); fmt.Sprint(l) != fmt.Sprint([]string{"settling 5 every 20s for 4m0s"}) {
		t.Errorf("reported %v, want one settle line", l)
	}
}

// A context ended during the wait stops the pass and says so in the error.
func TestSettleStopsOnCancellation(t *testing.T) {
	inner := newScripted(nil)
	inner.transient["example.com/a/v2"] = -1
	r := New(inner, discardLogger())
	r.sleep = func(context.Context, time.Duration) error { return context.Canceled }

	got := r.Settle(context.Background(), askRound(r, "example.com/a/v2"), 4)[0]
	if !errors.Is(got.Err, context.Canceled) {
		t.Errorf("error = %v, want the cancellation in it", got.Err)
	}
	if n := inner.asked("example.com/a/v2"); n != 1 {
		t.Errorf("requests = %d, want 1", n)
	}
}

// gatedResolver records how many requests are in flight at once.
type gatedResolver struct {
	inner          ports.LatestResolver
	inFlight, peak *atomic.Int64
	mu             sync.Mutex
}

func (g *gatedResolver) LatestInfo(ctx context.Context, path string) (ports.LatestInfo, error) {
	n := g.inFlight.Add(1)
	defer g.inFlight.Add(-1)
	g.mu.Lock()
	if n > g.peak.Load() {
		g.peak.Store(n)
	}
	g.mu.Unlock()
	time.Sleep(time.Millisecond) // overlap the pool's goroutines so the bound is exercised
	return g.inner.LatestInfo(ctx, path)
}

// The pass logs its start and its outcome, so a run's log can be split into
// round and settle time.
func TestSettleLogsItsStartAndOutcome(t *testing.T) {
	var buf bytes.Buffer
	r := New(nil, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	clk := withFakeClock(r, 0)
	inner := newScripted(clk)
	inner.transient["example.com/a/v2"] = 1
	inner.transient["example.com/b/v2"] = -1
	r.inner = inner

	r.Settle(context.Background(), askRound(r, "example.com/a/v2", "example.com/b/v2"), 4)
	log := buf.String()
	for _, want := range []string{
		"msg=staleness.latest.settling pending=2 interval_ms=20000 window_ms=240000",
		"msg=staleness.latest.retried module.path=example.com/a/v2 attempts=2 absent=false elapsed_ms=20000",
		"msg=staleness.latest.settled pending=2 unanswered=1 elapsed_ms=240000",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("log %q does not contain %q", log, want)
		}
	}
}

// Paths whose windows close at different times are each warned about once.
func TestSettleWarnsOncePerPathWhenWindowsDiffer(t *testing.T) {
	var buf bytes.Buffer
	r := New(nil, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	clk := withFakeClock(r, 0)
	inner := newScripted(clk)
	inner.transient["example.com/a/v2"] = -1
	inner.transient["example.com/b/v2"] = -1
	r.inner = inner

	round := askRound(r, "example.com/a/v2", "example.com/b/v2")
	round[0].FirstAsked = round[0].FirstAsked.Add(-100 * time.Second)
	r.Settle(context.Background(), round, 4)
	log := buf.String()
	for _, p := range []string{"example.com/a/v2", "example.com/b/v2"} {
		if n := strings.Count(log, "module.path="+p+" "); n != 1 {
			t.Errorf("%s warned %d times, want once: %q", p, n, log)
		}
	}
	if n := inner.asked("example.com/b/v2"); n != 13 {
		t.Errorf("b requests = %d, want 13: a closing early must not end b's window", n)
	}
}
