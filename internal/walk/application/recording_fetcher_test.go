package application

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// recorderFakeFetcher is a controllable inner fetcher used only by
// recording_fetcher_test. Tests in this file live in package application so
// they can reach into the recorder's outcomes directly (instead of going
// through Walker.Walk).
type recorderFakeFetcher struct {
	mu        sync.Mutex
	records   map[string]fetchdomain.FactRecord
	fromCache map[string]bool
	errors    map[string]error
	panicOn   map[string]bool
	calls     map[string]int
}

func newRecorderFakeFetcher() *recorderFakeFetcher {
	return &recorderFakeFetcher{
		records:   make(map[string]fetchdomain.FactRecord),
		fromCache: make(map[string]bool),
		errors:    make(map[string]error),
		panicOn:   make(map[string]bool),
		calls:     make(map[string]int),
	}
}

func (f *recorderFakeFetcher) add(path, version string, fromCache bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := path + "@" + version
	f.records[k] = fetchdomain.FactRecord{ModulePath: path, ModuleVersion: version}
	f.fromCache[k] = fromCache
}

func (f *recorderFakeFetcher) addError(path, version string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errors[path+"@"+version] = err
}

func (f *recorderFakeFetcher) addPanic(path, version string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.panicOn[path+"@"+version] = true
}

func (f *recorderFakeFetcher) callCount(path, version string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[path+"@"+version]
}

func (f *recorderFakeFetcher) EnsureFetched(_ context.Context, c fetchdomain.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	k := c.Path + "@" + c.Version
	f.mu.Lock()
	f.calls[k]++
	shouldPanic := f.panicOn[k]
	err := f.errors[k]
	rec, hasRec := f.records[k]
	cached := f.fromCache[k]
	f.mu.Unlock()
	if shouldPanic {
		panic("injected: " + k)
	}
	if err != nil {
		return walkports.ModuleFetchResult{}, err
	}
	if hasRec {
		return walkports.ModuleFetchResult{Record: rec, FromCache: cached}, nil
	}
	return walkports.ModuleFetchResult{}, errors.New("no record")
}

// fakeLap implements fetchports.Lap with a configurable duration.
type fakeLap struct{ d time.Duration }

func (l fakeLap) Elapsed() time.Duration { return l.d }

// fakeStopwatch2 implements fetchports.Stopwatch using a counter so each
// call returns a deterministic, distinct duration. Used to verify that
// duration_ms is captured per-coord and not zeroed.
type fakeStopwatch2 struct {
	mu      sync.Mutex
	counter int64
}

func (s *fakeStopwatch2) Start() fetchports.Lap {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counter++
	return fakeLap{d: time.Duration(s.counter) * time.Millisecond}
}

func newRecorderForTest(inner walkports.ModuleFetcher) *recordingFetcher {
	return newRecorderForTestWithProgress(inner, nil)
}

func newRecorderForTestWithProgress(inner walkports.ModuleFetcher, progress walkports.ProgressReporter) *recordingFetcher {
	return newRecordingFetcher(
		inner,
		&fakeStopwatch2{},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		fetchdomain.ModuleCoordinate{Path: "example.com/target", Version: "v1.0.0"},
		progress,
	)
}

func rcoord(path, version string) fetchdomain.ModuleCoordinate {
	return fetchdomain.ModuleCoordinate{Path: path, Version: version}
}

func TestRecordingFetcher_RecordsFirstCallOutcome(t *testing.T) {
	inner := newRecorderFakeFetcher()
	inner.add("example.com/a", "v1.0.0", false)
	r := newRecorderForTest(inner)

	fr, err := r.EnsureFetched(context.Background(), rcoord("example.com/a", "v1.0.0"))
	if err != nil {
		t.Fatalf("EnsureFetched: %v", err)
	}
	if fr.FromCache {
		t.Error("first call FromCache = true, want false")
	}

	out, ok := r.outcomeFor(rcoord("example.com/a", "v1.0.0"))
	if !ok {
		t.Fatal("outcome not recorded")
	}
	if out.fromCache {
		t.Error("recorded fromCache = true, want false")
	}
	if out.durationMs == 0 {
		t.Error("recorded durationMs = 0, want >0")
	}
	if out.err != nil {
		t.Errorf("recorded err = %v, want nil", out.err)
	}
}

func TestRecordingFetcher_MemoisesSubsequentCalls(t *testing.T) {
	inner := newRecorderFakeFetcher()
	// Set fromCache=true so we can detect whether the inner fetcher was
	// hit again on the second call (it must not be — the recorder should
	// return the first-call outcome).
	inner.add("example.com/a", "v1.0.0", false)
	r := newRecorderForTest(inner)

	for range 5 {
		fr, err := r.EnsureFetched(context.Background(), rcoord("example.com/a", "v1.0.0"))
		if err != nil {
			t.Fatalf("EnsureFetched: %v", err)
		}
		if fr.FromCache {
			t.Error("subsequent call FromCache = true (recorded fromCache was false)")
		}
	}
	if got := inner.callCount("example.com/a", "v1.0.0"); got != 1 {
		t.Errorf("inner fetcher called %d times, want 1 (recorder must memoise)", got)
	}
}

func TestRecordingFetcher_RecordsError(t *testing.T) {
	inner := newRecorderFakeFetcher()
	inner.addError("example.com/x", "v1.0.0", errors.New("boom"))
	r := newRecorderForTest(inner)

	_, err := r.EnsureFetched(context.Background(), rcoord("example.com/x", "v1.0.0"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	out, ok := r.outcomeFor(rcoord("example.com/x", "v1.0.0"))
	if !ok {
		t.Fatal("outcome not recorded")
	}
	if out.err == nil {
		t.Error("recorded err = nil, want non-nil")
	}
	if out.panicked {
		t.Error("recorded panicked = true, want false (plain error, not panic)")
	}
}

func TestRecordingFetcher_RecoversFromPanic(t *testing.T) {
	inner := newRecorderFakeFetcher()
	inner.addPanic("example.com/p", "v1.0.0")
	r := newRecorderForTest(inner)

	_, err := r.EnsureFetched(context.Background(), rcoord("example.com/p", "v1.0.0"))
	if err == nil {
		t.Fatal("expected error from panic recovery, got nil")
	}
	var pe *panicError
	if !errors.As(err, &pe) {
		t.Errorf("err type = %T, want *panicError", err)
	}

	out, ok := r.outcomeFor(rcoord("example.com/p", "v1.0.0"))
	if !ok {
		t.Fatal("outcome not recorded")
	}
	if !out.panicked {
		t.Error("recorded panicked = false, want true")
	}
}

func TestRecordingFetcher_PerCoordIsolation(t *testing.T) {
	inner := newRecorderFakeFetcher()
	inner.add("example.com/a", "v1.0.0", false)
	inner.add("example.com/b", "v1.0.0", true) // pre-cached upstream
	r := newRecorderForTest(inner)

	ctx := context.Background()
	if _, err := r.EnsureFetched(ctx, rcoord("example.com/a", "v1.0.0")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.EnsureFetched(ctx, rcoord("example.com/b", "v1.0.0")); err != nil {
		t.Fatal(err)
	}

	a, _ := r.outcomeFor(rcoord("example.com/a", "v1.0.0"))
	b, _ := r.outcomeFor(rcoord("example.com/b", "v1.0.0"))
	if a.fromCache {
		t.Error("a fromCache = true, want false")
	}
	if !b.fromCache {
		t.Error("b fromCache = false, want true")
	}
}

func TestRecordingFetcher_ConcurrentSameCoord(t *testing.T) {
	inner := newRecorderFakeFetcher()
	inner.add("example.com/a", "v1.0.0", false)
	r := newRecorderForTest(inner)

	const n = 32
	var wg sync.WaitGroup
	var errCount atomic.Int32
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.EnsureFetched(context.Background(), rcoord("example.com/a", "v1.0.0")); err != nil {
				errCount.Add(1)
			}
		}()
	}
	wg.Wait()
	if errCount.Load() != 0 {
		t.Errorf("got %d errors, want 0", errCount.Load())
	}
	// Concurrent first calls may race past the memoisation check, so we
	// allow more than one inner call but never more than n.
	got := inner.callCount("example.com/a", "v1.0.0")
	if got < 1 || got > n {
		t.Errorf("inner call count = %d, want in [1,%d]", got, n)
	}
}

func TestRecordingFetcher_OutcomeForUnknownCoord(t *testing.T) {
	inner := newRecorderFakeFetcher()
	r := newRecorderForTest(inner)
	if _, ok := r.outcomeFor(rcoord("example.com/unknown", "v1.0.0")); ok {
		t.Error("outcomeFor returned ok=true for never-fetched coord")
	}
}

// fakeProgress records the running totals passed to Advance.
type fakeProgress struct {
	mu    sync.Mutex
	dones []int
}

func (f *fakeProgress) Advance(done int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dones = append(f.dones, done)
}

func (f *fakeProgress) snapshot() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.dones...)
}

func TestRecordingFetcher_ProgressAdvancesOncePerDistinctCoord(t *testing.T) {
	inner := newRecorderFakeFetcher()
	inner.add("example.com/a", "v1.0.0", false)
	inner.add("example.com/b", "v1.0.0", true)
	prog := &fakeProgress{}
	r := newRecorderForTestWithProgress(inner, prog)
	ctx := context.Background()

	_, _ = r.EnsureFetched(ctx, rcoord("example.com/a", "v1.0.0"))
	_, _ = r.EnsureFetched(ctx, rcoord("example.com/b", "v1.0.0"))
	// Repeat of a: the recorder returns the memoised outcome and must not
	// report progress again.
	_, _ = r.EnsureFetched(ctx, rcoord("example.com/a", "v1.0.0"))

	got := prog.snapshot()
	if len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Errorf("Advance running totals = %v, want [1 2]", got)
	}
}

func TestRecordingFetcher_NilProgressIsSafe(t *testing.T) {
	inner := newRecorderFakeFetcher()
	inner.add("example.com/a", "v1.0.0", false)
	r := newRecorderForTestWithProgress(inner, nil)
	if _, err := r.EnsureFetched(context.Background(), rcoord("example.com/a", "v1.0.0")); err != nil {
		t.Fatalf("EnsureFetched with nil progress: %v", err)
	}
}
