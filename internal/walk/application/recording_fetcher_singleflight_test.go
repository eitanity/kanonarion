package application

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// blockingFetcher holds every EnsureFetched call at a gate so a test can pin a
// fetch in flight and let further callers arrive while it is still running.
type blockingFetcher struct {
	inner   *recorderFakeFetcher
	entered chan struct{}
	release chan struct{}
}

func (b *blockingFetcher) EnsureFetched(ctx context.Context, c coordinate.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	b.entered <- struct{}{}
	<-b.release
	return b.inner.EnsureFetched(ctx, c)
}

// A coordinate can reach one BFS level twice — a module whose replace target is
// also an independent build-list entry occupies two nodes, so two fetch tasks
// carry the same coordinate and run concurrently. Every overlapping caller must
// share the one fetch: a second fetch would measure and append a second,
// redundant fact record for the same artefact.
func TestRecordingFetcher_OverlappingCallsFetchOnce(t *testing.T) {
	c := coordinatetest.MustNew("example.com/dup", "v1.0.0")
	inner := newRecorderFakeFetcher()
	inner.add(t, c.Path(), c.Version(), false)
	gate := &blockingFetcher{inner: inner, entered: make(chan struct{}), release: make(chan struct{})}
	rec := newRecorderForTest(gate)

	const callers = 8
	results := make([]walkports.ModuleFetchResult, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup

	// Caller 0 becomes the leader; wait until it is inside the inner fetcher so
	// the remaining callers are guaranteed to find the fetch already in flight.
	wg.Add(1)
	go func() {
		defer wg.Done()
		results[0], errs[0] = rec.EnsureFetched(context.Background(), c)
	}()
	<-gate.entered

	for i := 1; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = rec.EnsureFetched(context.Background(), c)
		}()
	}
	close(gate.release)
	wg.Wait()

	if got := inner.callCount(c.Path(), c.Version()); got != 1 {
		t.Errorf("inner EnsureFetched calls = %d, want 1 across %d overlapping callers", got, callers)
	}
	for i := range callers {
		if errs[i] != nil {
			t.Errorf("caller %d: unexpected error: %v", i, errs[i])
		}
		if results[i].Record.ContentHash != results[0].Record.ContentHash {
			t.Errorf("caller %d saw a different record than the leader", i)
		}
	}
}

// A caller that waits on an in-flight fetch must observe that fetch's failure,
// not silently start a second one and report its own.
func TestRecordingFetcher_OverlappingCallsShareFailure(t *testing.T) {
	c := coordinatetest.MustNew("example.com/broken", "v1.0.0")
	sentinel := errors.New("proxy unreachable")
	inner := newRecorderFakeFetcher()
	inner.addError(c.Path(), c.Version(), sentinel)
	gate := &blockingFetcher{inner: inner, entered: make(chan struct{}), release: make(chan struct{})}
	rec := newRecorderForTest(gate)

	var wg sync.WaitGroup
	var leadErr, waitErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, leadErr = rec.EnsureFetched(context.Background(), c)
	}()
	<-gate.entered
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, waitErr = rec.EnsureFetched(context.Background(), c)
	}()
	close(gate.release)
	wg.Wait()

	if got := inner.callCount(c.Path(), c.Version()); got != 1 {
		t.Errorf("inner EnsureFetched calls = %d, want 1", got)
	}
	if !errors.Is(leadErr, sentinel) {
		t.Errorf("leader error = %v, want %v", leadErr, sentinel)
	}
	if !errors.Is(waitErr, sentinel) {
		t.Errorf("waiter error = %v, want %v", waitErr, sentinel)
	}
}

// A cancelled waiter must return the cancellation rather than block until the
// in-flight fetch finishes.
func TestRecordingFetcher_WaiterHonoursContextCancellation(t *testing.T) {
	c := coordinatetest.MustNew("example.com/slow", "v1.0.0")
	inner := newRecorderFakeFetcher()
	inner.add(t, c.Path(), c.Version(), false)
	gate := &blockingFetcher{inner: inner, entered: make(chan struct{}), release: make(chan struct{})}
	rec := newRecorderForTest(gate)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = rec.EnsureFetched(context.Background(), c)
	}()
	<-gate.entered

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := rec.EnsureFetched(ctx, c); !errors.Is(err, context.Canceled) {
		t.Errorf("waiter error = %v, want context.Canceled", err)
	}

	close(gate.release)
	wg.Wait()
}
