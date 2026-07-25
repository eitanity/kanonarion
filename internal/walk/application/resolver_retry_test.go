package application_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/walk/adapters/fetcher/retrying"
	"github.com/eitanity/kanonarion/internal/walk/adapters/gomod/xmod"
	"github.com/eitanity/kanonarion/internal/walk/application"
	domain3 "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// flakyFetcher fails the first failures calls for one coordinate and then
// delegates to the wrapped fetcher — the "fails N times then succeeds" seam.
type flakyFetcher struct {
	inner    walkports.ModuleFetcher
	path     string
	err      error
	failures int

	mu    sync.Mutex
	calls int
}

func (f *flakyFetcher) EnsureFetched(ctx context.Context, c coordinate.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	if c.Path == f.path {
		f.mu.Lock()
		f.calls++
		remaining := f.failures
		f.failures--
		f.mu.Unlock()
		if remaining > 0 {
			return walkports.ModuleFetchResult{}, f.err
		}
	}
	return f.inner.EnsureFetched(ctx, c) //nolint:wrapcheck // test fake
}

// retryingResolver wires a resolver whose fetcher fails the first failures
// attempts for example.com/flaky with err, behind the retry decorator.
func retryingResolver(t testing.TB, failures int, err error) (*application.GraphResolver, *flakyFetcher) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add(t, "example.com/target", "v1.0.0", `module example.com/target

go 1.21

require example.com/flaky v1.0.0
`, blobs)
	fetcher.add(t, "example.com/flaky", "v1.0.0", "module example.com/flaky\n\ngo 1.21\n", blobs)

	flaky := &flakyFetcher{inner: fetcher, path: "example.com/flaky", err: err, failures: failures}
	// Zero base delay keeps the backoff schedule out of the test's runtime; the
	// retry decision itself is what is under test here.
	retrier := retrying.New(flaky, slog.New(slog.NewTextHandler(io.Discard, nil)), retrying.WithBaseDelay(0))
	r := application.NewGraphResolver(
		xmod.New(), retrier, blobs, fixedClock{fixedNow}, "",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	return r, flaky
}

// A module whose download is reset twice by the proxy must resolve normally:
// the transient flake is retried away instead of degrading a real dependency
// to a fetch-failure node for the whole walk.
func TestResolve_TransientFetchErrorIsRetriedNotRecorded(t *testing.T) {
	streamReset := errors.New("inner fetcher: fetching module: proxy download: reading zip: " +
		"stream error: stream ID 587; INTERNAL_ERROR; received from peer")
	r, flaky := retryingResolver(t, 2, streamReset)

	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if g.Partial {
		t.Errorf("graph is partial (%s); a retried transient error must not degrade the walk", g.PartialReason)
	}

	node := findNode(t, g.Nodes, "example.com/flaky")
	if node.ResolutionSource == domain3.ResolutionFetchFailed {
		t.Errorf("flaky node source = %s, want a resolved source", node.ResolutionSource)
	}
	if node.ErrorDetail != "" {
		t.Errorf("flaky node carries ErrorDetail %q, want none", node.ErrorDetail)
	}
	if flaky.calls != 3 {
		t.Errorf("fetcher called %d times for the flaky module, want 3 (two resets, then success)", flaky.calls)
	}
}

// The control: a permanent error still fails on the first attempt and is
// recorded exactly as before, so retries cannot mask a genuine fetch failure.
func TestResolve_PermanentFetchErrorIsNotRetried(t *testing.T) {
	r, flaky := retryingResolver(t, 2, errors.New("inner fetcher: fetching module: checksum mismatch"))

	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !g.Partial {
		t.Error("graph should be partial when a dep fails permanently")
	}

	node := findNode(t, g.Nodes, "example.com/flaky")
	if node.ResolutionSource != domain3.ResolutionFetchFailed {
		t.Errorf("flaky node source = %s, want fetch_failed", node.ResolutionSource)
	}
	if node.ErrorDetail == "" {
		t.Error("fetch-failed node should carry an ErrorDetail")
	}
	if flaky.calls != 1 {
		t.Errorf("fetcher called %d times, want 1 (no retry for a permanent error)", flaky.calls)
	}
}
