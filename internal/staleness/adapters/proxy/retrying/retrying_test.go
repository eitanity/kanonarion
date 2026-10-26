package retrying

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	directproxy "code.eitanity.com/kanonarion/internal/adapters/proxy/direct"
	staleproxy "code.eitanity.com/kanonarion/internal/staleness/adapters/proxy"
	"code.eitanity.com/kanonarion/internal/staleness/ports"
)

// The whole path is under test — an httptest proxy, the module-proxy client,
// the port bridge and the decorator — because the fix turns on a condition
// travelling from an HTTP response to a retry decision through two error
// wrappings. A fake resolver returning a hand-built error would pass whether or
// not the client actually produces one.
func resolverFor(t *testing.T, h http.Handler) ports.LatestResolver {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	proxy, err := directproxy.New(srv.URL, true)
	if err != nil {
		t.Fatalf("building proxy client: %v", err)
	}
	// A fake clock: the schedule itself is pinned in backoff_test.go.
	r := New(staleproxy.New(proxy), discardLogger())
	withFakeClock(r, 0)
	return r
}

// An empty 200 is the shape a loaded proxy answers with. It settles nothing, so
// it is asked again — and the answer that comes back is the module's.
func TestEmptyResponseIsRetriedAndThenAnswered(t *testing.T) {
	var calls atomic.Int64
	res := resolverFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"Version":"v2.1.0","Time":"2026-01-02T03:04:05Z"}`) //nolint:errcheck // a failed write is seen by the client under test
	}))

	info, err := res.LatestInfo(context.Background(), "example.com/mod/v2")
	if err != nil {
		t.Fatalf("LatestInfo after one empty response: %v", err)
	}
	if info.Version != "v2.1.0" {
		t.Errorf("version = %q, want v2.1.0", info.Version)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("proxy asked %d times, want 2 (the empty answer, then the real one)", got)
	}
}

// The risk of the change: a definitive absence must not become a slow one. Most
// of a sweep's probe requests end at a 404, and the last one always does.
func TestAbsentPathIsNotRetried(t *testing.T) {
	var calls atomic.Int64
	res := resolverFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "not found: module example.com/mod/v9: no matching versions", http.StatusNotFound)
	}))

	_, err := res.LatestInfo(context.Background(), "example.com/mod/v9")
	if !errors.Is(err, ports.ErrPathAbsent) {
		t.Fatalf("error = %v, want ErrPathAbsent", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("proxy asked %d times for an absent path, want exactly 1", got)
	}
}

// A proxy that answers empty every time is not covered up: the window is spent
// and the failure reported, in the words it has always used.
func TestPersistentEmptyResponseStillFails(t *testing.T) {
	var calls atomic.Int64
	res := resolverFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))

	_, err := res.LatestInfo(context.Background(), "example.com/mod/v2")
	if !errors.Is(err, ports.ErrLookupFailed) {
		t.Fatalf("error = %v, want ErrLookupFailed", err)
	}
	if want := "proxy returned an empty response for example.com/mod/v2@latest"; !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want it to still contain %q", err.Error(), want)
	}
	if got := calls.Load(); got != 13 {
		t.Errorf("proxy asked %d times, want 13 (every 20s over the 240s window)", got)
	}
}

// A 500 is the other transient shape the shared classifier already recognised;
// this pins that the staleness path now gets that behaviour too rather than
// only the empty-body one.
func TestServerErrorIsRetried(t *testing.T) {
	var calls atomic.Int64
	res := resolverFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, `{"Version":"v2.1.0"}`) //nolint:errcheck // a failed write is seen by the client under test
	}))

	if _, err := res.LatestInfo(context.Background(), "example.com/mod/v2"); err != nil {
		t.Fatalf("LatestInfo after one 500: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("proxy asked %d times, want 2", got)
	}
}
