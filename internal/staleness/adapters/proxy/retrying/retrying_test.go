package retrying_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	directproxy "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	staleproxy "github.com/eitanity/kanonarion/internal/staleness/adapters/proxy"
	"github.com/eitanity/kanonarion/internal/staleness/adapters/proxy/retrying"
	"github.com/eitanity/kanonarion/internal/staleness/ports"
)

// The whole path is under test — an httptest proxy, the module-proxy client,
// the port bridge and the decorator — because the fix turns on a condition
// travelling from an HTTP response to a retry decision through two error
// wrappings. A fake resolver returning a hand-built error would pass whether or
// not the client actually produces one.
func resolverFor(t *testing.T, h http.Handler, opts ...retrying.Option) ports.LatestResolver {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	proxy, err := directproxy.New(srv.URL, true)
	if err != nil {
		t.Fatalf("building proxy client: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Zero backoff: the schedule itself is measured in backoff_test.go, and a
	// test that waits its own real 600ms is a test people stop running.
	opts = append([]retrying.Option{retrying.WithBaseDelay(0)}, opts...)
	return retrying.New(staleproxy.New(proxy), logger, opts...)
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
		_, _ = io.WriteString(w, `{"Version":"v2.1.0","Time":"2026-01-02T03:04:05Z"}`)
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

// A proxy that answers empty every time is not covered up: the budget is spent
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
	if got := calls.Load(); got != 3 {
		t.Errorf("proxy asked %d times, want the 3-attempt budget", got)
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
		_, _ = io.WriteString(w, `{"Version":"v2.1.0"}`)
	}))

	if _, err := res.LatestInfo(context.Background(), "example.com/mod/v2"); err != nil {
		t.Fatalf("LatestInfo after one 500: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("proxy asked %d times, want 2", got)
	}
}
