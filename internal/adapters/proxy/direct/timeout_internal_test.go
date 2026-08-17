package direct

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// newTestProxy builds a Proxy against srv with a metadata timeout short enough
// to run in a test. The field is what makes the timeout path reachable without
// waiting the real ten seconds.
func newTestProxy(t *testing.T, base string, timeout time.Duration) *Proxy {
	t.Helper()
	return &Proxy{
		baseURL:         base,
		httpClient:      &http.Client{},
		metadataTimeout: timeout,
		insecure:        true, // httptest serves plain HTTP
	}
}

// neverAnswering serves a handler that blocks until the test ends. It is the
// condition the module proxy presents when it is still resolving an origin
// lookup it has not finished.
func neverAnswering(t *testing.T) *httptest.Server {
	t.Helper()
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-done:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(done)
		srv.Close()
	})
	return srv
}

// TestMetadataTimeout_IsAdapterTimeoutAndTransient is the property the retry
// depends on: a request that outran the adapter's OWN deadline, with the caller
// still waiting, is reported as an adapter timeout and classified transient.
func TestMetadataTimeout_IsAdapterTimeoutAndTransient(t *testing.T) {
	t.Parallel()
	srv := neverAnswering(t)
	p := newTestProxy(t, srv.URL, 50*time.Millisecond)

	_, err := p.LatestInfo(context.Background(), "example.com/mod")
	if err == nil {
		t.Fatal("LatestInfo succeeded against a server that never answers")
	}
	var terr *fetchdomain.ProxyRequestTimeoutError
	if !errors.As(err, &terr) {
		t.Fatalf("error is not a ProxyRequestTimeoutError: %v", err)
	}
	if terr.Timeout != 50*time.Millisecond {
		t.Errorf("Timeout = %v, want 50ms", terr.Timeout)
	}
	if !fetchdomain.IsTransientFetchError(err) {
		t.Errorf("IsTransientFetchError = false, want true: an adapter timeout would never be retried")
	}
	// The guard the classification has to survive: the value still unwraps to
	// the deadline error, so ordering inside the classifier is load-bearing.
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("adapter timeout no longer unwraps to context.DeadlineExceeded")
	}
}

// TestCallerCancellation_IsNotAdapterTimeout is the non-zero control for the
// change: the caller giving up must stay non-transient, which is the property
// the classifier's context guard exists to protect.
func TestCallerCancellation_IsNotAdapterTimeout(t *testing.T) {
	t.Parallel()
	srv := neverAnswering(t)
	p := newTestProxy(t, srv.URL, time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, err := p.LatestInfo(ctx, "example.com/mod")
	if err == nil {
		t.Fatal("LatestInfo succeeded after the caller cancelled")
	}
	var terr *fetchdomain.ProxyRequestTimeoutError
	if errors.As(err, &terr) {
		t.Fatalf("caller cancellation reported as an adapter timeout: %v", err)
	}
	if fetchdomain.IsTransientFetchError(err) {
		t.Errorf("IsTransientFetchError = true for a caller cancellation, want false")
	}
}

// TestCallerDeadline_IsNotAdapterTimeout covers the other half of the control:
// the caller's own deadline expiring is still the caller giving up, even though
// it produces the identical error value the adapter's timeout does.
func TestCallerDeadline_IsNotAdapterTimeout(t *testing.T) {
	t.Parallel()
	srv := neverAnswering(t)
	p := newTestProxy(t, srv.URL, time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := p.LatestInfo(ctx, "example.com/mod")
	if err == nil {
		t.Fatal("LatestInfo succeeded after the caller's deadline passed")
	}
	var terr *fetchdomain.ProxyRequestTimeoutError
	if errors.As(err, &terr) {
		t.Fatalf("caller deadline reported as an adapter timeout: %v", err)
	}
	if fetchdomain.IsTransientFetchError(err) {
		t.Errorf("IsTransientFetchError = true for an expired caller deadline, want false")
	}
}

// TestDefinitiveAnswerUnaffectedByTimeout is the other non-zero control: the
// timeout must cost nothing on the answering path. A 404 is the commonest
// result of the major probe and must still come back on the first attempt.
func TestDefinitiveAnswerUnaffectedByTimeout(t *testing.T) {
	t.Parallel()
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.NotFound(w, r)
	}))
	defer srv.Close()
	p := newTestProxy(t, srv.URL, time.Minute)

	start := time.Now()
	_, err := p.LatestInfo(context.Background(), "example.com/mod/v2")
	elapsed := time.Since(start)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("LatestInfo error = %v, want ErrNotFound", err)
	}
	if calls != 1 {
		t.Errorf("server saw %d requests, want 1", calls)
	}
	if fetchdomain.IsTransientFetchError(err) {
		t.Error("a 404 classified transient: the probe's ordinary negative would be retried")
	}
	if elapsed > time.Second {
		t.Errorf("a definitive 404 took %v; the timeout must not add latency to an answered probe", elapsed)
	}
}

// TestZipDownloadKeepsTheLongerTimeout pins the split. A module zip is up to
// 500 MB and http.Client's deadline covers the body, so applying the metadata
// timeout to it would refuse large modules on slow links.
func TestZipDownloadKeepsTheLongerTimeout(t *testing.T) {
	t.Parallel()
	if metadataTimeout >= downloadTimeout {
		t.Fatalf("metadataTimeout %v is not shorter than downloadTimeout %v", metadataTimeout, downloadTimeout)
	}
	if downloadTimeout != 60*time.Second {
		t.Errorf("downloadTimeout = %v, want the 60s this adapter has always given a transfer", downloadTimeout)
	}
}
