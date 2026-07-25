package gosum

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

var testCoord = coordinate.ModuleCoordinate{Path: "golang.org/x/text", Version: "v0.37.0"}

// newServerClient points a Client at a local test server. The key is the real
// sum.golang.org verifier key, so note verification behaves as in production; the
// tests here only exercise paths that fail before any note is verified.
func newServerClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	host := ts.Listener.Addr().String()
	cacheDir := t.TempDir()
	c := &Client{
		server: host,
		newOps: func() *ops {
			return &ops{
				server:   host,
				key:      defaultKey,
				cacheDir: cacheDir,
				httpCli:  ts.Client(),
			}
		},
	}
	return c, ts
}

// TestLookupPolicyReasonsAreNotFailures pins the reason split for the answers the
// database gives without any network error: they must never be retried.
func TestLookupPolicyReasonsAreNotFailures(t *testing.T) {
	t.Setenv("GOPRIVATE", "")
	t.Setenv("GONOSUMCHECK", "")
	t.Setenv("GONOSUMDB", "")

	t.Run("GOSUMDB off", func(t *testing.T) {
		res := (&Client{disabled: true}).Lookup(context.Background(), testCoord)
		assertPolicy(t, res, "GOSUMDB=off")
	})

	t.Run("GOPRIVATE match", func(t *testing.T) {
		t.Setenv("GOPRIVATE", "golang.org/x")
		res := (&Client{}).Lookup(context.Background(), testCoord)
		assertPolicy(t, res, "GONOSUMCHECK/GOPRIVATE")
	})
}

func assertPolicy(t *testing.T, res ports.SumDBResult, reasonSubstr string) {
	t.Helper()
	if res.Available {
		t.Fatalf("result reported available: %+v", res)
	}
	if res.Unavailability != ports.SumDBUnavailabilityPolicy {
		t.Errorf("Unavailability = %q, want %q", res.Unavailability, ports.SumDBUnavailabilityPolicy)
	}
	if res.LookupFailed() {
		t.Error("a policy answer was classified as a lookup failure, so it would be retried and left un-cacheable")
	}
	if res.Err != nil {
		t.Errorf("Err = %v, want nil for a policy answer", res.Err)
	}
	if !strings.Contains(res.Reason, reasonSubstr) {
		t.Errorf("Reason = %q, want it to mention %q", res.Reason, reasonSubstr)
	}
}

// TestLookupTransientStatusIsClassifiableFailure is the guard on the error that
// actually reaches the caller. sumdb.Client.Lookup annotates its error with %v,
// flattening the chain, so the status has to survive by another route or a 503
// would be classified permanent and never retried.
func TestLookupTransientStatusIsClassifiableFailure(t *testing.T) {
	for _, status := range []int{429, 500, 502, 503} {
		t.Run(fmt.Sprintf("HTTP %d", status), func(t *testing.T) {
			c, _ := newServerClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			})

			res := c.Lookup(context.Background(), testCoord)
			if res.Available {
				t.Fatalf("lookup reported available against a failing server: %+v", res)
			}
			if !res.LookupFailed() {
				t.Fatalf("Unavailability = %q, want %q", res.Unavailability, ports.SumDBUnavailabilityFailure)
			}
			if res.Err == nil {
				t.Fatal("Err is nil, so a decorator has nothing to classify")
			}
			if !fetchdomain.IsTransientFetchError(res.Err) {
				t.Errorf("IsTransientFetchError(%v) = false, want true: a %d would never be retried", res.Err, status)
			}
			var pse *fetchdomain.ProxyStatusError
			if !errors.As(res.Err, &pse) {
				t.Fatalf("Err = %v, want an unwrappable *ProxyStatusError", res.Err)
			}
			if pse.StatusCode != status {
				t.Errorf("StatusCode = %d, want %d", pse.StatusCode, status)
			}
			// The human-facing reason still names the status, since it is what the
			// verification detail on the record ends up quoting.
			if !strings.Contains(res.Reason, fmt.Sprint(status)) {
				t.Errorf("Reason = %q, want it to name the status", res.Reason)
			}
		})
	}
}

// TestLookupPermanentStatusIsFailureButNotTransient covers a 4xx: the lookup did
// fail (so the record must not be cached as a verdict about the module), but the
// answer will not change on a retry.
func TestLookupPermanentStatusIsFailureButNotTransient(t *testing.T) {
	c, _ := newServerClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGone)
	})

	res := c.Lookup(context.Background(), testCoord)
	if !res.LookupFailed() {
		t.Fatalf("Unavailability = %q, want %q", res.Unavailability, ports.SumDBUnavailabilityFailure)
	}
	if fetchdomain.IsTransientFetchError(res.Err) {
		t.Errorf("IsTransientFetchError(%v) = true, want false for a 410", res.Err)
	}
}

// TestFailedLookupIsRetriedAgainstTheNetwork is the regression guard for the
// memoisation trap: sumdb.Client caches lookup errors per client instance, keyed
// by module@version, so without discarding the client a retry would replay the
// cached error and never issue a second request. The retry decorator would then
// be a silent no-op in production while every unit test with a fake client passed.
func TestFailedLookupIsRetriedAgainstTheNetwork(t *testing.T) {
	var requests atomic.Int64
	c, _ := newServerClient(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	const lookups = 3
	for range lookups {
		if res := c.Lookup(context.Background(), testCoord); !res.LookupFailed() {
			t.Fatalf("lookup did not report a failure: %+v", res)
		}
	}

	if got := requests.Load(); got < lookups {
		t.Errorf("server saw %d requests for %d lookups of the same coordinate: the failed lookup "+
			"was served from sumdb.Client's in-memory cache, so retrying it cannot reach the network", got, lookups)
	}
}

// TestSecurityErrorIsNotReportedAsTransient keeps a misbehaving-server verdict
// permanent even when a transport failure was observed during the same lookup —
// readTile falls back from the partial tile to the full one, so a 5xx can be seen
// on a fetch that later succeeds. Retrying a tamper signal is the wrong response.
func TestSecurityErrorIsNotReportedAsTransient(t *testing.T) {
	o := &ops{}
	transient := fmt.Errorf("sumdb HTTP 503 for https://example.com/mod/lookup/x: %w",
		&fetchdomain.ProxyStatusError{StatusCode: 503, URL: "https://example.com/mod/lookup/x"})
	_ = o.recordRemoteErr(transient)
	o.SecurityError("tree head inconsistent with previous")

	// The chain is flattened by the time it reaches the adapter, exactly as
	// sumdb.Client.Lookup's %v annotation leaves it.
	flattened := errors.New("golang.org/x/text@v0.37.0: security error: misbehaving server")
	got := classifiableLookupError(flattened, o)
	if fetchdomain.IsTransientFetchError(got) {
		t.Errorf("classifiableLookupError returned %v, which classifies as transient: a security error must never be retried", got)
	}
	if got != flattened { //nolint:errorlint // identity is the assertion: the error must be passed through untouched
		t.Errorf("classifiableLookupError = %v, want the security error unchanged", got)
	}
}

// TestRecoveredTransportErrorIsCleared stops a 5xx that a later fetch satisfied
// from colouring an unrelated verification failure as transient.
func TestRecoveredTransportErrorIsCleared(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Swap(false) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("tile data"))
	}))
	defer ts.Close()

	o := &ops{server: ts.Listener.Addr().String(), cacheDir: t.TempDir(), httpCli: ts.Client()}
	if _, err := o.ReadRemote("/tile/8/0/000"); err == nil {
		t.Fatal("first ReadRemote succeeded, want the injected 503")
	}
	if o.lastTransportError() == nil {
		t.Fatal("transport failure not retained for classification")
	}
	if _, err := o.ReadRemote("/tile/8/0/000"); err != nil {
		t.Fatalf("second ReadRemote: %v", err)
	}
	if got := o.lastTransportError(); got != nil {
		t.Errorf("lastTransportError = %v after a successful fetch, want nil", got)
	}

	inconsistent := errors.New("golang.org/x/text@v0.37.0: downloaded inconsistent tile")
	if fetchdomain.IsTransientFetchError(classifiableLookupError(inconsistent, o)) {
		t.Error("a recovered 503 made an unrelated failure classify as transient")
	}
}

// TestClassifiableLookupErrorWithoutOps guards the nil-ops path: a Client
// constructed without a lookup ever reaching the network must still report the
// error it was given rather than panic.
func TestClassifiableLookupErrorWithoutOps(t *testing.T) {
	err := errors.New("some lookup error")
	if got := classifiableLookupError(err, nil); got != err { //nolint:errorlint // identity is the assertion
		t.Errorf("classifiableLookupError = %v, want %v", got, err)
	}
}

// TestDiscardIgnoresARebuiltClient covers the identity check: a concurrent lookup
// that already rebuilt the client must not have its fresh client dropped by a
// slower goroutine reporting an older failure.
func TestDiscardIgnoresARebuiltClient(t *testing.T) {
	c, _ := newServerClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	stale, _ := c.client()
	c.discard(stale)
	fresh, _ := c.client()
	if fresh == stale {
		t.Fatal("discard did not drop the failed client")
	}
	c.discard(stale)
	current, _ := c.client()
	if current != fresh {
		t.Error("discarding a stale client dropped the rebuilt one")
	}
}
