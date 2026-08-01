package retrying

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

var testCoord = coordinatetest.MustNew("golang.org/x/text", "v0.37.0")

// scriptedFetcher fails with errs[i] on attempt i+1 and succeeds once the
// script runs out — the "fails N times then succeeds" seam.
type scriptedFetcher struct {
	errs  []error
	calls int
	// forced records the last WithForce argument; nil when WithForce is absent.
	forced *bool
}

func (f *scriptedFetcher) EnsureFetched(context.Context, coordinate.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	f.calls++
	if f.calls <= len(f.errs) {
		return walkports.ModuleFetchResult{}, f.errs[f.calls-1]
	}
	return walkports.ModuleFetchResult{FromCache: true}, nil
}

// forcingScriptedFetcher is a scriptedFetcher that also implements the walker's
// force-mode interface.
type forcingScriptedFetcher struct {
	*scriptedFetcher
}

func (f *forcingScriptedFetcher) WithForce(force bool) walkports.ModuleFetcher {
	f.forced = &force
	return f
}

func transientErr() error {
	return fmt.Errorf("inner fetcher: fetching module: proxy download: reading zip: %w",
		errors.New("stream error: stream ID 587; INTERNAL_ERROR; received from peer"))
}

func permanentErr() error {
	return errors.New("inner fetcher: fetching module: checksum mismatch")
}

// newTestFetcher wraps inner with the backoff seams replaced: no real waiting,
// no randomness, and every requested delay recorded.
func newTestFetcher(t *testing.T, inner walkports.ModuleFetcher, opts ...Option) (walkports.ModuleFetcher, *[]time.Duration, *bytes.Buffer) {
	t.Helper()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	var delays []time.Duration
	f := New(inner, logger, opts...)
	base := baseOf(f)
	base.jitter = func(d time.Duration) time.Duration { return d }
	base.sleep = func(context.Context, time.Duration) error { return nil }
	origSleep := base.sleep
	base.sleep = func(ctx context.Context, d time.Duration) error {
		delays = append(delays, d)
		return origSleep(ctx, d)
	}
	return f, &delays, &logBuf
}

// baseOf reaches the embedded *Fetcher regardless of which variant New returned.
func baseOf(f walkports.ModuleFetcher) *Fetcher {
	switch v := f.(type) {
	case *forcingFetcher:
		return v.Fetcher
	case *vcsFetcher:
		return v.Fetcher
	case *forcingVCSFetcher:
		return v.Fetcher
	case *Fetcher:
		return v
	default:
		panic("unexpected fetcher type")
	}
}

func TestSuccessOnFirstAttemptDoesNotRetry(t *testing.T) {
	inner := &scriptedFetcher{}
	f, delays, logBuf := newTestFetcher(t, inner)

	res, err := f.EnsureFetched(context.Background(), testCoord)
	if err != nil {
		t.Fatalf("EnsureFetched: %v", err)
	}
	if !res.FromCache {
		t.Error("result not passed through from the wrapped fetcher")
	}
	if inner.calls != 1 {
		t.Errorf("inner called %d times, want 1", inner.calls)
	}
	if len(*delays) != 0 {
		t.Errorf("backoff waits = %v, want none", *delays)
	}
	if strings.Contains(logBuf.String(), "walk.fetch.retry") {
		t.Error("retry logged on a successful first attempt")
	}
}

func TestTransientErrorRetriesThenSucceeds(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"http2 stream reset", transientErr()},
		{"connection reset", errors.New("proxy download: read tcp: connection reset by peer")},
		{"unexpected EOF", fmt.Errorf("proxy download: reading zip: %w", io.ErrUnexpectedEOF)},
		{"proxy 500", fmt.Errorf("proxy info: %w", &fetchdomain.ProxyStatusError{StatusCode: 500, URL: "https://proxy.golang.org"})},
		{"proxy 429", fmt.Errorf("proxy info: %w", &fetchdomain.ProxyStatusError{StatusCode: 429, URL: "https://proxy.golang.org"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inner := &scriptedFetcher{errs: []error{tc.err}}
			f, delays, logBuf := newTestFetcher(t, inner)

			if _, err := f.EnsureFetched(context.Background(), testCoord); err != nil {
				t.Fatalf("EnsureFetched: %v, want success after one retry", err)
			}
			if inner.calls != 2 {
				t.Errorf("inner called %d times, want 2", inner.calls)
			}
			if want := []time.Duration{defaultBaseDelay}; len(*delays) != 1 || (*delays)[0] != want[0] {
				t.Errorf("backoff waits = %v, want %v", *delays, want)
			}
			logged := logBuf.String()
			if !strings.Contains(logged, "walk.fetch.retry") ||
				!strings.Contains(logged, "module.path=golang.org/x/text") ||
				!strings.Contains(logged, "attempt=1") {
				t.Errorf("retry not logged with module and attempt: %s", logged)
			}
			if !strings.Contains(logged, "level=DEBUG msg=walk.fetch.retry ") {
				t.Errorf("per-attempt retry logged above debug level: %s", logged)
			}
			// The success needed a retry, so the inflated fetch duration the walker
			// reports at INFO must be explicable at INFO too.
			if !strings.Contains(logged, "level=INFO msg=walk.fetch.retried") ||
				!strings.Contains(logged, "attempts=2") {
				t.Errorf("retried success not summarised at info level: %s", logged)
			}
			if strings.Contains(logged, "level=WARN") {
				t.Errorf("a recovered flake must not warn: %s", logged)
			}
		})
	}
}

func TestTransientErrorRetriesUntilBudgetExhausted(t *testing.T) {
	final := transientErr()
	inner := &scriptedFetcher{errs: []error{transientErr(), transientErr(), final}}
	f, delays, logBuf := newTestFetcher(t, inner)

	_, err := f.EnsureFetched(context.Background(), testCoord)
	if err == nil {
		t.Fatal("EnsureFetched succeeded, want the final transient error")
	}
	if err.Error() != final.Error() {
		t.Errorf("error = %q, want the unmodified final error %q", err, final)
	}
	if inner.calls != defaultAttempts {
		t.Errorf("inner called %d times, want %d", inner.calls, defaultAttempts)
	}
	// Exponential: 200ms then 400ms, with the third attempt failing outright.
	want := []time.Duration{defaultBaseDelay, 2 * defaultBaseDelay}
	if fmt.Sprint(*delays) != fmt.Sprint(want) {
		t.Errorf("backoff schedule = %v, want %v", *delays, want)
	}

	// The walk.fetch.failed WARN that follows carries only the last error. Without
	// this line an exhausted budget reads exactly like a first-attempt failure.
	logged := logBuf.String()
	if !strings.Contains(logged, "level=WARN msg=walk.fetch.retries_exhausted") {
		t.Errorf("exhausted budget not warned: %s", logged)
	}
	for _, want := range []string{
		"module.path=golang.org/x/text", "module.version=v0.37.0", "attempts=3", "backoff_total_ms=600",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("exhaustion warning missing %q: %s", want, logged)
		}
	}
	if strings.Contains(logged, "walk.fetch.retried") {
		t.Errorf("a failed fetch must not be summarised as a retried success: %s", logged)
	}
}

func TestNonTransientErrorFailsWithoutRetry(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"checksum mismatch", permanentErr()},
		{"not found", errors.New("inner fetcher: fetching module: proxy info: not found")},
		{"proxy 404 gone", fmt.Errorf("proxy info: %w", &fetchdomain.ProxyStatusError{StatusCode: 410, URL: "u"})},
		{"context canceled", fmt.Errorf("proxy download: %w", context.Canceled)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inner := &scriptedFetcher{errs: []error{tc.err, tc.err, tc.err}}
			f, delays, logBuf := newTestFetcher(t, inner)

			if _, err := f.EnsureFetched(context.Background(), testCoord); !errors.Is(err, tc.err) {
				t.Fatalf("error = %v, want %v", err, tc.err)
			}
			if inner.calls != 1 {
				t.Errorf("inner called %d times, want 1 (no retry)", inner.calls)
			}
			if len(*delays) != 0 {
				t.Errorf("backoff waits = %v, want none", *delays)
			}
			logged := logBuf.String()
			if strings.Contains(logged, "walk.fetch.retry") {
				t.Error("retry logged for a non-transient error")
			}
			// A permanent error is the module's real answer: it was never retried,
			// so it must not be reported as an exhausted retry budget either.
			if strings.Contains(logged, "walk.fetch.retries_exhausted") {
				t.Errorf("non-transient failure reported as exhausted retries: %s", logged)
			}
		})
	}
}

func TestCancellationDuringBackoffStopsRetrying(t *testing.T) {
	transient := transientErr()
	inner := &scriptedFetcher{errs: []error{transient, transient, transient}}
	f, _, logBuf := newTestFetcher(t, inner)
	baseOf(f).sleep = func(context.Context, time.Duration) error { return context.Canceled }

	_, err := f.EnsureFetched(context.Background(), testCoord)
	if err == nil || err.Error() != transient.Error() {
		t.Fatalf("error = %v, want the fetch error %v", err, transient)
	}
	if inner.calls != 1 {
		t.Errorf("inner called %d times, want 1 (backoff was cut short)", inner.calls)
	}

	// A deliberate stop is its own outcome: it neither exhausted the budget nor
	// succeeded, and must not be reported as either.
	logged := logBuf.String()
	if !strings.Contains(logged, "level=DEBUG msg=walk.fetch.retry.aborted") ||
		!strings.Contains(logged, `reason="context canceled"`) {
		t.Errorf("aborted backoff not logged with its reason: %s", logged)
	}
	if strings.Contains(logged, "walk.fetch.retries_exhausted") {
		t.Errorf("cancelled backoff reported as exhausted retries: %s", logged)
	}
}

func TestAttemptsAndBaseDelayOptions(t *testing.T) {
	inner := &scriptedFetcher{errs: []error{transientErr(), transientErr(), transientErr(), transientErr()}}
	f, delays, _ := newTestFetcher(t, inner, WithAttempts(5), WithBaseDelay(10*time.Millisecond))

	if _, err := f.EnsureFetched(context.Background(), testCoord); err != nil {
		t.Fatalf("EnsureFetched: %v, want success on the fifth attempt", err)
	}
	if inner.calls != 5 {
		t.Errorf("inner called %d times, want 5", inner.calls)
	}
	want := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond, 80 * time.Millisecond}
	if fmt.Sprint(*delays) != fmt.Sprint(want) {
		t.Errorf("backoff schedule = %v, want %v", *delays, want)
	}
}

func TestInvalidOptionsAreIgnored(t *testing.T) {
	f := baseOf(New(&scriptedFetcher{}, slog.New(slog.DiscardHandler),
		WithAttempts(0), WithBaseDelay(-time.Second)))
	if f.attempts != defaultAttempts {
		t.Errorf("attempts = %d, want the default %d", f.attempts, defaultAttempts)
	}
	if f.baseDelay != defaultBaseDelay {
		t.Errorf("baseDelay = %v, want the default %v", f.baseDelay, defaultBaseDelay)
	}
}

// The walker decides whether --force is honoured by type-asserting its fetcher,
// so the decorator must advertise force mode exactly when the wrapped fetcher
// has it — never on top of a fetcher that cannot force.
func TestForceCapabilityMirrorsWrappedFetcher(t *testing.T) {
	type forceCapableCheck interface {
		WithForce(bool) walkports.ModuleFetcher
	}

	plain := New(&scriptedFetcher{}, slog.New(slog.DiscardHandler))
	if _, ok := plain.(forceCapableCheck); ok {
		t.Error("decorator advertises force mode over a fetcher that lacks it")
	}

	inner := &forcingScriptedFetcher{scriptedFetcher: &scriptedFetcher{errs: []error{transientErr()}}}
	wrapped := New(inner, slog.New(slog.DiscardHandler))
	fc, ok := wrapped.(forceCapableCheck)
	if !ok {
		t.Fatal("decorator dropped the wrapped fetcher's force-mode capability")
	}

	forced := fc.WithForce(true)
	if inner.forced == nil || !*inner.forced {
		t.Error("WithForce(true) not passed through to the wrapped fetcher")
	}
	// Retries must still apply to the force-mode clone.
	base := baseOf(forced)
	base.sleep = func(context.Context, time.Duration) error { return nil }
	if _, err := forced.EnsureFetched(context.Background(), testCoord); err != nil {
		t.Fatalf("EnsureFetched on the force clone: %v", err)
	}
	if inner.calls != 2 {
		t.Errorf("inner called %d times through the force clone, want 2", inner.calls)
	}
	if baseOf(wrapped).attempts != defaultAttempts {
		t.Error("WithForce mutated the original decorator")
	}
}

// A forcingFetcher whose inner lost the capability (only reachable by
// constructing one directly) returns itself rather than panicking.
func TestForceOverNonForcingInnerReturnsSelf(t *testing.T) {
	f := &forcingFetcher{Fetcher: baseOf(New(&scriptedFetcher{}, slog.New(slog.DiscardHandler)))}
	if got := f.WithForce(true); got != walkports.ModuleFetcher(f) {
		t.Error("WithForce over a non-forcing inner did not return the decorator unchanged")
	}
}

// A large attempt budget must saturate the backoff, not overflow it: a negative
// interval would collapse to a zero wait and spin against the proxy.
func TestBackoffSaturatesInsteadOfOverflowing(t *testing.T) {
	f := baseOf(New(&scriptedFetcher{}, slog.New(slog.DiscardHandler)))

	prev := time.Duration(0)
	for attempt := 1; attempt <= 200; attempt++ {
		got := f.backoffFor(attempt)
		if got <= 0 {
			t.Fatalf("backoffFor(%d) = %v, want a positive interval", attempt, got)
		}
		if got > maxBackoff {
			t.Fatalf("backoffFor(%d) = %v, want at most %v", attempt, got, maxBackoff)
		}
		if got < prev {
			t.Fatalf("backoffFor(%d) = %v, want at least the previous %v", attempt, got, prev)
		}
		prev = got
	}
	if prev != maxBackoff {
		t.Errorf("backoff saturated at %v, want %v", prev, maxBackoff)
	}

	// A zero base delay (used by tests to skip the wait) must stay zero rather
	// than being pulled up to the cap.
	zero := baseOf(New(&scriptedFetcher{}, slog.New(slog.DiscardHandler), WithBaseDelay(0)))
	if got := zero.backoffFor(10); got != 0 {
		t.Errorf("backoffFor with a zero base = %v, want 0", got)
	}
}

func TestFullJitterStaysWithinHalfOfTheInterval(t *testing.T) {
	if got := fullJitter(0); got != 0 {
		t.Errorf("fullJitter(0) = %v, want 0", got)
	}
	if got := fullJitter(-time.Second); got != 0 {
		t.Errorf("fullJitter(negative) = %v, want 0", got)
	}
	const d = 200 * time.Millisecond
	for range 200 {
		got := fullJitter(d)
		if got < d/2 || got > d {
			t.Fatalf("fullJitter(%v) = %v, want within [%v, %v]", d, got, d/2, d)
		}
	}
}

func TestSleepCtx(t *testing.T) {
	if err := sleepCtx(context.Background(), time.Millisecond); err != nil {
		t.Errorf("sleepCtx returned %v, want nil after the timer fired", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepCtx(cancelled, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("sleepCtx on a cancelled context = %v, want context.Canceled", err)
	}
	if err := sleepCtx(cancelled, 0); !errors.Is(err, context.Canceled) {
		t.Errorf("sleepCtx(0) on a cancelled context = %v, want context.Canceled", err)
	}
	if err := sleepCtx(context.Background(), 0); err != nil {
		t.Errorf("sleepCtx(0) = %v, want nil", err)
	}
}

// The default backoff must be real: a decorator built without test seams waits
// between attempts rather than hammering the proxy.
func TestDefaultSeamsWait(t *testing.T) {
	inner := &scriptedFetcher{errs: []error{transientErr()}}
	f := New(inner, slog.New(slog.DiscardHandler), WithBaseDelay(20*time.Millisecond))

	start := time.Now()
	if _, err := f.EnsureFetched(context.Background(), testCoord); err != nil {
		t.Fatalf("EnsureFetched: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 10*time.Millisecond {
		t.Errorf("elapsed %v, want at least the jittered floor of 10ms", elapsed)
	}
}

// vcsScriptedFetcher is a scriptedFetcher that also accepts a per-walk VCS
// forge allowlist.
type vcsScriptedFetcher struct {
	*scriptedFetcher
	hosts *fetchdomain.VCSHostAllowlist
}

func (f *vcsScriptedFetcher) WithVCSHosts(hosts fetchdomain.VCSHostAllowlist) walkports.ModuleFetcher {
	f.hosts = &hosts
	return f
}

// bothScriptedFetcher has both optional capabilities, like the production
// adapters/fetcher/local fetcher.
type bothScriptedFetcher struct {
	*vcsScriptedFetcher
}

func (f *bothScriptedFetcher) WithForce(force bool) walkports.ModuleFetcher {
	f.forced = &force
	return f
}

// Declared on the outer type so the clone keeps both capabilities; the embedded
// vcsScriptedFetcher's method would return the inner type and drop WithForce.
func (f *bothScriptedFetcher) WithVCSHosts(hosts fetchdomain.VCSHostAllowlist) walkports.ModuleFetcher {
	f.hosts = &hosts
	return f
}

type vcsCapableCheck interface {
	WithVCSHosts(fetchdomain.VCSHostAllowlist) walkports.ModuleFetcher
}

type forceCapableCheckIface interface {
	WithForce(bool) walkports.ModuleFetcher
}

// The decorator must advertise the VCS-allowlist capability exactly when the
// wrapped fetcher has it: advertising it over a fetcher that lacks it would
// drop an operator's allowed_vcs_hosts silently.
func TestVCSHostCapabilityMirrorsWrappedFetcher(t *testing.T) {
	plain := New(&scriptedFetcher{}, slog.New(slog.DiscardHandler))
	if _, ok := plain.(vcsCapableCheck); ok {
		t.Error("decorator advertises a VCS allowlist over a fetcher that lacks it")
	}

	inner := &vcsScriptedFetcher{scriptedFetcher: &scriptedFetcher{}}
	wrapped := New(inner, slog.New(slog.DiscardHandler))
	vc, ok := wrapped.(vcsCapableCheck)
	if !ok {
		t.Fatal("decorator dropped the wrapped fetcher's VCS-allowlist capability")
	}
	if _, ok := wrapped.(forceCapableCheckIface); ok {
		t.Error("decorator advertises force mode over a fetcher that only takes hosts")
	}

	want, err := fetchdomain.NewVCSHostAllowlist([]string{"github.com"})
	if err != nil {
		t.Fatalf("building allowlist: %v", err)
	}
	clone := vc.WithVCSHosts(want)
	if inner.hosts == nil {
		t.Fatal("WithVCSHosts not passed through to the wrapped fetcher")
	}
	if inner.hosts.IsAllowed("gitlab.com") {
		t.Error("the wrapped fetcher received the wrong allowlist")
	}
	if _, ok := clone.(vcsCapableCheck); !ok {
		t.Error("the clone lost the VCS-allowlist capability")
	}
}

// A fetcher with both capabilities must keep both across either clone, so
// --force and allowed_vcs_hosts compose instead of cancelling each other.
func TestBothCapabilitiesSurviveEitherClone(t *testing.T) {
	inner := &bothScriptedFetcher{vcsScriptedFetcher: &vcsScriptedFetcher{scriptedFetcher: &scriptedFetcher{}}}
	wrapped := New(inner, slog.New(slog.DiscardHandler))

	fc, ok := wrapped.(forceCapableCheckIface)
	if !ok {
		t.Fatal("decorator dropped force capability")
	}
	hosts, err := fetchdomain.NewVCSHostAllowlist([]string{"github.com"})
	if err != nil {
		t.Fatalf("building allowlist: %v", err)
	}
	forced := fc.WithForce(true)
	vc, ok := forced.(vcsCapableCheck)
	if !ok {
		t.Fatal("the force clone lost the VCS-allowlist capability")
	}
	both := vc.WithVCSHosts(hosts)
	if _, ok := both.(forceCapableCheckIface); !ok {
		t.Error("the allowlist clone lost force capability")
	}
	if inner.forced == nil || !*inner.forced {
		t.Error("force not passed through")
	}
	if inner.hosts == nil || inner.hosts.IsAllowed("gitlab.com") {
		t.Error("allowlist not passed through")
	}
}

// The variants whose inner lost a capability (only reachable by constructing
// one directly) return themselves rather than panicking.
func TestCapabilityCloneOverIncapableInnerReturnsSelf(t *testing.T) {
	base := baseOf(New(&scriptedFetcher{}, slog.New(slog.DiscardHandler)))
	v := &vcsFetcher{Fetcher: base}
	if got := v.WithVCSHosts(fetchdomain.DefaultVCSHostAllowlist()); got != walkports.ModuleFetcher(v) {
		t.Error("WithVCSHosts over an incapable inner did not return the decorator unchanged")
	}
	fv := &forcingVCSFetcher{Fetcher: base}
	if got := fv.WithVCSHosts(fetchdomain.DefaultVCSHostAllowlist()); got != walkports.ModuleFetcher(fv) {
		t.Error("WithVCSHosts over an incapable inner did not return the decorator unchanged")
	}
	if got := fv.WithForce(true); got != walkports.ModuleFetcher(fv) {
		t.Error("WithForce over an incapable inner did not return the decorator unchanged")
	}
}

// EnsureFetchedReplacing delegates: this fake has no replace-aware behaviour of
// its own, so a replaced module is fetched exactly like an unreplaced one.
func (f *scriptedFetcher) EnsureFetchedReplacing(ctx context.Context, c, _ coordinate.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	return f.EnsureFetched(ctx, c)
}
