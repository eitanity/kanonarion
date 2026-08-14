package application_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/staleness/application"
	"github.com/eitanity/kanonarion/internal/staleness/domain"
	"github.com/eitanity/kanonarion/internal/staleness/ports"
)

var errProxyDown = errors.New("proxy down")

// fakeProxy answers from a fixed map. Any path not in it is absent, which is
// what bounds the probe. Paths in fail return errProxyDown instead.
type fakeProxy struct {
	versions map[string]string
	fail     map[string]bool
	calls    []string
}

func (f *fakeProxy) LatestInfo(_ context.Context, path string) (ports.LatestInfo, error) {
	f.calls = append(f.calls, path)
	if f.fail[path] {
		return ports.LatestInfo{}, errProxyDown
	}
	v, ok := f.versions[path]
	if !ok {
		return ports.LatestInfo{}, fmt.Errorf("%w: %s", ports.ErrPathAbsent, path)
	}
	return ports.LatestInfo{Version: v, Time: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)}, nil
}

type fakeLedger struct {
	rows   map[string]domain.Record
	writes int
	reads  int
}

func newFakeLedger() *fakeLedger { return &fakeLedger{rows: map[string]domain.Record{}} }

func (l *fakeLedger) GetStaleness(_ context.Context, path string) (domain.Record, bool, error) {
	l.reads++
	rec, ok := l.rows[path]
	return rec, ok, nil
}

func (l *fakeLedger) PutStaleness(_ context.Context, rec domain.Record) error {
	l.writes++
	l.rows[rec.ModulePath] = rec
	return nil
}

type fixedClock struct{ t time.Time }

func (c *fixedClock) Now() time.Time { return c.t }

func TestResolve_ProbesUpwardAndStopsAtTheFirstAbsentMajor(t *testing.T) {
	proxy := &fakeProxy{versions: map[string]string{
		"example.com/mod":    "v1.9.0",
		"example.com/mod/v2": "v2.1.0",
		"example.com/mod/v3": "v3.4.0",
		// no /v4, and a /v5 that must never be reached because the walk stops
		// at the first gap.
		"example.com/mod/v5": "v5.0.0",
	}}
	r := application.NewResolver(proxy, nil, &fixedClock{t: time.Now()}, time.Hour, false)

	ans, err := r.Resolve(context.Background(), "example.com/mod", "v1.5.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ans.LatestVersion != "v1.9.0" {
		t.Errorf("LatestVersion = %q, want v1.9.0", ans.LatestVersion)
	}
	if !ans.NewerMajor.Exists() {
		t.Fatal("expected a newer major")
	}
	if ans.NewerMajor.Path != "example.com/mod/v3" || ans.NewerMajor.Version != "v3.4.0" {
		t.Errorf("NewerMajor = %s@%s, want example.com/mod/v3@v3.4.0", ans.NewerMajor.Path, ans.NewerMajor.Version)
	}
	for _, called := range proxy.calls {
		if called == "example.com/mod/v5" {
			t.Error("probe walked past the first absent major")
		}
	}
}

// The failure the whole change exists to correct: a module at the newest
// version of its own path while a newer major line is available. IsLatest-style
// facts and the major fact must both be present and separate.
func TestResolve_CurrentPathWithNewerMajorReportsBoth(t *testing.T) {
	proxy := &fakeProxy{versions: map[string]string{
		"example.com/mod/v6": "v6.0.57",
		"example.com/mod/v7": "v7.2.1",
	}}
	r := application.NewResolver(proxy, nil, &fixedClock{t: time.Now()}, time.Hour, false)

	ans, err := r.Resolve(context.Background(), "example.com/mod/v6", "v6.0.57")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ans.LatestVersion != "v6.0.57" {
		t.Errorf("LatestVersion = %q: the same-major answer must be unchanged", ans.LatestVersion)
	}
	if ans.NewerMajor.Path != "example.com/mod/v7" {
		t.Errorf("NewerMajor.Path = %q, want example.com/mod/v7", ans.NewerMajor.Path)
	}
}

func TestResolve_RecordsTheNegativeProbe(t *testing.T) {
	proxy := &fakeProxy{versions: map[string]string{"example.com/mod": "v1.0.0"}}
	ledger := newFakeLedger()
	r := application.NewResolver(proxy, ledger, &fixedClock{t: time.Now()}, time.Hour, false)

	ans, err := r.Resolve(context.Background(), "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !ans.NewerMajor.Probed {
		t.Fatal("a completed probe must be recorded as probed")
	}
	if ans.NewerMajor.Exists() {
		t.Error("no newer major exists")
	}
	// The recorded negative is the point: an absent major is a definitive
	// answer, so the next run inside the TTL must not re-pay for it.
	stored := ledger.rows["example.com/mod"]
	if !stored.NewerMajor.Probed || stored.NewerMajor.Path != "" {
		t.Errorf("stored probe = %+v, want a recorded negative", stored.NewerMajor)
	}
}

func TestResolve_ServesAFreshRowWithoutTouchingTheProxy(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	ledger := newFakeLedger()
	ledger.rows["example.com/mod"] = domain.Record{
		ModulePath:    "example.com/mod",
		LatestVersion: "v1.9.0",
		NewerMajor:    domain.NewerMajor{Probed: true, FromMajor: 2},
		LookedUpAt:    now.Add(-10 * time.Minute),
	}
	proxy := &fakeProxy{versions: map[string]string{"example.com/mod": "v2.0.0"}}
	r := application.NewResolver(proxy, ledger, &fixedClock{t: now}, time.Hour, false)

	ans, err := r.Resolve(context.Background(), "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(proxy.calls) != 0 {
		t.Errorf("a fresh row must not query the proxy, got %v", proxy.calls)
	}
	if !ans.Served {
		t.Error("Served must be true for a wholly-served answer")
	}
	if ans.LatestVersion != "v1.9.0" {
		t.Errorf("LatestVersion = %q, want the stored v1.9.0", ans.LatestVersion)
	}
	// The stated lookup time is the ORIGINAL one, not now: a served answer that
	// re-dated itself would be indistinguishable from a live one.
	if !ans.LookedUpAt.Equal(now.Add(-10 * time.Minute)) {
		t.Errorf("LookedUpAt = %v, want the original lookup time", ans.LookedUpAt)
	}
}

func TestResolve_ExpiredRowIsRequeried(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	ledger := newFakeLedger()
	ledger.rows["example.com/mod"] = domain.Record{
		ModulePath:    "example.com/mod",
		LatestVersion: "v1.0.0",
		NewerMajor:    domain.NewerMajor{Probed: true, FromMajor: 2},
		LookedUpAt:    now.Add(-2 * time.Hour),
	}
	proxy := &fakeProxy{versions: map[string]string{"example.com/mod": "v1.9.0"}}
	r := application.NewResolver(proxy, ledger, &fixedClock{t: now}, time.Hour, false)

	ans, err := r.Resolve(context.Background(), "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ans.LatestVersion != "v1.9.0" {
		t.Errorf("LatestVersion = %q, want the re-queried v1.9.0", ans.LatestVersion)
	}
	if ans.Served {
		t.Error("an expired row must not report as served")
	}
	if !ans.LookedUpAt.Equal(now) {
		t.Errorf("LookedUpAt = %v, want now", ans.LookedUpAt)
	}
}

// --fresh must suppress ledger READS but still write: a freshly measured fact
// is exactly what the next run should be served.
func TestResolve_FreshBypassesTheReadAndStillWrites(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	ledger := newFakeLedger()
	ledger.rows["example.com/mod"] = domain.Record{
		ModulePath:    "example.com/mod",
		LatestVersion: "v1.0.0",
		NewerMajor:    domain.NewerMajor{Probed: true, FromMajor: 2},
		LookedUpAt:    now,
	}
	proxy := &fakeProxy{versions: map[string]string{"example.com/mod": "v1.9.0"}}
	r := application.NewResolver(proxy, ledger, &fixedClock{t: now}, time.Hour, true)

	ans, err := r.Resolve(context.Background(), "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ledger.reads != 0 {
		t.Errorf("--fresh must not read the ledger, got %d reads", ledger.reads)
	}
	if ans.LatestVersion != "v1.9.0" {
		t.Errorf("LatestVersion = %q, want the live v1.9.0", ans.LatestVersion)
	}
	if ledger.writes != 1 || ledger.rows["example.com/mod"].LatestVersion != "v1.9.0" {
		t.Error("--fresh must still record what it resolved")
	}
}

// The sumdb rule: failures are not cacheable facts.
func TestResolve_FailedLookupIsNotWritten(t *testing.T) {
	proxy := &fakeProxy{
		versions: map[string]string{},
		fail:     map[string]bool{"example.com/mod": true},
	}
	ledger := newFakeLedger()
	r := application.NewResolver(proxy, ledger, &fixedClock{t: time.Now()}, time.Hour, false)

	if _, err := r.Resolve(context.Background(), "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("expected the failure to surface")
	}
	if ledger.writes != 0 {
		t.Errorf("a failed lookup must not be written, got %d writes", ledger.writes)
	}
}

// A probe whose request FAILED must leave Probed false. Recording it as a
// negative would turn an unasked question into "no newer major exists".
func TestResolve_FailedProbeIsNotRecordedAsANegative(t *testing.T) {
	proxy := &fakeProxy{
		versions: map[string]string{"example.com/mod": "v1.0.0"},
		fail:     map[string]bool{"example.com/mod/v2": true},
	}
	ledger := newFakeLedger()
	r := application.NewResolver(proxy, ledger, &fixedClock{t: time.Now()}, time.Hour, false)

	ans, err := r.Resolve(context.Background(), "example.com/mod", "v1.0.0")
	if err == nil {
		t.Fatal("expected the probe failure to surface")
	}
	if ans.NewerMajor.Probed {
		t.Error("a failed probe must not be recorded as probed")
	}
	// The same-major half DID resolve, and that is a real fact worth keeping.
	if ledger.writes != 1 {
		t.Fatalf("expected the resolved half to be written, got %d writes", ledger.writes)
	}
	if stored := ledger.rows["example.com/mod"]; stored.NewerMajor.Probed {
		t.Error("stored row must record the probe as not run")
	}
}

// A cached probe is keyed to the major it started at. The same bare path pinned
// at v1 and at v2+incompatible start at /v2 and /v3, and the first stops on a
// gap the second steps over — so the first's answer must not be served to the
// second.
func TestResolve_CachedProbeIsNotReusedAcrossStartMajors(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	ledger := newFakeLedger()
	ledger.rows["example.com/mod"] = domain.Record{
		ModulePath:    "example.com/mod",
		LatestVersion: "v2.22.0+incompatible",
		NewerMajor:    domain.NewerMajor{Probed: true, FromMajor: 2},
		LookedUpAt:    now.Add(-time.Minute),
	}
	proxy := &fakeProxy{versions: map[string]string{"example.com/mod/v3": "v3.3.0"}}
	r := application.NewResolver(proxy, ledger, &fixedClock{t: now}, time.Hour, false)

	ans, err := r.Resolve(context.Background(), "example.com/mod", "v2.22.0+incompatible")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ans.Served {
		t.Error("a probe cached from a different start major must not be served")
	}
	if ans.NewerMajor.Path != "example.com/mod/v3" {
		t.Errorf("NewerMajor.Path = %q, want example.com/mod/v3", ans.NewerMajor.Path)
	}
	// The re-probed row keeps the cached lookup time: the answer as a whole is
	// no fresher than its oldest half.
	if !ans.LookedUpAt.Equal(now.Add(-time.Minute)) {
		t.Errorf("LookedUpAt = %v, want the cached lookup time", ans.LookedUpAt)
	}
}

func TestResolve_NoLedgerIsLiveAndUnwritten(t *testing.T) {
	proxy := &fakeProxy{versions: map[string]string{"example.com/mod": "v1.0.0"}}
	r := application.NewResolver(proxy, nil, &fixedClock{t: time.Now()}, time.Hour, false)

	ans, err := r.Resolve(context.Background(), "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ans.Served {
		t.Error("a ledger-less resolver can never serve")
	}
	if ans.LatestVersion != "v1.0.0" {
		t.Errorf("LatestVersion = %q", ans.LatestVersion)
	}
}

// Without a pin the resolved latest places the probe. A bare path whose newest
// release is a +incompatible v2 must still probe from /v3.
func TestResolve_UnpinnedUsesTheResolvedLatestToPlaceTheProbe(t *testing.T) {
	proxy := &fakeProxy{versions: map[string]string{
		"example.com/mod":    "v2.22.0+incompatible",
		"example.com/mod/v3": "v3.3.0",
	}}
	r := application.NewResolver(proxy, nil, &fixedClock{t: time.Now()}, time.Hour, false)

	ans, err := r.Resolve(context.Background(), "example.com/mod", "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ans.NewerMajor.Path != "example.com/mod/v3" {
		t.Errorf("NewerMajor.Path = %q, want example.com/mod/v3", ans.NewerMajor.Path)
	}
}

// TestResolve_ZeroTTLAndFreshAgreeOnTheAnswerAndDifferOnTheRead
//
// There are two ways to ask for a live lookup and they are not the same
// mechanism. --fresh suppresses the ledger READ. A zero staleness.ttl leaves
// the read in place and makes every row fail FreshAt. Both produce a live
// answer and both still write, so the answer never depends on which was used;
// what differs is whether the ledger is touched at all, which is visible when
// the ledger itself is broken — a zero TTL surfaces that read failure, --fresh
// cannot. Pinned here because "two ways to ask the same question" is exactly
// the shape that drifts apart unmeasured.
func TestResolve_ZeroTTLAndFreshAgreeOnTheAnswerAndDifferOnTheRead(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	stored := domain.Record{
		ModulePath:    "example.com/mod",
		LatestVersion: "v1.0.0",
		NewerMajor:    domain.NewerMajor{Probed: true, FromMajor: 2},
		LookedUpAt:    now,
	}

	tests := []struct {
		name      string
		ttl       time.Duration
		fresh     bool
		wantReads int
	}{
		{name: "fresh bypasses the read", ttl: time.Hour, fresh: true, wantReads: 0},
		{name: "a zero TTL reads and rejects", ttl: 0, fresh: false, wantReads: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ledger := newFakeLedger()
			ledger.rows["example.com/mod"] = stored
			proxy := &fakeProxy{versions: map[string]string{"example.com/mod": "v1.9.0"}}
			r := application.NewResolver(proxy, ledger, &fixedClock{t: now}, tt.ttl, tt.fresh)

			ans, err := r.Resolve(context.Background(), "example.com/mod", "v1.0.0")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			// The answer is the same either way: live, and recorded.
			if ans.LatestVersion != "v1.9.0" {
				t.Errorf("LatestVersion = %q, want the live v1.9.0", ans.LatestVersion)
			}
			if ans.Served {
				t.Error("a live answer must not report itself as served from the ledger")
			}
			if ledger.writes != 1 {
				t.Errorf("writes = %d, want 1 — a live lookup is what the next run should be served", ledger.writes)
			}
			// The mechanism is not the same.
			if ledger.reads != tt.wantReads {
				t.Errorf("ledger reads = %d, want %d", ledger.reads, tt.wantReads)
			}
		})
	}
}
