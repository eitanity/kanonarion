package application_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
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

// A +incompatible pin lives at the bare path while carrying its major in the
// version, so the properly-versioned publication of THAT major is a different
// module path and is the migration target. gavv/httpexpect is the measured
// case: /v2 is published, /v3 does not exist.
func TestResolve_IncompatiblePinFindsItsOwnMajorRepublished(t *testing.T) {
	proxy := &fakeProxy{versions: map[string]string{
		"github.com/gavv/httpexpect":    "v2.0.0+incompatible",
		"github.com/gavv/httpexpect/v2": "v2.16.0",
	}}
	r := application.NewResolver(proxy, nil, &fixedClock{t: time.Now()}, time.Hour, false)

	ans, err := r.Resolve(context.Background(), "github.com/gavv/httpexpect", "v2.0.0+incompatible")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !ans.NewerMajor.Exists() {
		t.Fatal("the republished /v2 must be reported, not a recorded negative")
	}
	if ans.NewerMajor.Path != "github.com/gavv/httpexpect/v2" {
		t.Errorf("NewerMajor.Path = %q, want github.com/gavv/httpexpect/v2", ans.NewerMajor.Path)
	}
	if ans.NewerMajor.Version != "v2.16.0" {
		t.Errorf("NewerMajor.Version = %q, want v2.16.0", ans.NewerMajor.Version)
	}
	// FromMajor still names the WALK's start. The same-major question is not a
	// step of the walk, and the stored start keeps its meaning.
	if ans.NewerMajor.FromMajor != 3 {
		t.Errorf("FromMajor = %d, want 3", ans.NewerMajor.FromMajor)
	}
	// The same-major question is asked first, and the walk still runs: a hit at
	// /v2 does not establish that there is nothing above it.
	wantCalls := []string{
		"github.com/gavv/httpexpect",
		"github.com/gavv/httpexpect/v2",
		"github.com/gavv/httpexpect/v3",
	}
	if !slices.Equal(proxy.calls, wantCalls) {
		t.Errorf("proxy calls = %v, want %v", proxy.calls, wantCalls)
	}
}

// The non-zero control. A +incompatible pin whose major was never republished
// under a suffixed path still reports no newer major — the extra step changes
// what is asked, not what is answered.
func TestResolve_IncompatiblePinWithNoRepublicationStillReportsNone(t *testing.T) {
	proxy := &fakeProxy{versions: map[string]string{
		"example.com/mod": "v2.22.0+incompatible",
	}}
	r := application.NewResolver(proxy, nil, &fixedClock{t: time.Now()}, time.Hour, false)

	ans, err := r.Resolve(context.Background(), "example.com/mod", "v2.22.0+incompatible")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !ans.NewerMajor.Probed {
		t.Fatal("the probe ran; the row must record it")
	}
	if ans.NewerMajor.Exists() {
		t.Errorf("NewerMajor.Path = %q, want a recorded negative", ans.NewerMajor.Path)
	}
	// Two probe requests, not one: the absent /v2 is stepped over, and the
	// absent /v3 is what ends the walk.
	wantCalls := []string{"example.com/mod", "example.com/mod/v2", "example.com/mod/v3"}
	if !slices.Equal(proxy.calls, wantCalls) {
		t.Errorf("proxy calls = %v, want %v", proxy.calls, wantCalls)
	}
}

// The Masterminds/sprig shape, which is why the same-major absence is stepped
// over instead of stopped on: /v2 was never published, /v3 was.
func TestResolve_IncompatiblePinStepsOverItsAbsentOwnMajor(t *testing.T) {
	proxy := &fakeProxy{versions: map[string]string{
		"github.com/Masterminds/sprig":    "v2.22.0+incompatible",
		"github.com/Masterminds/sprig/v3": "v3.3.0",
	}}
	r := application.NewResolver(proxy, nil, &fixedClock{t: time.Now()}, time.Hour, false)

	ans, err := r.Resolve(context.Background(), "github.com/Masterminds/sprig", "v2.22.0+incompatible")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ans.NewerMajor.Path != "github.com/Masterminds/sprig/v3" {
		t.Errorf("NewerMajor.Path = %q, want github.com/Masterminds/sprig/v3", ans.NewerMajor.Path)
	}
}

// When both exist the row reports the HIGHEST major found. The republished
// same-major is the answer only when there is nothing above it.
func TestResolve_IncompatiblePinReportsTheHighestMajorWhenBothExist(t *testing.T) {
	proxy := &fakeProxy{versions: map[string]string{
		"example.com/mod":    "v2.22.0+incompatible",
		"example.com/mod/v2": "v2.30.0",
		"example.com/mod/v3": "v3.1.0",
	}}
	r := application.NewResolver(proxy, nil, &fixedClock{t: time.Now()}, time.Hour, false)

	ans, err := r.Resolve(context.Background(), "example.com/mod", "v2.22.0+incompatible")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ans.NewerMajor.Path != "example.com/mod/v3" {
		t.Errorf("NewerMajor.Path = %q, want example.com/mod/v3", ans.NewerMajor.Path)
	}
	if ans.NewerMajor.Version != "v3.1.0" {
		t.Errorf("NewerMajor.Version = %q, want v3.1.0", ans.NewerMajor.Version)
	}
}

// A module already on a /vN path must not probe its own major: the module the
// caller is using is not its own upgrade target, and a proxy that answers /v2
// would otherwise report the pin back as a migration.
func TestResolve_SuffixedPinDoesNotReprobeItsOwnMajor(t *testing.T) {
	proxy := &fakeProxy{versions: map[string]string{
		"example.com/mod/v2": "v2.16.0",
	}}
	r := application.NewResolver(proxy, nil, &fixedClock{t: time.Now()}, time.Hour, false)

	ans, err := r.Resolve(context.Background(), "example.com/mod/v2", "v2.16.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ans.NewerMajor.Exists() {
		t.Errorf("NewerMajor.Path = %q, want a recorded negative", ans.NewerMajor.Path)
	}
	// The @latest call is on the pinned path itself; the probe starts at /v3.
	wantCalls := []string{"example.com/mod/v2", "example.com/mod/v3"}
	if !slices.Equal(proxy.calls, wantCalls) {
		t.Errorf("proxy calls = %v, want %v", proxy.calls, wantCalls)
	}
}

// The change alters what a probe RECORDS, not how a row is keyed, so no stored
// row is invalidated by it and none is re-probed on account of it. A row
// written before the change stays servable until its lookup time falls outside
// the TTL — which is the only thing that qualifies this ledger, and the only
// way a stale row is told from a current one.
func TestResolve_RowFromBeforeTheChangeExpiresRatherThanBeingInvalidated(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	// The recorded negative the probe produced before it asked about /v2.
	before := domain.Record{
		ModulePath:    "github.com/gavv/httpexpect",
		LatestVersion: "v2.0.0+incompatible",
		NewerMajor:    domain.NewerMajor{Probed: true, FromMajor: 3},
		LookedUpAt:    now.Add(-30 * time.Minute),
	}
	proxy := func() *fakeProxy {
		return &fakeProxy{versions: map[string]string{
			"github.com/gavv/httpexpect":    "v2.0.0+incompatible",
			"github.com/gavv/httpexpect/v2": "v2.16.0",
		}}
	}

	t.Run("inside the TTL it is served unchanged", func(t *testing.T) {
		ledger := newFakeLedger()
		ledger.rows[before.ModulePath] = before
		px := proxy()
		r := application.NewResolver(px, ledger, &fixedClock{t: now}, time.Hour, false)

		ans, err := r.Resolve(context.Background(), before.ModulePath, "v2.0.0+incompatible")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if !ans.Served {
			t.Error("a row inside the TTL is served; nothing about the change invalidates it")
		}
		if len(px.calls) != 0 {
			t.Errorf("proxy calls = %v, want none", px.calls)
		}
	})

	t.Run("outside the TTL it is re-probed and picks up the republished major", func(t *testing.T) {
		ledger := newFakeLedger()
		ledger.rows[before.ModulePath] = before
		px := proxy()
		r := application.NewResolver(px, ledger, &fixedClock{t: now}, 10*time.Minute, false)

		ans, err := r.Resolve(context.Background(), before.ModulePath, "v2.0.0+incompatible")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if ans.Served {
			t.Error("a row outside the TTL must not be served")
		}
		if ans.NewerMajor.Path != "github.com/gavv/httpexpect/v2" {
			t.Errorf("NewerMajor.Path = %q, want github.com/gavv/httpexpect/v2", ans.NewerMajor.Path)
		}
	})

	// --fresh is the way to get the new answer without waiting the TTL out.
	t.Run("fresh bypasses the row entirely", func(t *testing.T) {
		ledger := newFakeLedger()
		ledger.rows[before.ModulePath] = before
		px := proxy()
		r := application.NewResolver(px, ledger, &fixedClock{t: now}, time.Hour, true)

		ans, err := r.Resolve(context.Background(), before.ModulePath, "v2.0.0+incompatible")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if ans.NewerMajor.Path != "github.com/gavv/httpexpect/v2" {
			t.Errorf("NewerMajor.Path = %q, want github.com/gavv/httpexpect/v2", ans.NewerMajor.Path)
		}
		if stored := ledger.rows[before.ModulePath]; stored.NewerMajor.Path != "github.com/gavv/httpexpect/v2" {
			t.Errorf("stored NewerMajor.Path = %q, want the freshly measured one", stored.NewerMajor.Path)
		}
	})
}
