package application_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/staleness/application"
	"github.com/eitanity/kanonarion/internal/staleness/domain"
	"github.com/eitanity/kanonarion/internal/staleness/ports"
)

// countingProxy answers like fakeProxy and records how many calls were in
// flight at once, which is the only thing that distinguishes a concurrent probe
// from a serial one.
type countingProxy struct {
	versions map[string]string
	delay    time.Duration

	mu      sync.Mutex
	inWork  int
	peak    int
	callsBy map[string]int
	total   atomic.Int64
}

func newCountingProxy(versions map[string]string, delay time.Duration) *countingProxy {
	return &countingProxy{versions: versions, delay: delay, callsBy: map[string]int{}}
}

func (c *countingProxy) LatestInfo(_ context.Context, path string) (ports.LatestInfo, error) {
	c.mu.Lock()
	c.inWork++
	if c.inWork > c.peak {
		c.peak = c.inWork
	}
	c.callsBy[path]++
	c.mu.Unlock()
	c.total.Add(1)

	time.Sleep(c.delay)

	c.mu.Lock()
	c.inWork--
	c.mu.Unlock()

	v, ok := c.versions[path]
	if !ok {
		return ports.LatestInfo{}, fmt.Errorf("%w: %s", ports.ErrPathAbsent, path)
	}
	return ports.LatestInfo{Version: v, Time: time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC)}, nil
}

func (c *countingProxy) peakInFlight() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peak
}

func scopeOf(n int) []ports.PinnedModule {
	mods := make([]ports.PinnedModule, 0, n)
	for i := range n {
		mods = append(mods, ports.PinnedModule{Path: fmt.Sprintf("example.com/m%02d", i), Version: "v1.0.0"})
	}
	return mods
}

func batchFor(mods []ports.PinnedModule) *fakeBatch {
	answers := map[string]ports.BatchLatest{}
	for _, m := range mods {
		answers[m.Path] = ports.BatchLatest{LatestInfo: ports.LatestInfo{Version: m.Version}}
	}
	return &fakeBatch{answers: answers}
}

// The newer-major probe is one request per module in the closure — for almost
// every module a 404 — and asking them one at a time is what was left of the
// marathon after the latest half was batched away. They go out concurrently,
// bounded, and this asserts both halves of that: the width is reached, and it
// is not exceeded.
func TestProbeRunsConcurrentlyUpToTheConfiguredWidth(t *testing.T) {
	mods := scopeOf(40)
	proxy := newCountingProxy(nil, 20*time.Millisecond)
	r := application.NewResolver(proxy, nil, &fixedClock{t: time.Now()}, time.Hour, false).
		WithBatch(batchFor(mods), mods, 8)

	for _, m := range mods {
		if _, err := r.Resolve(context.Background(), m.Path, m.Version); err != nil {
			t.Fatalf("Resolve(%s): %v", m.Path, err)
		}
	}

	peak := proxy.peakInFlight()
	if peak < 2 {
		t.Errorf("peak in-flight probes = %d: the probe is still serial", peak)
	}
	if peak > 8 {
		t.Errorf("peak in-flight probes = %d, above the configured width of 8", peak)
	}
}

// The bound is a correctness dial, not only a speed one: a throttled proxy
// answers 200 with an empty body rather than refusing, so an unbounded probe
// trades wall time for lost answers. Width 1 must still work, and must be
// serial.
func TestProbeWidthOneIsSerial(t *testing.T) {
	mods := scopeOf(10)
	proxy := newCountingProxy(nil, 5*time.Millisecond)
	r := application.NewResolver(proxy, nil, &fixedClock{t: time.Now()}, time.Hour, false).
		WithBatch(batchFor(mods), mods, 1)

	for _, m := range mods {
		if _, err := r.Resolve(context.Background(), m.Path, m.Version); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
	}
	if peak := proxy.peakInFlight(); peak != 1 {
		t.Errorf("peak in-flight = %d at width 1, want 1", peak)
	}
}

// The prefetch must not change what the walk ANSWERS. It walks in rounds — one
// round per major — and still stops at the first absent major, so a module with
// /v2 and /v3 published and no /v4 reports /v3 and never asks about /v5.
func TestPrefetchedWalkStillStopsAtTheFirstGap(t *testing.T) {
	mods := []ports.PinnedModule{{Path: "example.com/mod", Version: "v1.5.0"}}
	proxy := newCountingProxy(map[string]string{
		"example.com/mod/v2": "v2.1.0",
		"example.com/mod/v3": "v3.4.0",
		// no /v4; /v5 exists and must never be reached.
		"example.com/mod/v5": "v5.0.0",
	}, 0)
	r := application.NewResolver(proxy, nil, &fixedClock{t: time.Now()}, time.Hour, false).
		WithBatch(&fakeBatch{answers: map[string]ports.BatchLatest{
			"example.com/mod": {LatestInfo: ports.LatestInfo{Version: "v1.9.0"}},
		}}, mods, 8)

	ans, err := r.Resolve(context.Background(), "example.com/mod", "v1.5.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ans.NewerMajor.Path != "example.com/mod/v3" || ans.NewerMajor.Version != "v3.4.0" {
		t.Errorf("NewerMajor = %+v, want example.com/mod/v3@v3.4.0", ans.NewerMajor)
	}
	proxy.mu.Lock()
	reached := proxy.callsBy["example.com/mod/v5"]
	proxy.mu.Unlock()
	if reached != 0 {
		t.Errorf("the rounds walked past the first absent major: /v5 asked %d times", reached)
	}
}

// A module whose stored row answers BOTH halves is not prefetched. A partially
// warm run must not pay a network request for the rows the ledger already
// answers — that charge is the entire thing the ledger exists to remove.
func TestPrefetchSkipsRowsTheLedgerWillServe(t *testing.T) {
	now := time.Now()
	mods := []ports.PinnedModule{
		{Path: "example.com/warm", Version: "v1.0.0"},
		{Path: "example.com/cold", Version: "v1.0.0"},
	}
	ledger := newFakeLedger()
	ledger.rows["example.com/warm"] = domain.Record{
		ModulePath:    "example.com/warm",
		LatestVersion: "v1.0.0",
		NewerMajor:    domain.NewerMajor{Probed: true, FromMajor: 2},
		LookedUpAt:    now.Add(-time.Minute),
	}
	proxy := newCountingProxy(nil, 0)
	r := application.NewResolver(proxy, ledger, &fixedClock{t: now}, time.Hour, false).
		WithBatch(batchFor(mods), mods, 8)

	for _, m := range mods {
		if _, err := r.Resolve(context.Background(), m.Path, m.Version); err != nil {
			t.Fatalf("Resolve(%s): %v", m.Path, err)
		}
	}
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if n := proxy.callsBy["example.com/warm/v2"]; n != 0 {
		t.Errorf("a row the ledger serves whole was probed %d times", n)
	}
	if n := proxy.callsBy["example.com/cold/v2"]; n != 1 {
		t.Errorf("the cold row's probe ran %d times, want 1", n)
	}
}

// A candidate no round asked about is asked LIVE, never read out of the
// prefetch's silence. `latest <module>` names a path no scope prefetched, and a
// missing entry that ended a walk would be absence answering a question.
func TestPrefetchMissIsAskedLiveNotReadAsAbsent(t *testing.T) {
	proxy := newCountingProxy(map[string]string{
		"example.com/solo":    "v1.0.0",
		"example.com/solo/v2": "v2.0.0",
	}, 0)
	// No batch at all: the positional shape.
	r := application.NewResolver(proxy, nil, &fixedClock{t: time.Now()}, time.Hour, false)

	ans, err := r.Resolve(context.Background(), "example.com/solo", "v1.0.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !ans.NewerMajor.Exists() || ans.NewerMajor.Path != "example.com/solo/v2" {
		t.Errorf("NewerMajor = %+v, want example.com/solo/v2 — an unprefetched path must be asked", ans.NewerMajor)
	}
}

// ---- the pin-ahead restoration ----

// aheadCase is one of the five rows the road-test corpus reads as
// "ahead of latest tag". The batched source reports NO update for each of them,
// because it resolves within the pin's own major and there is nothing higher
// there — so read alone it renders them `current`, which is the answer the
// pin-ahead state exists to withhold.
var aheadCases = []struct {
	path   string
	pin    string
	tag    string
	update string // non-empty when the batch has a real update to keep
	want   domain.PinPosition
}{
	{
		path: "github.com/planetscale/vtprotobuf",
		pin:  "v0.6.1-0.20240319094008-0393e58bdf10", tag: "v0.6.0", want: domain.PinAhead,
	},
	{
		path: "github.com/hashicorp/hcl",
		pin:  "v1.0.1-vault-7", tag: "v1.0.0", want: domain.PinAhead,
	},
	{
		path: "github.com/smallstep/go-attestation",
		pin:  "v0.4.4-0.20260603212853-e1a87a0b07d9", tag: "v0.4.3", want: domain.PinAhead,
	},
	{
		path: "github.com/xordataexchange/crypt",
		pin:  "v0.0.3-0.20170626215501-b2862e3d0a77", tag: "v0.0.2", want: domain.PinAhead,
	},
	{
		path: "github.com/pmezard/go-difflib",
		pin:  "v1.0.1-0.20181226105442-5d4384ee4fb2", tag: "v1.0.0", want: domain.PinAhead,
	},
	{
		// The non-zero control, and the row that must NOT move: the batch has a
		// real update within the pin's own major and it is the better answer.
		path: "github.com/coreos/etcd",
		pin:  "v3.3.10+incompatible", tag: "v2.3.8+incompatible",
		update: "v3.3.27+incompatible", want: domain.PinBehind,
	},
}

func TestPinAheadOfTheLastTagSurvivesTheBatch(t *testing.T) {
	for _, tc := range aheadCases {
		t.Run(tc.path, func(t *testing.T) {
			latest := tc.pin
			if tc.update != "" {
				latest = tc.update
			}
			batch := &fakeBatch{answers: map[string]ports.BatchLatest{
				tc.path: {LatestInfo: ports.LatestInfo{Version: latest}, Updated: tc.update != ""},
			}}
			// The per-path resolver answers the module's own @latest with the
			// newest release TAG, which is what the proxy serves and what the
			// batched source cannot express.
			proxy := newCountingProxy(map[string]string{tc.path: tc.tag}, 0)
			mods := []ports.PinnedModule{{Path: tc.path, Version: tc.pin}}
			r := application.NewResolver(proxy, nil, &fixedClock{t: time.Now()}, time.Hour, false).
				WithBatch(batch, mods, 8)

			ans, err := r.Resolve(context.Background(), tc.path, tc.pin)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got := domain.ComparePin(tc.pin, ans.LatestVersion); got != tc.want {
				t.Errorf("position = %v, want %v (latest reported as %q)", got, tc.want, ans.LatestVersion)
			}
			if tc.update != "" && ans.LatestVersion != tc.update {
				t.Errorf("latest = %q, want the go command's update %q — its answer is never overwritten",
					ans.LatestVersion, tc.update)
			}
			if tc.update == "" && ans.LatestVersion != tc.tag {
				t.Errorf("latest = %q, want the last release tag %q", ans.LatestVersion, tc.tag)
			}
		})
	}
}

// The narrowing is syntactic and must not cost a request on the rows it cannot
// apply to. A plain release pin the go command reports no update for is the
// newest tag in its major by construction, and is not looked up.
func TestPlainReleasePinsAreNotLookedUp(t *testing.T) {
	mods := []ports.PinnedModule{{Path: "example.com/plain", Version: "v1.2.3"}}
	batch := &fakeBatch{answers: map[string]ports.BatchLatest{
		"example.com/plain": {LatestInfo: ports.LatestInfo{Version: "v1.2.3"}},
	}}
	proxy := newCountingProxy(map[string]string{"example.com/plain": "v1.2.3"}, 0)
	r := application.NewResolver(proxy, nil, &fixedClock{t: time.Now()}, time.Hour, false).
		WithBatch(batch, mods, 8)

	if _, err := r.Resolve(context.Background(), "example.com/plain", "v1.2.3"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if n := proxy.callsBy["example.com/plain"]; n != 0 {
		t.Errorf("a plain release pin cost %d @latest lookups, want 0", n)
	}
}

// A tag lookup that FAILS subtracts nothing. The batch's answer stands, because
// a lookup that established nothing must not turn a measured answer into a
// worse one.
func TestAFailedTagLookupLeavesTheBatchAnswerAlone(t *testing.T) {
	const pin = "v1.0.1-vault-7"
	mods := []ports.PinnedModule{{Path: "example.com/pre", Version: pin}}
	batch := &fakeBatch{answers: map[string]ports.BatchLatest{
		"example.com/pre": {LatestInfo: ports.LatestInfo{Version: pin}},
	}}
	// The path is absent from the proxy fake, so the tag lookup errors.
	proxy := newCountingProxy(nil, 0)
	r := application.NewResolver(proxy, nil, &fixedClock{t: time.Now()}, time.Hour, false).
		WithBatch(batch, mods, 8)

	ans, err := r.Resolve(context.Background(), "example.com/pre", pin)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ans.LatestVersion != pin {
		t.Errorf("latest = %q, want the batch's %q left untouched", ans.LatestVersion, pin)
	}
}

var _ = errors.Is
