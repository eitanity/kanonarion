package application_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/staleness/application"
	"github.com/eitanity/kanonarion/internal/staleness/domain"
	"github.com/eitanity/kanonarion/internal/staleness/ports"
)

var errBatchRefused = errors.New("the environment forbids fetching")

// fakeBatch answers the whole set from a fixed map, and counts its calls: the
// batch's entire reason for existing is that it is asked ONCE for a set the
// per-path resolver was asked about one module at a time.
type fakeBatch struct {
	answers map[string]ports.BatchLatest
	err     error

	mu    sync.Mutex
	calls int
	asked []string
}

func (b *fakeBatch) LatestBatch(_ context.Context, paths []string) (map[string]ports.BatchLatest, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	b.asked = append(b.asked, paths...)
	if b.err != nil {
		return nil, b.err
	}
	return b.answers, nil
}

// pins turns "path@version" test coordinates into the scope shape.
func pins(coords ...string) []ports.PinnedModule {
	mods := make([]ports.PinnedModule, 0, len(coords))
	for _, c := range coords {
		at := strings.LastIndex(c, "@")
		mods = append(mods, ports.PinnedModule{Path: c[:at], Version: c[at+1:]})
	}
	return mods
}

func batchAnswer(version string, day int, deprecated string) ports.BatchLatest {
	return ports.BatchLatest{
		LatestInfo: ports.LatestInfo{
			Version: version,
			Time:    time.Date(2026, 5, day, 0, 0, 0, 0, time.UTC),
		},
		Deprecated: deprecated,
	}
}

// TestBatchAnswersTheLatestAndTheProbeStillRuns is the composition this change
// turns on: the same-major latest comes from ONE batched call for the whole set,
// and the newer-major probe stays kanonarion's own per-path work.
//
// `go list -m -u` deliberately does not cross a major boundary, so the /vN
// answer is the fact this tool adds and it must survive the change. The two
// halves land on one row without either's absence being read as the other's
// answer.
func TestBatchAnswersTheLatestAndTheProbeStillRuns(t *testing.T) {
	proxy := &fakeProxy{versions: map[string]string{
		// The per-path resolver knows the /vN paths and NOTHING about the
		// module's own path: if the batch answer were ignored the resolve would
		// fail outright rather than quietly agreeing.
		"example.com/mod/v2": "v2.1.0",
	}}
	batch := &fakeBatch{answers: map[string]ports.BatchLatest{
		"example.com/mod": batchAnswer("v1.9.0", 4, ""),
	}}
	ledger := newFakeLedger()
	r := application.NewResolver(proxy, ledger, &fixedClock{t: time.Now()}, time.Hour, false).
		WithBatch(batch, pins("example.com/mod@v1.5.0"), 4)

	ans, err := r.Resolve(context.Background(), "example.com/mod", "v1.5.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ans.LatestVersion != "v1.9.0" {
		t.Errorf("LatestVersion = %q, want the batch's v1.9.0", ans.LatestVersion)
	}
	if want := time.Date(2026, 5, 4, 0, 0, 0, 0, time.UTC); !ans.LatestPublishedAt.Equal(want) {
		t.Errorf("LatestPublishedAt = %v, want %v — the publication date the batch carries", ans.LatestPublishedAt, want)
	}
	// The fact the go command does not answer.
	if !ans.NewerMajor.Exists() || ans.NewerMajor.Path != "example.com/mod/v2" {
		t.Errorf("NewerMajor = %+v, want example.com/mod/v2 — the probe is kanonarion's own and must survive", ans.NewerMajor)
	}
	// The probe asked about /vN paths only. The module's own path was answered
	// by the batch and must not have been asked about again.
	if slices.Contains(proxy.calls, "example.com/mod") {
		t.Errorf("the per-path resolver was asked for the module's own latest: %v", proxy.calls)
	}
	if batch.calls != 1 {
		t.Errorf("batch called %d times, want exactly 1 for the whole set", batch.calls)
	}

	// A batch-resolved answer is still a resolved answer: it is recorded, and it
	// carries the lookup time of the run that resolved it.
	if ledger.writes != 1 {
		t.Fatalf("ledger writes = %d, want 1 — a batched answer is still recorded", ledger.writes)
	}
	if ledger.rows["example.com/mod"].LookedUpAt.IsZero() {
		t.Error("the recorded row carries no lookup time")
	}
}

// TestBatchIsAskedOnceForTheWholeSet: one call, however many modules are
// resolved through it. This is the whole change — the same sweep was one proxy
// request per module, serially.
func TestBatchIsAskedOnceForTheWholeSet(t *testing.T) {
	paths := []string{"example.com/a", "example.com/b", "example.com/c"}
	batch := &fakeBatch{answers: map[string]ports.BatchLatest{
		"example.com/a": batchAnswer("v1.0.0", 1, ""),
		"example.com/b": batchAnswer("v2.0.0", 2, ""),
		"example.com/c": batchAnswer("v3.0.0", 3, ""),
	}}
	r := application.NewResolver(&fakeProxy{}, nil, &fixedClock{t: time.Now()}, time.Hour, false).
		WithBatch(batch, pins("example.com/a@v1.0.0", "example.com/b@v2.0.0", "example.com/c@v3.0.0"), 4)

	for _, p := range paths {
		if _, err := r.Resolve(context.Background(), p, "v1.0.0"); err != nil {
			t.Fatalf("Resolve(%s): %v", p, err)
		}
	}
	if batch.calls != 1 {
		t.Errorf("batch called %d times for %d modules, want 1", batch.calls, len(paths))
	}
	if !slices.Equal(batch.asked, paths) {
		t.Errorf("batch asked about %v, want the caller's scope %v", batch.asked, paths)
	}
}

// TestBatchSilenceIsNotAnAnswer: a path the batch did not report was NOT
// answered, and the resolver falls through to the per-path resolver instead of
// reading the silence as "this module is current".
//
// This is the same rule the whole context is built on. It is the reason the port
// returns a map of what it answered rather than a slice parallel to the request.
func TestBatchSilenceIsNotAnAnswer(t *testing.T) {
	proxy := &fakeProxy{versions: map[string]string{"example.com/unlisted": "v7.0.0"}}
	batch := &fakeBatch{answers: map[string]ports.BatchLatest{
		"example.com/other": batchAnswer("v1.0.0", 1, ""),
	}}
	r := application.NewResolver(proxy, nil, &fixedClock{t: time.Now()}, time.Hour, false).
		WithBatch(batch, pins("example.com/other@v1.0.0"), 4)

	ans, err := r.Resolve(context.Background(), "example.com/unlisted", "v6.0.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ans.LatestVersion != "v7.0.0" {
		t.Errorf("LatestVersion = %q, want the per-path resolver's v7.0.0", ans.LatestVersion)
	}
	// A path the batch did not answer was not asked about deprecation either.
	if ans.Deprecation.Checked {
		t.Error("a path the batch never reported came back with its deprecation established")
	}
	if !slices.Contains(proxy.calls, "example.com/unlisted") {
		t.Errorf("the per-path resolver was never asked: %v", proxy.calls)
	}
}

// TestBatchRefusalStopsTheRunAndWritesNothing: a batched call that could not be
// made is an error for every module, not an answer for any of them.
//
// This is the GOPROXY=off trap at the layer above the adapter. The refusal
// travels as ErrBatchUnavailable so the caller can stop the run once, and the
// ledger is untouched: a refusal is not a cacheable fact.
func TestBatchRefusalStopsTheRunAndWritesNothing(t *testing.T) {
	ledger := newFakeLedger()
	batch := &fakeBatch{err: errBatchRefused}
	r := application.NewResolver(&fakeProxy{}, ledger, &fixedClock{t: time.Now()}, time.Hour, false).
		WithBatch(batch, pins("example.com/mod@v1.5.0"), 4)

	ans, err := r.Resolve(context.Background(), "example.com/mod", "v1.0.0")
	if !errors.Is(err, application.ErrBatchUnavailable) {
		t.Fatalf("err = %v, want ErrBatchUnavailable", err)
	}
	if !errors.Is(err, errBatchRefused) {
		t.Errorf("the refusal's own reason was lost: %v", err)
	}
	if ans.LatestVersion != "" {
		t.Errorf("a refused batch produced a version: %q", ans.LatestVersion)
	}
	if ledger.writes != 0 {
		t.Errorf("ledger writes = %d, want 0 — a refusal is not a cacheable fact", ledger.writes)
	}

	// The failed call is not repeated per module: it failed for the whole set.
	if _, err := r.Resolve(context.Background(), "example.com/other", "v1.0.0"); !errors.Is(err, application.ErrBatchUnavailable) {
		t.Fatalf("second module: err = %v, want ErrBatchUnavailable", err)
	}
	if batch.calls != 1 {
		t.Errorf("batch retried %d times after failing for the whole set, want 1", batch.calls)
	}
}

// TestFreshRowsNeverReachTheBatch: the ledger is what a run inside the TTL is
// answered from, and it stays that way. A run whose rows are all fresh does not
// shell out at all — the batch is primed lazily, on the first module that
// actually needs a live latest.
func TestFreshRowsNeverReachTheBatch(t *testing.T) {
	now := time.Now()
	ledger := newFakeLedger()
	ledger.rows["example.com/mod"] = domain.Record{
		ModulePath:    "example.com/mod",
		LatestVersion: "v1.2.3",
		NewerMajor:    domain.NewerMajor{Probed: true, FromMajor: 2},
		Deprecation:   domain.Deprecation{Checked: true, Notice: "moved to example.com/mod2"},
		LookedUpAt:    now.Add(-time.Minute),
	}
	batch := &fakeBatch{}
	r := application.NewResolver(&fakeProxy{}, ledger, &fixedClock{t: now}, time.Hour, false).
		WithBatch(batch, pins("example.com/mod@v1.5.0"), 4)

	ans, err := r.Resolve(context.Background(), "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !ans.Served {
		t.Error("a row inside the TTL was not served from the ledger")
	}
	if batch.calls != 0 {
		t.Errorf("batch called %d times for an entirely served run, want 0", batch.calls)
	}
	// A recorded deprecation is served back with the row it was recorded beside.
	if !ans.Deprecation.Deprecated() || ans.Deprecation.Notice != "moved to example.com/mod2" {
		t.Errorf("served Deprecation = %+v, want the recorded notice", ans.Deprecation)
	}
	if !ans.LookedUpAt.Equal(now.Add(-time.Minute)) {
		t.Errorf("LookedUpAt = %v, want the ORIGINAL lookup time", ans.LookedUpAt)
	}
}

// TestDeprecationRidesOnTheBatchAnswer: the notice comes back with the latest
// version, is recorded, and a module declaring none records a NEGATIVE — checked
// and empty — which is a different state from never having been asked.
func TestDeprecationRidesOnTheBatchAnswer(t *testing.T) {
	const notice = "aws-sdk-go is deprecated. Use aws-sdk-go-v2."
	batch := &fakeBatch{answers: map[string]ports.BatchLatest{
		"example.com/old":   batchAnswer("v1.0.0", 1, notice),
		"example.com/fresh": batchAnswer("v2.0.0", 2, ""),
	}}
	ledger := newFakeLedger()
	r := application.NewResolver(&fakeProxy{}, ledger, &fixedClock{t: time.Now()}, time.Hour, false).
		WithBatch(batch, pins("example.com/old@v1.0.0", "example.com/fresh@v2.0.0"), 4)

	old, err := r.Resolve(context.Background(), "example.com/old", "v1.0.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !old.Deprecation.Deprecated() || old.Deprecation.Notice != notice {
		t.Errorf("Deprecation = %+v, want the notice verbatim", old.Deprecation)
	}
	if got := ledger.rows["example.com/old"].Deprecation.Notice; got != notice {
		t.Errorf("recorded notice = %q, want it verbatim", got)
	}

	ok, err := r.Resolve(context.Background(), "example.com/fresh", "v2.0.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !ok.Deprecation.Checked {
		t.Error("a module the batch answered for is not marked as checked")
	}
	if ok.Deprecation.Deprecated() {
		t.Error("a module declaring no deprecation was reported deprecated")
	}
}
