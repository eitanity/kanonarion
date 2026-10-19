package application_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/walk/adapters/gomod/xmod"
	application2 "github.com/eitanity/kanonarion/internal/walk/application"
	"github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
	"go.uber.org/goleak"
)

// ---- walker fake fetcher ----

// walkerFakeFetcher is a ModuleFetcher for walker tests. It tracks peak
// concurrency and supports controlled gates, errors, and panic injection.
type walkerFakeFetcher struct {
	mu        sync.Mutex
	records   map[string]domain2.CompositeRecord
	fromCache map[string]bool
	errors    map[string]error
	panicOn   map[string]bool
	gate      map[string]chan struct{}

	inFlight    atomic.Int32
	maxInFlight atomic.Int32
}

func newWalkerFetcher() *walkerFakeFetcher {
	return &walkerFakeFetcher{
		records:   make(map[string]domain2.CompositeRecord),
		fromCache: make(map[string]bool),
		errors:    make(map[string]error),
		panicOn:   make(map[string]bool),
		gate:      make(map[string]chan struct{}),
	}
}

func (f *walkerFakeFetcher) addRecord(t testing.TB, path, version string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[wkey(path, version)] = makeComposite(t, path, version)
}

func (f *walkerFakeFetcher) addCached(t testing.TB, path, version string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := wkey(path, version)
	f.records[k] = makeComposite(t, path, version)
	f.fromCache[k] = true
}

func (f *walkerFakeFetcher) addFetchError(path, version string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errors[wkey(path, version)] = err
}

func (f *walkerFakeFetcher) addPanic(path, version string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.panicOn[wkey(path, version)] = true
}

// addGate makes the fetch for (path, version) block until the returned channel
// is closed. Must be called before Walk.
func (f *walkerFakeFetcher) addGate(path, version string) chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch := make(chan struct{})
	f.gate[wkey(path, version)] = ch
	return ch
}

func (f *walkerFakeFetcher) EnsureFetched(ctx context.Context, c coordinate.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	k := wkey(c.Path(), c.Version())

	f.mu.Lock()
	shouldPanic := f.panicOn[k]
	fetchErr := f.errors[k]
	rec, hasRec := f.records[k]
	cached := f.fromCache[k]
	gateCh := f.gate[k]
	f.mu.Unlock()

	if shouldPanic {
		panic("injected panic for " + k)
	}

	cur := f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	for {
		max := f.maxInFlight.Load()
		if cur <= max {
			break
		}
		if f.maxInFlight.CompareAndSwap(max, cur) {
			break
		}
	}

	if gateCh != nil {
		select {
		case <-gateCh:
		case <-ctx.Done():
			return walkports.ModuleFetchResult{}, fmt.Errorf("gate cancelled: %w", ctx.Err())
		}
	}

	if fetchErr != nil {
		return walkports.ModuleFetchResult{}, fetchErr
	}
	if hasRec {
		return walkports.ModuleFetchResult{Record: rec, FromCache: cached}, nil
	}
	return walkports.ModuleFetchResult{}, fmt.Errorf("no walker fake record for %s", k)
}

func wkey(path, version string) string { return path + "@" + version }

// ---- test setup helpers ----

// buildWalker wires a Walker with:
// - a real GraphResolver backed by rf (fakeModuleFetcher) and blobs
// - wf (walkerFakeFetcher) as the walker's own fetcher
func buildWalker(rf *fakeModuleFetcher, wf *walkerFakeFetcher, blobs *fakeBlobStore, workers int) *application2.Walker {
	resolver := application2.NewGraphResolver(
		newXmodParser(),
		rf,
		blobs,
		fixedClock{fixedNow},
		"",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	return application2.NewWalker(
		resolver,
		wf,
		nil, // no local fetcher in base walker tests
		fixedClock{fixedNow},
		fakeStopwatch{},
		workers,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
}

// newXmodParser returns the real xmod GoModParser used in production.
func newXmodParser() walkports.GoModParser { return xmod.New() }

// ---- local fetcher fake ----

// fakeLocalFetcher implements walkports.LocalModuleFetcher for tests.
type fakeLocalFetcher struct {
	mu      sync.Mutex
	records map[string]domain2.CompositeRecord // key: path@version
	errors  map[string]error
	calls   []localFetchCall
}

// localFetchCall is one EnsureFetchedFromPath call: the directory read and the
// path the record names.
type localFetchCall struct {
	coord                coordinate.ModuleCoordinate
	absPath, writtenPath string
}

func newFakeLocalFetcher() *fakeLocalFetcher {
	return &fakeLocalFetcher{
		records: make(map[string]domain2.CompositeRecord),
		errors:  make(map[string]error),
	}
}

func (f *fakeLocalFetcher) addRecord(t testing.TB, path, version string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[wkey(path, version)] = makeComposite(t, path, version)
}

func (f *fakeLocalFetcher) addError(path, version string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errors[wkey(path, version)] = err
}

func (f *fakeLocalFetcher) EnsureFetchedFromPath(_ context.Context, c coordinate.ModuleCoordinate, absPath, writtenPath string) (walkports.LocalModuleFetchResult, error) {
	k := wkey(c.Path(), c.Version())
	f.mu.Lock()
	f.calls = append(f.calls, localFetchCall{coord: c, absPath: absPath, writtenPath: writtenPath})
	rec, hasRec := f.records[k]
	err := f.errors[k]
	f.mu.Unlock()
	if err != nil {
		return walkports.LocalModuleFetchResult{}, err
	}
	if hasRec {
		return walkports.LocalModuleFetchResult{Record: rec, FromCache: false}, nil
	}
	return walkports.LocalModuleFetchResult{}, fmt.Errorf("no local fake record for %s", k)
}

// buildWalkerWithLocal wires a Walker with a LocalModuleFetcher.
func buildWalkerWithLocal(rf *fakeModuleFetcher, wf *walkerFakeFetcher, lf *fakeLocalFetcher, blobs *fakeBlobStore, workers int) *application2.Walker {
	resolver := application2.NewGraphResolver(
		newXmodParser(),
		rf,
		blobs,
		fixedClock{fixedNow},
		"",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	return application2.NewWalker(
		resolver,
		wf,
		lf,
		fixedClock{fixedNow},
		fakeStopwatch{},
		workers,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
}

// ---- tests ----

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestWalker_NoDependencies(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(t, "example.com/target", "v1.0.0", "module example.com/target\ngo 1.21\n", blobs)

	wf := newWalkerFetcher()
	wf.addRecord(t, "example.com/target", "v1.0.0")

	w := buildWalker(rf, wf, blobs, 1)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
	})

	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if outcome.OverallStatus != domain.WalkSucceeded {
		t.Errorf("status = %s, want succeeded", outcome.OverallStatus)
	}
	if len(outcome.PerNodeResults) != 1 {
		t.Errorf("node count = %d, want 1", len(outcome.PerNodeResults))
	}
	r := outcome.PerNodeResults[coord("example.com/target", "v1.0.0")]
	if r.Status != domain.NodeSucceeded {
		t.Errorf("target status = %s, want succeeded", r.Status)
	}
}

func TestWalker_MultipleNodes(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(t, "example.com/target", "v1.0.0",
		"module example.com/target\ngo 1.21\nrequire example.com/dep v1.0.0\n", blobs)
	rf.add(t, "example.com/dep", "v1.0.0",
		"module example.com/dep\ngo 1.21\n", blobs)

	wf := newWalkerFetcher()
	wf.addRecord(t, "example.com/target", "v1.0.0")
	wf.addRecord(t, "example.com/dep", "v1.0.0")

	w := buildWalker(rf, wf, blobs, 2)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
	})

	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if outcome.OverallStatus != domain.WalkSucceeded {
		t.Errorf("status = %s, want succeeded", outcome.OverallStatus)
	}
	if len(outcome.PerNodeResults) != 2 {
		t.Errorf("node count = %d, want 2", len(outcome.PerNodeResults))
	}
	for _, r := range outcome.PerNodeResults {
		if r.Status != domain.NodeSucceeded {
			t.Errorf("%s status = %s, want succeeded", r.Coordinate, r.Status)
		}
	}
}

func TestWalker_TargetFetchFails(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()

	wf := newWalkerFetcher()
	wf.addFetchError("example.com/target", "v1.0.0", errors.New("proxy unavailable"))

	w := buildWalker(rf, wf, blobs, 2)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
	})

	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if outcome.OverallStatus != domain.WalkFailed {
		t.Errorf("status = %s, want failed", outcome.OverallStatus)
	}
	r := outcome.PerNodeResults[coord("example.com/target", "v1.0.0")]
	if r.Status != domain.NodeFetchFailed {
		t.Errorf("target node status = %s, want fetch_failed", r.Status)
	}
	// Regression: the graph target must be populated even when the
	// target fetch fails, otherwise the persisted record cannot be read back.
	if outcome.Graph.Target != coord("example.com/target", "v1.0.0") {
		t.Errorf("graph target = %+v, want example.com/target@v1.0.0", outcome.Graph.Target)
	}
}

func TestWalker_DependencyFetchFails(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(t, "example.com/target", "v1.0.0",
		"module example.com/target\ngo 1.21\nrequire example.com/dep v1.0.0\n", blobs)
	rf.add(t, "example.com/dep", "v1.0.0", "module example.com/dep\ngo 1.21\n", blobs)

	wf := newWalkerFetcher()
	wf.addRecord(t, "example.com/target", "v1.0.0")
	wf.addFetchError("example.com/dep", "v1.0.0", errors.New("dep unavailable"))

	w := buildWalker(rf, wf, blobs, 2)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
	})

	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if outcome.OverallStatus != domain.WalkPartial {
		t.Errorf("status = %s, want partial", outcome.OverallStatus)
	}
	dep := outcome.PerNodeResults[coord("example.com/dep", "v1.0.0")]
	if dep.Status != domain.NodeFetchFailed {
		t.Errorf("dep status = %s, want fetch_failed", dep.Status)
	}
	if dep.Error == nil || dep.Error.Message == "" {
		t.Error("dep NodeResult.Error should be populated")
	}
	tgt := outcome.PerNodeResults[coord("example.com/target", "v1.0.0")]
	if tgt.Status != domain.NodeSucceeded {
		t.Errorf("target status = %s, want succeeded", tgt.Status)
	}
}

func TestWalker_CacheHit(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(t, "example.com/target", "v1.0.0", "module example.com/target\ngo 1.21\n", blobs)

	wf := newWalkerFetcher()
	wf.addCached(t, "example.com/target", "v1.0.0")

	w := buildWalker(rf, wf, blobs, 1)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
	})

	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	r := outcome.PerNodeResults[coord("example.com/target", "v1.0.0")]
	if !r.FromCache {
		t.Error("expected FromCache=true for cached module")
	}
}

func TestWalker_ContextCancellation(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(t, "example.com/target", "v1.0.0",
		"module example.com/target\ngo 1.21\nrequire example.com/dep v1.0.0\n", blobs)
	rf.add(t, "example.com/dep", "v1.0.0", "module example.com/dep\ngo 1.21\n", blobs)

	wf := newWalkerFetcher()
	wf.addRecord(t, "example.com/target", "v1.0.0")
	// The gate for dep is never closed — the worker must exit via ctx.Done.
	gate := wf.addGate("example.com/dep", "v1.0.0")
	wf.addRecord(t, "example.com/dep", "v1.0.0")
	// Close the gate at test end so the goroutine can't leak if something goes wrong.
	t.Cleanup(func() { close(gate) })

	ctx, cancel := context.WithCancel(context.Background())

	w := buildWalker(rf, wf, blobs, 2)

	resultCh := make(chan domain.WalkOutcome, 1)
	go func() {
		o, _ := w.Walk(ctx, application2.WalkRequest{ //nolint:errcheck // cancelled mid-walk by design; the outcome is the subject
			Target: coord("example.com/target", "v1.0.0"),
		})
		resultCh <- o
	}()

	// Brief pause to let the goroutine block on the dep gate before cancelling.
	time.Sleep(5 * time.Millisecond)
	cancel()

	select {
	case outcome := <-resultCh:
		if outcome.OverallStatus != domain.WalkCancelled && outcome.OverallStatus != domain.WalkPartial {
			t.Errorf("status = %s, want cancelled or partial", outcome.OverallStatus)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Walk did not complete after context cancellation")
	}
}

func TestWalker_WorkerPoolLimit(t *testing.T) {
	const workerLimit = 2
	const depCount = 8

	blobs := newFakeBlobStore()
	rf := newFakeFetcher()

	gomod := "module example.com/target\ngo 1.21\n"
	for i := range depCount {
		gomod += fmt.Sprintf("require example.com/dep%d v1.0.0\n", i)
	}
	rf.add(t, "example.com/target", "v1.0.0", gomod, blobs)
	for i := range depCount {
		dep := fmt.Sprintf("example.com/dep%d", i)
		rf.add(t, dep, "v1.0.0", "module "+dep+"\ngo 1.21\n", blobs)
	}

	wf := newWalkerFetcher()
	wf.addRecord(t, "example.com/target", "v1.0.0")

	gates := make([]chan struct{}, depCount)
	for i := range depCount {
		gates[i] = wf.addGate(fmt.Sprintf("example.com/dep%d", i), "v1.0.0")
		wf.addRecord(t, fmt.Sprintf("example.com/dep%d", i), "v1.0.0")
	}

	// Release all gates after a short window so workers have time to pile up.
	go func() {
		time.Sleep(20 * time.Millisecond)
		for _, g := range gates {
			close(g)
		}
	}()

	w := buildWalker(rf, wf, blobs, workerLimit)
	_, err := w.Walk(context.Background(), application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	if got := int(wf.maxInFlight.Load()); got > workerLimit {
		t.Errorf("max concurrent fetches = %d, want ≤ %d", got, workerLimit)
	}
}

func TestWalker_PanicRecovery(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(t, "example.com/target", "v1.0.0",
		"module example.com/target\ngo 1.21\nrequire example.com/dep v1.0.0\n", blobs)
	rf.add(t, "example.com/dep", "v1.0.0", "module example.com/dep\ngo 1.21\n", blobs)

	wf := newWalkerFetcher()
	wf.addRecord(t, "example.com/target", "v1.0.0")
	wf.addPanic("example.com/dep", "v1.0.0")

	w := buildWalker(rf, wf, blobs, 2)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
	})

	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	dep := outcome.PerNodeResults[coord("example.com/dep", "v1.0.0")]
	if dep.Status != domain.NodeInternalPanic {
		t.Errorf("dep status = %s, want internal_panic", dep.Status)
	}
	if dep.Error == nil || dep.Error.Type != "internal_panic" {
		t.Errorf("dep error type = %v, want internal_panic", dep.Error)
	}
	if outcome.OverallStatus == domain.WalkSucceeded {
		t.Error("expected non-succeeded walk when a dep panicked")
	}
}

// ---- shallow walk tests ----

func TestWalker_Shallow_OnlyFetchesTarget(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(t, "example.com/target", "v1.0.0",
		"module example.com/target\ngo 1.21\nrequire example.com/dep v1.0.0\n", blobs)
	// dep is NOT added; shallow walk must not fetch it.

	wf := newWalkerFetcher()
	wf.addRecord(t, "example.com/target", "v1.0.0")

	w := buildWalker(rf, wf, blobs, 1)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
		Depth:  domain.WalkDepthShallow,
	})

	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if outcome.OverallStatus != domain.WalkSucceeded {
		t.Errorf("status = %s, want succeeded", outcome.OverallStatus)
	}
	// Only the target should appear in PerNodeResults.
	if len(outcome.PerNodeResults) != 1 {
		t.Errorf("PerNodeResults count = %d, want 1", len(outcome.PerNodeResults))
	}
	if _, ok := outcome.PerNodeResults[coord("example.com/target", "v1.0.0")]; !ok {
		t.Error("target not in PerNodeResults")
	}
}

func TestWalker_Shallow_GraphIsPartial(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(t, "example.com/target", "v1.0.0",
		"module example.com/target\ngo 1.21\nrequire example.com/dep v1.0.0\n", blobs)

	wf := newWalkerFetcher()
	wf.addRecord(t, "example.com/target", "v1.0.0")

	w := buildWalker(rf, wf, blobs, 1)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
		Depth:  domain.WalkDepthShallow,
	})

	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if !outcome.Graph.Partial {
		t.Error("graph should be marked Partial for shallow walk")
	}
	if outcome.Graph.PartialReason != "shallow" {
		t.Errorf("PartialReason = %q, want %q", outcome.Graph.PartialReason, "shallow")
	}
}

func TestWalker_Shallow_TargetFetchFails(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()

	wf := newWalkerFetcher()
	wf.addFetchError("example.com/target", "v1.0.0", errors.New("proxy unavailable"))

	w := buildWalker(rf, wf, blobs, 1)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
		Depth:  domain.WalkDepthShallow,
	})

	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if outcome.OverallStatus != domain.WalkFailed {
		t.Errorf("status = %s, want failed", outcome.OverallStatus)
	}
}

// A local main module's filesystem-replaced require lands in the graph at its
// local identity. With no local fetcher wired the walker records a
// NodeLocalReplace per-node result without trying to read it, and the overall
// walk remains WalkSucceeded. (Local replaces are only honoured for the local
// main module — a fetched target's own local replaces are ignored.)
func TestWalker_ProjectLocalReplace_RecordedWithoutFetch(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()

	wf := newWalkerFetcher()

	mainGoMod := []byte(`module example.com/project

go 1.21

require example.com/dep v1.0.0

replace example.com/dep => ../local/dep
`)

	w := buildWalker(rf, wf, blobs, 1)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target:          coord("example.com/project", coordinate.LocalVersion),
		ProjectMode:     true,
		MainModuleGoMod: mainGoMod,
		ProjectDir:      "/work/project",
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	depCoord := coord("example.com/dep", coordinate.LocalVersion)
	depResult, ok := outcome.PerNodeResults[depCoord]
	if !ok {
		t.Fatalf("no PerNodeResults entry for local-replace node %s", depCoord)
	}
	if depResult.Status != domain.NodeLocalReplace {
		t.Errorf("status = %s, want local_replace", depResult.Status)
	}
	if depResult.Error == nil || depResult.Error.Type != string(domain.ResolutionLocalReplace) {
		t.Errorf("error = %+v, want type=local_replace", depResult.Error)
	}
	if outcome.OverallStatus != domain.WalkSucceeded {
		t.Errorf("overall status = %s, want succeeded", outcome.OverallStatus)
	}
}

func TestWalker_Shallow_IncludesDepNodes(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(t, "example.com/target", "v1.0.0",
		"module example.com/target\ngo 1.21\nrequire example.com/dep v1.0.0\n", blobs)

	wf := newWalkerFetcher()
	wf.addRecord(t, "example.com/target", "v1.0.0")

	w := buildWalker(rf, wf, blobs, 1)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
		Depth:  domain.WalkDepthShallow,
	})

	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	// Graph has target + dep node (dep not fetched, just listed).
	if len(outcome.Graph.Nodes) != 2 {
		t.Errorf("graph node count = %d, want 2", len(outcome.Graph.Nodes))
	}
}

// A local replacement is read from disk on every project walk, under its local
// identity: the node stays local_replace, names the require it replaces, and
// the relative path is read against the project directory.
func TestWalker_ProjectLocalReplace_AnalysedByDefault(t *testing.T) {
	blobs := newFakeBlobStore()
	lf := newFakeLocalFetcher()
	lf.addRecord(t, "example.com/dep", coordinate.LocalVersion)

	mainGoMod := []byte(`module example.com/project

go 1.21

require example.com/dep v1.0.0

replace example.com/dep => ../local/dep
`)

	w := buildWalkerWithLocal(newFakeFetcher(), newWalkerFetcher(), lf, blobs, 1)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target:          coord("example.com/project", coordinate.LocalVersion),
		ProjectMode:     true,
		MainModuleGoMod: mainGoMod,
		ProjectDir:      "/work/project",
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	depCoord := coord("example.com/dep", coordinate.LocalVersion)
	res, ok := outcome.PerNodeResults[depCoord]
	if !ok {
		t.Fatalf("no PerNodeResults entry for local-replace node %s", depCoord)
	}
	if res.Status != domain.NodeSucceeded || res.FetchRecord == nil {
		t.Errorf("result = %s (record %v), want succeeded with the local record", res.Status, res.FetchRecord != nil)
	}
	if len(lf.calls) != 1 || lf.calls[0].absPath != "/work/local/dep" || lf.calls[0].coord != depCoord {
		t.Errorf("local fetcher calls = %+v, want one read of %s from /work/local/dep", lf.calls, depCoord)
	}

	var graphNode *domain.GraphNode
	for i := range outcome.Graph.Nodes {
		if outcome.Graph.Nodes[i].Coordinate == depCoord {
			graphNode = &outcome.Graph.Nodes[i]
			break
		}
	}
	if graphNode == nil {
		t.Fatalf("dep node not found in graph")
	}
	if graphNode.ResolutionSource != domain.ResolutionLocalReplace {
		t.Errorf("ResolutionSource = %s, want local_replace", graphNode.ResolutionSource)
	}
	if graphNode.OriginalCoordinate != coord("example.com/dep", "v1.0.0") {
		t.Errorf("OriginalCoordinate = %s, want example.com/dep@v1.0.0", graphNode.OriginalCoordinate)
	}
	if outcome.OverallStatus != domain.WalkSucceeded {
		t.Errorf("overall status = %s, want succeeded", outcome.OverallStatus)
	}
}

// The record names a local replace by the path go.mod writes, never by the
// directory it was read from. A relative target is read against the project
// directory; an absolute one is read where it is, never joined onto it.
func TestWalker_ProjectLocalReplace_RecordsThePathAsWritten(t *testing.T) {
	cases := []struct{ name, projectDir, target, wantAbs string }{
		{"relative", "/some/project", "../local/dep", "/some/local/dep"},
		{"absolute", "/some/project", "/srv/local/dep", "/srv/local/dep"},
	}
	for _, tc := range cases {
		mainGoMod := []byte("module example.com/project\n\ngo 1.21\n\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep => " + tc.target + "\n")
		t.Run(tc.name, func(t *testing.T) {
			lf := newFakeLocalFetcher()
			lf.addRecord(t, "example.com/dep", coordinate.LocalVersion)
			blobs := newFakeBlobStore()
			w := buildWalkerWithLocal(newFakeFetcher(), newWalkerFetcher(), lf, blobs, 1)
			if _, err := w.Walk(context.Background(), application2.WalkRequest{
				Target:          coord("example.com/project", coordinate.LocalVersion),
				ProjectMode:     true,
				MainModuleGoMod: mainGoMod,
				ProjectDir:      tc.projectDir,
			}); err != nil {
				t.Fatalf("Walk: %v", err)
			}
			if len(lf.calls) != 1 {
				t.Fatalf("local fetcher calls = %d, want 1", len(lf.calls))
			}
			got := lf.calls[0]
			if got.writtenPath != tc.target {
				t.Errorf("writtenPath = %q, want %q, the replace target as go.mod writes it", got.writtenPath, tc.target)
			}
			if got.absPath != tc.wantAbs {
				t.Errorf("absPath = %q, want %q", got.absPath, tc.wantAbs)
			}
		})
	}
}

// A local replacement the walk could not read leaves a module of the build
// unanalysed, so the node is recorded failed and the walk partial.
func TestWalker_ProjectLocalReplace_ReadFailureIsPartial(t *testing.T) {
	lf := newFakeLocalFetcher()
	lf.addError("example.com/dep", coordinate.LocalVersion, errors.New("directory not found"))

	mainGoMod := []byte(`module example.com/project

go 1.21

require example.com/dep v1.0.0

replace example.com/dep => ../local/dep
`)

	w := buildWalkerWithLocal(newFakeFetcher(), newWalkerFetcher(), lf, newFakeBlobStore(), 1)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target:          coord("example.com/project", coordinate.LocalVersion),
		ProjectMode:     true,
		MainModuleGoMod: mainGoMod,
		ProjectDir:      "/work/project",
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	res := outcome.PerNodeResults[coord("example.com/dep", coordinate.LocalVersion)]
	if res.Status != domain.NodeFetchFailed || res.Error == nil || res.Error.Type != "local_fetch_failed" {
		t.Errorf("result = %+v, want fetch_failed of type local_fetch_failed", res)
	}
	if outcome.OverallStatus != domain.WalkPartial {
		t.Errorf("overall status = %s, want partial", outcome.OverallStatus)
	}
}

// A relative replace path with no project directory to read it against is not
// read from wherever the process happens to run: the node is recorded failed.
func TestWalker_ProjectLocalReplace_NoProjectDirIsNotGuessed(t *testing.T) {
	lf := newFakeLocalFetcher()
	lf.addRecord(t, "example.com/dep", coordinate.LocalVersion)

	mainGoMod := []byte(`module example.com/project

go 1.21

require example.com/dep v1.0.0

replace example.com/dep => ../local/dep
`)

	w := buildWalkerWithLocal(newFakeFetcher(), newWalkerFetcher(), lf, newFakeBlobStore(), 1)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target:          coord("example.com/project", coordinate.LocalVersion),
		ProjectMode:     true,
		MainModuleGoMod: mainGoMod,
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(lf.calls) != 0 {
		t.Errorf("local fetcher calls = %d, want 0", len(lf.calls))
	}
	if res := outcome.PerNodeResults[coord("example.com/dep", coordinate.LocalVersion)]; res.Status != domain.NodeFetchFailed {
		t.Errorf("status = %s, want fetch_failed", res.Status)
	}
}

// when no local fetcher is wired (nil) the node stays as NodeLocalReplace.
func TestWalker_ProjectLocalReplace_SkippedWhenNoLocalFetcher(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()

	wf := newWalkerFetcher()

	mainGoMod := []byte(`module example.com/project

go 1.21

require example.com/dep v1.0.0

replace example.com/dep => ../local/dep
`)

	w := buildWalker(rf, wf, blobs, 1) // nil localFetcher
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target:          coord("example.com/project", coordinate.LocalVersion),
		ProjectMode:     true,
		MainModuleGoMod: mainGoMod,
		ProjectDir:      "/work/project",
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	depCoord := coord("example.com/dep", coordinate.LocalVersion)
	res, ok := outcome.PerNodeResults[depCoord]
	if !ok {
		t.Fatalf("no PerNodeResults entry for local-replace node %s", depCoord)
	}
	if res.Status != domain.NodeLocalReplace {
		t.Errorf("status = %s, want local_replace (no localFetcher)", res.Status)
	}
	if outcome.OverallStatus != domain.WalkSucceeded {
		t.Errorf("overall status = %s, want succeeded", outcome.OverallStatus)
	}
}

// ---- regression ----

// productionCacheFetcher mimics production fetch semantics: the first call for
// any coordinate populates the cache and returns FromCache=false; subsequent
// calls return FromCache=true. This is the behaviour that previously caused
// per_node_results to misreport transitives as cache hits when the walker
// re-fetched them after the resolver had already populated the cache.
type productionCacheFetcher struct {
	mu      sync.Mutex
	records map[string]domain2.CompositeRecord
	seen    map[string]int // call count per key
	blobs   *fakeBlobStore
}

func newProductionCacheFetcher(blobs *fakeBlobStore) *productionCacheFetcher {
	return &productionCacheFetcher{
		records: make(map[string]domain2.CompositeRecord),
		seen:    make(map[string]int),
		blobs:   blobs,
	}
}

func (f *productionCacheFetcher) add(t testing.TB, path, version, goMod string) {
	k := wkey(path, version)
	rec := makeFactRecord(t, path, version)
	f.records[k] = mustComposeOne(t, rec)
	seedZipBlob(t, f.blobs, rec, buildFakeZip(path, version, goMod))
}

func (f *productionCacheFetcher) callCount(path, version string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen[wkey(path, version)]
}

func (f *productionCacheFetcher) EnsureFetched(_ context.Context, c coordinate.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	k := wkey(c.Path(), c.Version())
	f.mu.Lock()
	rec, ok := f.records[k]
	if !ok {
		f.mu.Unlock()
		return walkports.ModuleFetchResult{}, fmt.Errorf("no record for %s", k)
	}
	count := f.seen[k]
	f.seen[k] = count + 1
	f.mu.Unlock()
	return walkports.ModuleFetchResult{Record: rec, FromCache: count > 0}, nil
}

// buildWalkerWithProductionCache wires a Walker where both the resolver and the
// walker share the same fetcher — the production invariant. The fetcher
// populates a cache on first call so subsequent calls report FromCache=true.
func buildWalkerWithProductionCache(pf *productionCacheFetcher, blobs *fakeBlobStore) *application2.Walker {
	resolver := application2.NewGraphResolver(
		newXmodParser(), pf, blobs,
		fixedClock{fixedNow}, "",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	return application2.NewWalker(
		resolver, pf, nil,
		fixedClock{fixedNow}, fakeStopwatch{},
		2, slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
}

// TestWalker_TransitivesReportColdFetch is the regression test for
// Before the fix the walker re-fetched every successful node after
// resolution, by which time the resolver had already populated the cache —
// transitives were always reported as cache hits with duration_ms=0. The fix
// routes all fetches through a recording wrapper that captures the first-call
// outcome; the walker reads PerNodeResults from those recordings instead of
// re-fetching.
func TestWalker_TransitivesReportColdFetch(t *testing.T) {
	blobs := newFakeBlobStore()
	pf := newProductionCacheFetcher(blobs)
	pf.add(t, "example.com/target", "v1.0.0",
		"module example.com/target\ngo 1.21\nrequire example.com/dep v1.0.0\n")
	pf.add(t, "example.com/dep", "v1.0.0", "module example.com/dep\ngo 1.21\n")

	w := buildWalkerWithProductionCache(pf, blobs)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if outcome.OverallStatus != domain.WalkSucceeded {
		t.Fatalf("status = %s, want succeeded", outcome.OverallStatus)
	}

	target := outcome.PerNodeResults[coord("example.com/target", "v1.0.0")]
	dep := outcome.PerNodeResults[coord("example.com/dep", "v1.0.0")]

	if target.FromCache {
		t.Error("target.FromCache = true, want false (cold fetch)")
	}
	if dep.FromCache {
		t.Error("dep.FromCache = true, want false (cold fetch)")
	}

	// Acceptance: every module downloaded during this walk reports
	// from_cache=false. Both target and dep were uncached on entry.
	cold := 0
	for _, r := range outcome.PerNodeResults {
		if !r.FromCache {
			cold++
		}
	}
	if cold != 2 {
		t.Errorf("cold-fetch count = %d, want 2", cold)
	}

	// The fetcher must have been invoked exactly once per coordinate — the
	// fix removes the walker's post-resolution re-fetch loop.
	if got := pf.callCount("example.com/dep", "v1.0.0"); got != 1 {
		t.Errorf("dep fetcher call count = %d, want 1 (no post-resolution re-fetch)", got)
	}
}

// TestWalker_WarmCacheReportsCacheHit verifies that when a module is
// already cached on walk entry (e.g. a previous walk populated the store),
// the walker correctly reports FromCache=true.
func TestWalker_WarmCacheReportsCacheHit(t *testing.T) {
	blobs := newFakeBlobStore()
	pf := newProductionCacheFetcher(blobs)
	pf.add(t, "example.com/target", "v1.0.0",
		"module example.com/target\ngo 1.21\nrequire example.com/dep v1.0.0\n")
	pf.add(t, "example.com/dep", "v1.0.0", "module example.com/dep\ngo 1.21\n")

	// Warm the cache by fetching both modules before the walk starts.
	ctx := context.Background()
	if _, err := pf.EnsureFetched(ctx, coord("example.com/target", "v1.0.0")); err != nil {
		t.Fatalf("warm target: %v", err)
	}
	if _, err := pf.EnsureFetched(ctx, coord("example.com/dep", "v1.0.0")); err != nil {
		t.Fatalf("warm dep: %v", err)
	}

	w := buildWalkerWithProductionCache(pf, blobs)
	outcome, err := w.Walk(ctx, application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if outcome.OverallStatus != domain.WalkSucceeded {
		t.Fatalf("status = %s, want succeeded", outcome.OverallStatus)
	}
	for c, r := range outcome.PerNodeResults {
		if !r.FromCache {
			t.Errorf("%s FromCache = false, want true (warm cache)", c)
		}
	}
}

// forcingProductionFetcher extends productionCacheFetcher with the WithForce
// hook the walker uses to bypass the persistent cache on --force walks
// When force=true, EnsureFetched always reports FromCache=false
// regardless of how many times the coordinate has been fetched before, and
// the per-coord call counter still ticks so tests can verify a real re-fetch
// happened.
type forcingProductionFetcher struct {
	*productionCacheFetcher
	force bool
}

func (f *forcingProductionFetcher) WithForce(force bool) walkports.ModuleFetcher {
	return &forcingProductionFetcher{productionCacheFetcher: f.productionCacheFetcher, force: force}
}

func (f *forcingProductionFetcher) EnsureFetched(ctx context.Context, c coordinate.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	fr, err := f.productionCacheFetcher.EnsureFetched(ctx, c)
	if err != nil {
		return fr, err
	}
	if f.force {
		fr.FromCache = false
	}
	return fr, nil
}

func buildWalkerWithForcingFetcher(pf *forcingProductionFetcher, blobs *fakeBlobStore) *application2.Walker {
	resolver := application2.NewGraphResolver(
		newXmodParser(), pf, blobs,
		fixedClock{fixedNow}, "",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	return application2.NewWalker(
		resolver, pf, nil,
		fixedClock{fixedNow}, fakeStopwatch{},
		2, slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
}

// TestWalker_ForceReFetchesEveryNode is the regression test for.
// Before the fix, the walker's WalkRequest.Force was discarded (the walker's
// fetchOne explicitly dropped it via `_ = force`); the local.Fetcher adapter
// always sent Force=false to the underlying use case, so a previously-cached
// closure short-circuited at the fact-store cache check and every node was
// reported as a cache hit with duration_ms=0. The fix type-asserts against
// forceCapable and swaps in a force-mode fetcher when req.Force is set.
func TestWalker_ForceReFetchesEveryNode(t *testing.T) {
	blobs := newFakeBlobStore()
	pf := &forcingProductionFetcher{productionCacheFetcher: newProductionCacheFetcher(blobs)}
	pf.add(t, "example.com/target", "v1.0.0",
		"module example.com/target\ngo 1.21\nrequire example.com/dep v1.0.0\n")
	pf.add(t, "example.com/dep", "v1.0.0", "module example.com/dep\ngo 1.21\n")

	// Warm the closure first so the cache is fully populated.
	ctx := context.Background()
	w := buildWalkerWithForcingFetcher(pf, blobs)
	if _, err := w.Walk(ctx, application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
	}); err != nil {
		t.Fatalf("warm walk: %v", err)
	}
	preForceTargetCalls := pf.callCount("example.com/target", "v1.0.0")
	preForceDepCalls := pf.callCount("example.com/dep", "v1.0.0")

	// Now run with Force.
	outcome, err := w.Walk(ctx, application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
		Force:  true,
	})
	if err != nil {
		t.Fatalf("force walk: %v", err)
	}
	if outcome.OverallStatus != domain.WalkSucceeded {
		t.Fatalf("status = %s, want succeeded", outcome.OverallStatus)
	}
	for c, r := range outcome.PerNodeResults {
		if r.FromCache {
			t.Errorf("%s FromCache = true under --force, want false", c)
		}
	}
	if got := pf.callCount("example.com/target", "v1.0.0") - preForceTargetCalls; got != 1 {
		t.Errorf("target fetcher calls during force walk = %d, want 1 (real re-fetch)", got)
	}
	if got := pf.callCount("example.com/dep", "v1.0.0") - preForceDepCalls; got != 1 {
		t.Errorf("dep fetcher calls during force walk = %d, want 1 (real re-fetch)", got)
	}
}

// TestWalker_ForceNoOpForNonForceCapableFetcher documents the fallback:
// if the underlying fetcher does not implement WithForce, --force has no
// effect — but the walker logs a warning so the user can tell. We assert on
// the from_cache values (warm cache hits) since the test fetcher in this
// case is the plain productionCacheFetcher without WithForce.
func TestWalker_ForceNoOpForNonForceCapableFetcher(t *testing.T) {
	blobs := newFakeBlobStore()
	pf := newProductionCacheFetcher(blobs)
	pf.add(t, "example.com/target", "v1.0.0", "module example.com/target\ngo 1.21\n")

	w := buildWalkerWithProductionCache(pf, blobs)
	ctx := context.Background()
	if _, err := w.Walk(ctx, application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
	}); err != nil {
		t.Fatalf("warm walk: %v", err)
	}
	outcome, err := w.Walk(ctx, application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
		Force:  true,
	})
	if err != nil {
		t.Fatalf("force walk: %v", err)
	}
	// Non-force-capable fetcher: cache hits stay cache hits.
	target := outcome.PerNodeResults[coord("example.com/target", "v1.0.0")]
	if !target.FromCache {
		t.Error("non-force-capable fetcher returned FromCache=false; expected hit")
	}
}

// TestWalker_ForceWithCleanCache verifies that --force on an empty
// store is a normal cold walk (every node from_cache=false), not a regression.
func TestWalker_ForceWithCleanCache(t *testing.T) {
	blobs := newFakeBlobStore()
	pf := &forcingProductionFetcher{productionCacheFetcher: newProductionCacheFetcher(blobs)}
	pf.add(t, "example.com/target", "v1.0.0",
		"module example.com/target\ngo 1.21\nrequire example.com/dep v1.0.0\n")
	pf.add(t, "example.com/dep", "v1.0.0", "module example.com/dep\ngo 1.21\n")

	w := buildWalkerWithForcingFetcher(pf, blobs)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
		Force:  true,
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	for c, r := range outcome.PerNodeResults {
		if r.FromCache {
			t.Errorf("%s FromCache = true on clean-cache force walk, want false", c)
		}
	}
}

// TestWalker_MixedCacheState combines a cold target with a previously
// cached dep — the walk record should report each module's cache status
// independently. This is the realistic case for resuming partial walks.
func TestWalker_MixedCacheState(t *testing.T) {
	blobs := newFakeBlobStore()
	pf := newProductionCacheFetcher(blobs)
	pf.add(t, "example.com/target", "v1.0.0",
		"module example.com/target\ngo 1.21\nrequire example.com/dep v1.0.0\n")
	pf.add(t, "example.com/dep", "v1.0.0", "module example.com/dep\ngo 1.21\n")

	// Warm only the dep — target is still cold.
	ctx := context.Background()
	if _, err := pf.EnsureFetched(ctx, coord("example.com/dep", "v1.0.0")); err != nil {
		t.Fatalf("warm dep: %v", err)
	}

	w := buildWalkerWithProductionCache(pf, blobs)
	outcome, err := w.Walk(ctx, application2.WalkRequest{
		Target: coord("example.com/target", "v1.0.0"),
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	target := outcome.PerNodeResults[coord("example.com/target", "v1.0.0")]
	dep := outcome.PerNodeResults[coord("example.com/dep", "v1.0.0")]
	if target.FromCache {
		t.Error("target.FromCache = true, want false")
	}
	if !dep.FromCache {
		t.Error("dep.FromCache = false, want true (pre-warmed)")
	}
}

// TestWalker_ProjectMode_RootsAtLocalMainModule verifies that a project walk
// roots the graph at the local main module (unfetched, version=local) and that
// the closure is the union of the go.mod require entries.
func TestWalker_ProjectMode_RootsAtLocalMainModule(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(t, "example.com/dep", "v1.0.0", "module example.com/dep\ngo 1.21\n", blobs)

	wf := newWalkerFetcher()
	wf.addRecord(t, "example.com/dep", "v1.0.0")

	mainGoMod := []byte("module example.com/project\ngo 1.21\nrequire example.com/dep v1.0.0\n")
	target := coordinatetest.MustNew("example.com/project", coordinate.LocalVersion)

	w := buildWalker(rf, wf, blobs, 2)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target:          target,
		ProjectMode:     true,
		MainModuleGoMod: mainGoMod,
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if outcome.OverallStatus != domain.WalkSucceeded {
		t.Fatalf("status = %s, want succeeded", outcome.OverallStatus)
	}

	// Root identity: the local main module anchors the graph.
	if outcome.Graph.Target != target {
		t.Errorf("graph target = %s, want %s", outcome.Graph.Target, target)
	}
	var root domain.GraphNode
	foundRoot := false
	for _, n := range outcome.Graph.Nodes {
		if n.Coordinate == target {
			root, foundRoot = n, true
		}
	}
	if !foundRoot {
		t.Fatalf("main module node %s absent from graph", target)
	}
	if root.ResolutionSource != domain.ResolutionLocalMainModule {
		t.Errorf("root source = %s, want local_main_module", root.ResolutionSource)
	}

	// The root is unfetched: a succeeded node with no fetch record.
	tr := outcome.PerNodeResults[target]
	if tr.Status != domain.NodeSucceeded {
		t.Errorf("root status = %s, want succeeded", tr.Status)
	}
	if tr.FetchRecord != nil {
		t.Errorf("root carries a fetch record, want none (local main module)")
	}

	// Closure includes the require.
	if _, ok := outcome.PerNodeResults[coord("example.com/dep", "v1.0.0")]; !ok {
		t.Errorf("require example.com/dep missing from closure")
	}
	// The project walk injects the synthetic standard-library node, recorded as a
	// succeeded node with no fetch record (it is toolchain-provided, never fetched).
	assertStdlibNodeUnfetched(t, outcome)
	if len(outcome.Graph.Nodes) != 3 {
		t.Errorf("node count = %d, want 3 (main module + dep + stdlib)", len(outcome.Graph.Nodes))
	}
}

// assertStdlibNodeUnfetched checks the graph holds a succeeded stdlib node
// carrying no fetch record.
func assertStdlibNodeUnfetched(t *testing.T, outcome domain.WalkOutcome) {
	t.Helper()
	var stdCoord domain.GraphNode
	foundStd := false
	for _, n := range outcome.Graph.Nodes {
		if n.ResolutionSource == domain.ResolutionStdlib {
			stdCoord, foundStd = n, true
		}
	}
	if !foundStd {
		t.Fatalf("stdlib node absent from project graph")
	}
	sr := outcome.PerNodeResults[stdCoord.Coordinate]
	if sr.Status != domain.NodeSucceeded {
		t.Errorf("stdlib node status = %s, want succeeded", sr.Status)
	}
	if sr.FetchRecord != nil {
		t.Errorf("stdlib node carries a fetch record, want none (toolchain-provided)")
	}
}

// EnsureFetchedReplacing delegates: this fake has no replace-aware behaviour of
// its own, so a replaced module is fetched exactly like an unreplaced one.
func (f *walkerFakeFetcher) EnsureFetchedReplacing(ctx context.Context, c, _ coordinate.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	return f.EnsureFetched(ctx, c)
}

// EnsureFetchedReplacing delegates: this fake has no replace-aware behaviour of
// its own, so a replaced module is fetched exactly like an unreplaced one.
func (f *productionCacheFetcher) EnsureFetchedReplacing(ctx context.Context, c, _ coordinate.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	return f.EnsureFetched(ctx, c)
}

// EnsureFetchedReplacing delegates: this fake has no replace-aware behaviour of
// its own, so a replaced module is fetched exactly like an unreplaced one.
func (f *forcingProductionFetcher) EnsureFetchedReplacing(ctx context.Context, c, _ coordinate.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	return f.EnsureFetched(ctx, c)
}
