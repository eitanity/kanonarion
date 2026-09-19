package application_test

import (
	"context"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/callgraph/application"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// TestTraverseCallers_TruncationIsTheFrontierNotTheBound is the whole of the
// truncation decision, at the boundary that decides it.
//
// layeredCallers expands over four levels. At depth 3 the walk stops holding
// the seven c-symbols it had discovered and not expanded; at depth 4 it expands
// them, finds nothing beyond, and exits with an empty frontier. Both answers
// carry the SAME fifteen nodes — so a marker derived from the node count, or
// from a second run's, cannot tell them apart, and one derived from "--depth
// was given" would mark them both.
//
// The unexpanded frontier tells them apart exactly, which is why it is the
// signal.
func TestTraverseCallers_TruncationIsTheFrontierNotTheBound(t *testing.T) {
	ctx := context.Background()
	graph := layeredCallers()

	cut, err := application.NewQueryCallGraphUseCase(&frontierBatchFake{frontierFake{callers: graph}}).
		TraverseCallers(ctx, traversal(3))
	if err != nil {
		t.Fatalf("depth 3: %v", err)
	}
	whole, err := application.NewQueryCallGraphUseCase(&frontierBatchFake{frontierFake{callers: graph}}).
		TraverseCallers(ctx, traversal(4))
	if err != nil {
		t.Fatalf("depth 4: %v", err)
	}

	if !reflect.DeepEqual(cut.Nodes, whole.Nodes) {
		t.Fatalf("the fixture no longer pins the boundary: depth 3 found %d nodes and depth 4 found %d; "+
			"the case is only a boundary while the two answers are identical", len(cut.Nodes), len(whole.Nodes))
	}
	if !cut.Truncated {
		t.Error("depth 3 stopped with seven symbols unexpanded and did not say so")
	}
	if whole.Truncated {
		t.Error("depth 4 reached the closure and was still marked truncated — a marker that fires on every bound is as wrong as one that never fires")
	}
}

// TestTraverseCallees_TruncationIsTheFrontierNotTheBound pins the same property
// on the other direction, which has its own frontier query and its own fallback.
func TestTraverseCallees_TruncationIsTheFrontierNotTheBound(t *testing.T) {
	ctx := context.Background()
	graph := layeredCallers()

	cut, err := application.NewQueryCallGraphUseCase(&frontierBatchFake{frontierFake{callees: graph}}).
		TraverseCallees(ctx, traversal(3))
	if err != nil {
		t.Fatalf("depth 3: %v", err)
	}
	whole, err := application.NewQueryCallGraphUseCase(&frontierBatchFake{frontierFake{callees: graph}}).
		TraverseCallees(ctx, traversal(4))
	if err != nil {
		t.Fatalf("depth 4: %v", err)
	}
	if !cut.Truncated {
		t.Error("depth 3 stopped with seven symbols unexpanded and did not say so")
	}
	if whole.Truncated {
		t.Error("depth 4 reached the closure and was still marked truncated")
	}
}

// TestTraverse_UnboundedIsNeverTruncated: --depth 0 expands until the frontier
// empties, so the only answer it can give is the closure. This is what makes
// "--depth 0" a remedy the answer can name.
func TestTraverse_UnboundedIsNeverTruncated(t *testing.T) {
	ctx := context.Background()
	for _, depth := range []int{0, 4, 5, 99} {
		res, err := application.NewQueryCallGraphUseCase(&frontierBatchFake{frontierFake{callers: layeredCallers()}}).
			TraverseCallers(ctx, traversal(depth))
		if err != nil {
			t.Fatalf("depth %d: %v", depth, err)
		}
		if res.Truncated {
			t.Errorf("depth %d reached the closure and reported itself truncated", depth)
		}
	}
}

// TestTraverse_TruncatedAlwaysCarriesNodes is the invariant the CLI renderer
// relies on, so it is pinned here rather than assumed there.
//
// A walk that exits truncated queued at least one symbol, and a symbol is
// queued only after it joins the visited set, so the node list cannot be empty.
// Truncated-with-no-nodes would render a measured absence under a notice saying
// more exist — two statements that contradict each other. The only bound that
// could produce it is a negative one, which is refused at the flag; if that loop
// condition is ever rewritten, this fails.
func TestTraverse_TruncatedAlwaysCarriesNodes(t *testing.T) {
	for _, depth := range []int{0, 1, 2, 3, 4, 5, 99} {
		res, err := application.NewQueryCallGraphUseCase(&frontierBatchFake{frontierFake{callers: layeredCallers()}}).
			TraverseCallers(context.Background(), traversal(depth))
		if err != nil {
			t.Fatalf("depth %d: %v", depth, err)
		}
		if res.Truncated && len(res.Nodes) == 0 {
			t.Errorf("depth %d reported truncated with no nodes: the renderer would state an absence and a bound at once", depth)
		}
	}
}

// recordingProgress captures every narration call so the test reads what the
// traversal reported rather than that it reported something.
//
// It locks because Advance is called from the traversal's narration goroutine
// while the test goroutine reads: the reporter is the seam where the two meet,
// and an unguarded slice here would be a race in the test rather than in the
// code under it.
type recordingProgress struct {
	mu    sync.Mutex
	calls [][2]int
}

func (p *recordingProgress) Advance(depth, visited int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, [2]int{depth, visited})
}

func (p *recordingProgress) snapshot() [][2]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([][2]int(nil), p.calls...)
}

var _ cgports.TraversalProgressReporter = (*recordingProgress)(nil)

// heldFrontier holds one level open inside the store until the test releases
// it, which is the shape of the wait the narration exists for: the traversal is
// not between levels, it is inside a set query that has not returned.
//
// fail makes the held call refuse when it is released, so the narration's
// shutdown is exercised on the error path as well as the plain one.
type heldFrontier struct {
	frontierFake
	holdCall int
	fail     bool

	entered chan struct{}
	release chan struct{}
	calls   int
	once    sync.Once
}

func newHeldFrontier(graph map[string][]string, holdCall int, fail bool) *heldFrontier {
	return &heldFrontier{
		frontierFake: frontierFake{callers: graph},
		holdCall:     holdCall,
		fail:         fail,
		entered:      make(chan struct{}),
		release:      make(chan struct{}),
	}
}

// hold blocks the holdCall'th query until the test lets it go. Every other call
// passes straight through, so only the level under test is slow.
func (s *heldFrontier) hold() error {
	s.calls++
	if s.calls != s.holdCall {
		return nil
	}
	s.once.Do(func() { close(s.entered) })
	<-s.release
	if s.fail {
		return errStoreRefused
	}
	return nil
}

func (s *heldFrontier) FindCallersOfEach(_ context.Context, syms []string, _ string, _ coordinate.ModuleSet, _ cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
	if err := s.hold(); err != nil {
		return nil, err
	}
	var out []cgports.CallEdgeRef
	for _, sym := range syms {
		out = append(out, edgesTo(s.callers, sym, true)...)
	}
	return out, nil
}

func (s *heldFrontier) FindCalleesOfEach(_ context.Context, _ []string, _ string, _ coordinate.ModuleSet, _ cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
	return nil, nil
}

var (
	_ cgports.CallGraphStore          = (*heldFrontier)(nil)
	_ cgports.CallGraphFrontierFinder = (*heldFrontier)(nil)
)

// awaitNarration waits for the reporter to have recorded at least n lines.
func awaitNarration(t *testing.T, rec *recordingProgress, n int, interval time.Duration) [][2]int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if got := rec.snapshot(); len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited 10s for %d narration lines and saw %d: the traversal is silent while a level is still running", n, len(rec.snapshot()))
		}
		time.Sleep(interval / 2)
	}
}

// TestTraverse_NarratesWhileALevelIsStillRunning is the whole of the decision.
//
// The traversal is held inside its FIRST store query — it has reached no level
// boundary and never will until the test releases it — and it must still say so
// on the interval. A reporter called only at level boundaries prints exactly
// nothing here, which is the six-minute silence this replaced.
//
// "depth 1, 0 symbols visited" is the expected line and is a true statement: the
// first level has not come back yet.
func TestTraverse_NarratesWhileALevelIsStillRunning(t *testing.T) {
	const interval = 20 * time.Millisecond
	store := newHeldFrontier(layeredCallers(), 1, false)
	rec := &recordingProgress{}

	req := traversal(0)
	req.Progress = rec
	req.ProgressInterval = interval

	done := make(chan error, 1)
	go func() {
		_, err := application.NewQueryCallGraphUseCase(store).TraverseCallers(context.Background(), req)
		done <- err
	}()

	<-store.entered
	got := awaitNarration(t, rec, 2, interval)
	for _, c := range got {
		if c != [2]int{1, 0} {
			t.Errorf("narrated %v while the first level was still in the store, want [1 0]", c)
		}
	}

	close(store.release)
	if err := <-done; err != nil {
		t.Fatalf("released traversal: %v", err)
	}
}

// TestTraverse_NarrationCarriesTheLevelInFlight: the two numbers are the
// traversal's own, not a tick count. Level 2 is held, and by then three symbols
// have been visited.
func TestTraverse_NarrationCarriesTheLevelInFlight(t *testing.T) {
	const interval = 20 * time.Millisecond
	store := newHeldFrontier(layeredCallers(), 2, false)
	rec := &recordingProgress{}

	req := traversal(0)
	req.Progress = rec
	req.ProgressInterval = interval

	done := make(chan error, 1)
	go func() {
		_, err := application.NewQueryCallGraphUseCase(store).TraverseCallers(context.Background(), req)
		done <- err
	}()

	<-store.entered
	got := awaitNarration(t, rec, 2, interval)
	last := got[len(got)-1]
	if last != [2]int{2, 3} {
		t.Errorf("narrated %v while level 2 was in the store, want [2 3]", last)
	}

	close(store.release)
	if err := <-done; err != nil {
		t.Fatalf("released traversal: %v", err)
	}
}

// TestTraverse_ShorterThanTheIntervalNarratesNothing: the narration is for a
// wait the operator is already sitting through. A traversal that finishes inside
// the interval is not one, and printing there would make every fast read noisy.
func TestTraverse_ShorterThanTheIntervalNarratesNothing(t *testing.T) {
	rec := &recordingProgress{}
	req := traversal(0)
	req.Progress = rec
	req.ProgressInterval = time.Hour

	if _, err := application.NewQueryCallGraphUseCase(&frontierBatchFake{frontierFake{callers: layeredCallers()}}).
		TraverseCallers(context.Background(), req); err != nil {
		t.Fatalf("traversal: %v", err)
	}
	if got := rec.snapshot(); len(got) != 0 {
		t.Errorf("a traversal shorter than the interval narrated %v", got)
	}
}

// TestTraverse_NarrationStopsOnEveryPath: the ticker must not outlive the call
// and must not leak a goroutine, on the path that returns an answer and on the
// path that returns an error.
//
// Stopping is asserted by the count standing still across many intervals after
// the traversal has returned — a goroutine that survived would keep writing, and
// in production it would be writing to a stderr the command has finished with.
func TestTraverse_NarrationStopsOnEveryPath(t *testing.T) {
	const interval = 5 * time.Millisecond
	for _, tc := range []struct {
		name string
		fail bool
	}{
		{"answered", false},
		{"refused", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := runtime.NumGoroutine()
			store := newHeldFrontier(layeredCallers(), 1, tc.fail)
			rec := &recordingProgress{}

			req := traversal(0)
			req.Progress = rec
			req.ProgressInterval = interval

			done := make(chan error, 1)
			go func() {
				_, err := application.NewQueryCallGraphUseCase(store).TraverseCallers(context.Background(), req)
				done <- err
			}()

			<-store.entered
			awaitNarration(t, rec, 2, interval)
			close(store.release)

			err := <-done
			if tc.fail != (err != nil) {
				t.Fatalf("error = %v, want an error: %v", err, tc.fail)
			}

			at := len(rec.snapshot())
			time.Sleep(20 * interval)
			if after := len(rec.snapshot()); after != at {
				t.Errorf("the ticker outlived the traversal: %d lines at return, %d a moment later", at, after)
			}

			deadline := time.Now().Add(5 * time.Second)
			for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
				time.Sleep(interval)
			}
			if leaked := runtime.NumGoroutine() - before; leaked > 0 {
				t.Errorf("the traversal left %d goroutine(s) running", leaked)
			}
		})
	}
}

// TestTraverse_NilProgressNarratesNothing: nil is what every caller that wants
// no output passes, and it must not be a nil-pointer dereference inside the
// loop.
func TestTraverse_NilProgressNarratesNothing(t *testing.T) {
	req := traversal(0)
	req.Progress = nil
	if _, err := application.NewQueryCallGraphUseCase(&frontierBatchFake{frontierFake{callers: layeredCallers()}}).
		TraverseCallers(context.Background(), req); err != nil {
		t.Fatalf("traversal with no reporter: %v", err)
	}
}

// failingStore answers the first level and then refuses, so the fault seam
// inside the loop is exercised rather than assumed. batch decides which of the
// two routes the traversal takes.
type failingStore struct {
	frontierFake
	asked int
}

var errStoreRefused = errors.New("the edge table refused")

func (s *failingStore) FindCallers(ctx context.Context, sym, pv string, scope coordinate.ModuleSet, opts cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
	s.asked++
	if s.asked > 1 {
		return nil, errStoreRefused
	}
	return s.frontierFake.FindCallers(ctx, sym, pv, scope, opts)
}

func (s *failingStore) FindCallersOfEach(_ context.Context, syms []string, _ string, _ coordinate.ModuleSet, _ cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
	s.asked++
	if s.asked > 1 {
		return nil, errStoreRefused
	}
	var out []cgports.CallEdgeRef
	for _, sym := range syms {
		out = append(out, edgesTo(s.callers, sym, true)...)
	}
	return out, nil
}

// FindCalleesOfEach completes the capability; the cases here follow callers.
func (s *failingStore) FindCalleesOfEach(_ context.Context, syms []string, _ string, _ coordinate.ModuleSet, _ cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
	s.asked++
	if s.asked > 1 {
		return nil, errStoreRefused
	}
	var out []cgports.CallEdgeRef
	for _, sym := range syms {
		out = append(out, edgesTo(s.callees, sym, false)...)
	}
	return out, nil
}

// TestTraverse_StoreFailureNamesTheDepthAndReturnsNoAnswer.
//
// A traversal that cannot finish must not hand back the levels it did manage:
// a half-expanded walk is indistinguishable from a bounded one once it leaves
// this function, and the caller would render it as an answer. The error names
// the level so an operator can see how far it got, and both routes — the set
// query and the per-symbol fallback — are checked, because each has its own
// call site inside the loop.
func TestTraverse_StoreFailureNamesTheDepthAndReturnsNoAnswer(t *testing.T) {
	for _, tc := range []struct {
		name  string
		batch bool
	}{{"set query", true}, {"per-symbol fallback", false}} {
		t.Run(tc.name, func(t *testing.T) {
			store := &failingStore{frontierFake: frontierFake{callers: layeredCallers()}}
			var uc *application.QueryCallGraphUseCase
			if tc.batch {
				uc = application.NewQueryCallGraphUseCase(store)
			} else {
				uc = application.NewQueryCallGraphUseCase(&plainFailingStore{store})
			}
			res, err := uc.TraverseCallers(context.Background(), traversal(0))
			if err == nil {
				t.Fatal("a refused edge query was reported as an answer")
			}
			if !errors.Is(err, errStoreRefused) {
				t.Errorf("the store's reason did not survive: %v", err)
			}
			if !strings.Contains(err.Error(), "depth 2") {
				t.Errorf("the error does not name the level it failed at: %v", err)
			}
			if res.Nodes != nil || res.Edges != nil || res.Truncated {
				t.Errorf("a failed traversal returned a partial answer: %+v", res)
			}
		})
	}
}

// plainFailingStore hides the set query so the traversal takes the per-symbol
// fallback against the same failure.
type plainFailingStore struct{ s *failingStore }

func (p *plainFailingStore) PutCallGraphRecord(ctx context.Context, r domain.CallGraphRecord) error {
	return p.s.PutCallGraphRecord(ctx, r)
}

func (p *plainFailingStore) GetCallGraphRecord(ctx context.Context, c coordinate.ModuleCoordinate, pv string) (domain.CallGraphRecord, bool, error) {
	return p.s.GetCallGraphRecord(ctx, c, pv)
}

func (p *plainFailingStore) ListCallGraphRecords(ctx context.Context, f cgports.CallGraphFilter) ([]cgports.CallGraphSummary, error) {
	return p.s.ListCallGraphRecords(ctx, f)
}

func (p *plainFailingStore) FindCallers(ctx context.Context, sym, pv string, scope coordinate.ModuleSet, opts cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
	return p.s.FindCallers(ctx, sym, pv, scope, opts)
}

func (p *plainFailingStore) FindCallees(ctx context.Context, sym, pv string, scope coordinate.ModuleSet, opts cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
	return p.s.FindCallees(ctx, sym, pv, scope, opts)
}

var (
	_ cgports.CallGraphStore          = (*failingStore)(nil)
	_ cgports.CallGraphFrontierFinder = (*failingStore)(nil)
	_ cgports.CallGraphStore          = (*plainFailingStore)(nil)
)
