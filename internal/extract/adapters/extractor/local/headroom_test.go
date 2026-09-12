package local

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/childproc"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/extract/domain"
	"github.com/eitanity/kanonarion/internal/extract/ports"
	"github.com/eitanity/kanonarion/internal/failurecause"
)

// varyingHostMemory reports whatever the test last set, so a run can be told the
// host filled up between one analysis and the next — which is the condition the
// gate exists for and the one a bound sized at start-up cannot see.
type varyingHostMemory struct {
	available atomic.Uint64
	reads     atomic.Int64
	err       error
}

func (v *varyingHostMemory) AvailableBytes() (uint64, error) {
	v.reads.Add(1)
	if v.err != nil {
		return 0, v.err
	}
	return v.available.Load(), nil
}

func extractedOutcome() staticCallGraphReader {
	return staticCallGraphReader{out: cgports.CallGraphOutcome{
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		ContentHash:   "hash",
	}}
}

// TestCallgraphHeadroom_HoldsTheSecondAnalysisBackOnAStarvedHost is the gate's
// whole point: the bound is four, the host cannot fund a second analysis, and
// only one runs.
//
// Repeated, because the defect it guards is a race. Claiming the run by reading
// the count and then incrementing it lets two workers each see an idle run and
// both start, and that window is two instructions wide, so a single round
// misses it more often than not. Measured against the defect deliberately
// planted back in: thirty rounds caught it two runs in three, a hundred caught
// it in every one.
func TestCallgraphHeadroom_HoldsTheSecondAnalysisBackOnAStarvedHost(t *testing.T) {
	const rounds = 100
	var read bool
	for round := range rounds {
		exec := &countingExecutor{release: make(chan struct{})}
		mem := &varyingHostMemory{}
		mem.available.Store(CallgraphBudgetBytes - 1)

		adapter := newCallgraphAdapter(exec, extractedOutcome()).
			WithCallgraphConcurrency(4).
			WithHostMemory(mem)
		adapter.cgPoll = time.Millisecond

		// waitFor 1, not 4: on a starved host only one analysis may be in flight,
		// so waiting for more is waiting for the defect.
		if peak := peakConcurrency(t, adapter, exec, 32, 1); peak != 1 {
			t.Fatalf("round %d: %d analyses ran at once on a host with less than one budget free, want 1",
				round, peak)
		}
		read = read || mem.reads.Load() > 0
	}
	if !read {
		t.Error("the host was never read, so nothing gated anything")
	}
}

// The control for the test above: the same bound, the same eight modules, and a
// host with room runs four at once. Without this, a gate that simply serialised
// everything would pass.
func TestCallgraphHeadroom_AHostWithRoomStillRunsTheFullBound(t *testing.T) {
	exec := &countingExecutor{release: make(chan struct{})}
	mem := &varyingHostMemory{}
	mem.available.Store(64 * CallgraphBudgetBytes)

	adapter := newCallgraphAdapter(exec, extractedOutcome()).
		WithCallgraphConcurrency(4).
		WithHostMemory(mem)

	if peak := peakConcurrency(t, adapter, exec, 8, 4); peak != 4 {
		t.Fatalf("%d analyses ran at once on a host with room, want the full bound of 4", peak)
	}
}

// A host that stays starved for the whole run must still analyse every module,
// one at a time. A gate that could stop every worker at once would turn a tight
// host into a hang, which is worse than the memory it was avoiding.
func TestCallgraphHeadroom_APermanentlyStarvedHostStillFinishesEveryModule(t *testing.T) {
	exec := &fakeSubprocessExecutor{}
	mem := &varyingHostMemory{}
	mem.available.Store(0)

	adapter := newCallgraphAdapter(exec, extractedOutcome()).
		WithCallgraphConcurrency(4).
		WithHostMemory(mem)

	const modules = 12
	var wg sync.WaitGroup
	var succeeded atomic.Int64
	for i := range modules {
		wg.Go(func() {
			coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
			if err != nil {
				t.Errorf("building the coordinate: %v", err)
				return
			}
			_ = i
			res, eerr := adapter.Extract(t.Context(), coord, "callgraph", false, "")
			if eerr != nil {
				t.Errorf("Extract returned error: %v", eerr)
				return
			}
			if res.Status == domain.StageSucceeded {
				succeeded.Add(1)
			}
		})
	}
	wg.Wait()
	if got := succeeded.Load(); got != modules {
		t.Fatalf("%d of %d modules were analysed on a permanently starved host, want all of them", got, modules)
	}
}

// An unreadable host is "unknown", never a budget of zero: refusing to run
// because the memory could not be measured would turn a diagnostic gap into an
// outage.
func TestCallgraphHeadroom_AnUnreadableHostDoesNotGate(t *testing.T) {
	exec := &countingExecutor{release: make(chan struct{})}
	mem := &varyingHostMemory{err: errors.New("no /proc/meminfo here")}

	adapter := newCallgraphAdapter(exec, extractedOutcome()).
		WithCallgraphConcurrency(4).
		WithHostMemory(mem)

	if peak := peakConcurrency(t, adapter, exec, 8, 4); peak != 4 {
		t.Fatalf("%d analyses ran at once with an unreadable host, want the full bound of 4", peak)
	}
}

// An adapter with no reporter behaves exactly as it did before the gate existed.
func TestCallgraphHeadroom_NoReporterDoesNotGate(t *testing.T) {
	exec := &countingExecutor{release: make(chan struct{})}
	adapter := newCallgraphAdapter(exec, extractedOutcome()).WithCallgraphConcurrency(3)

	if peak := peakConcurrency(t, adapter, exec, 8, 3); peak != 3 {
		t.Fatalf("%d analyses ran at once with no host-memory reporter, want the bound of 3", peak)
	}
}

func TestCallgraphHeadroom_SaysWhyItIsWaiting(t *testing.T) {
	exec := &countingExecutor{release: make(chan struct{})}
	mem := &varyingHostMemory{}
	mem.available.Store(CallgraphBudgetBytes - 1)

	var logged lockedBuffer
	adapter := newCallgraphAdapter(exec, extractedOutcome()).
		WithCallgraphConcurrency(4).
		WithHostMemory(mem).
		WithLogger(slog.New(slog.NewTextHandler(&logged, nil)))

	if peak := peakConcurrency(t, adapter, exec, 8, 1); peak != 1 {
		t.Fatalf("%d analyses ran at once, want 1", peak)
	}
	for _, want := range []string{"callgraph_analysis_waiting_for_memory", "available_bytes", "per_subprocess_budget_bytes"} {
		if !strings.Contains(logged.String(), want) {
			t.Errorf("a run that waited for memory did not say %q: %s", want, logged.String())
		}
	}
}

// lockedBuffer is a bytes.Buffer several worker goroutines may log into.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p) //nolint:wrapcheck // a test sink; the error is bytes.Buffer's, which never fails
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// TestCallgraph_OutOfMemoryHasAProducer covers the status that sat in the type
// with nothing writing it.
//
// The producer is in the PARENT, about a child it saw ended by a signal that
// neither of its own deadlines explains. A process the kernel ends writes
// nothing, so a status it had to record itself could never describe the failure
// it was named for.
func TestCallgraph_OutOfMemoryHasAProducer(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("building the coordinate: %v", err)
	}

	exec := &fakeSubprocessExecutor{err: errors.New("signal: killed")}
	adapter := newCallgraphAdapter(exec, extractedOutcome())

	res, eerr := adapter.Extract(t.Context(), coord, "callgraph", false, "")
	if eerr != nil {
		t.Fatalf("Extract failed: %v", eerr)
	}
	if res.Status != domain.StageFailed {
		t.Fatalf("Status = %v, want Failed", res.Status)
	}
	if !strings.Contains(res.Error, "status="+cgdomain.CallGraphStatusOutOfMemory.String()) {
		t.Errorf("Error = %q, want it to name status=OutOfMemory", res.Error)
	}
	if res.Cause != failurecause.Environment {
		t.Errorf("Cause = %q, want environment: it describes this host, never the published bytes", res.Cause)
	}
}

// The control: the other ways a child can end must NOT be reported as memory.
// A status that every failure produces says nothing, and the two deadlines have
// different remedies from the kernel's.
func TestCallgraph_OnlyAnUnexplainedKillIsOutOfMemory(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("building the coordinate: %v", err)
	}

	cases := []struct {
		name string
		err  error
	}{
		{"stalled", errors.New("child stalled: " + childproc.ErrStalled.Error())},
		{"ceiling", childproc.ErrCeiling},
		{"cancelled", context.Canceled},
		{"a plain non-zero exit", fakeExitStatus{code: 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exec := &fakeSubprocessExecutor{err: tc.err}
			res, eerr := newCallgraphAdapter(exec, extractedOutcome()).Extract(t.Context(), coord, "callgraph", false, "")
			if eerr != nil {
				t.Fatalf("Extract failed: %v", eerr)
			}
			if strings.Contains(res.Error, "status="+cgdomain.CallGraphStatusOutOfMemory.String()) {
				t.Errorf("%s was reported as OutOfMemory: %q", tc.name, res.Error)
			}
		})
	}
}

// A run ended while a worker is waiting for the host records that the analysis
// never started, rather than starting one nothing will read.
func TestCallgraphHeadroom_ARunEndedWhileWaitingRecordsThatItNeverStarted(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("building the coordinate: %v", err)
	}

	exec := &countingExecutor{release: make(chan struct{})}
	mem := &varyingHostMemory{}
	mem.available.Store(CallgraphBudgetBytes - 1)

	adapter := newCallgraphAdapter(exec, extractedOutcome()).
		WithCallgraphConcurrency(4).
		WithHostMemory(mem)
	adapter.cgPoll = time.Millisecond

	ctx, cancel := context.WithCancel(t.Context())

	// One analysis holds the run busy, so the second has to wait for headroom
	// that never arrives.
	var held sync.WaitGroup
	held.Go(func() {
		if _, eerr := adapter.Extract(ctx, coord, "callgraph", false, ""); eerr != nil {
			t.Errorf("the holding analysis returned an error: %v", eerr)
		}
	})
	for exec.inFlight.Load() < 1 {
		runtime.Gosched()
	}

	waited := make(chan ports.StageResult, 1)
	go func() {
		res, eerr := adapter.Extract(ctx, coord, "callgraph", false, "")
		if eerr != nil {
			t.Errorf("the waiting analysis returned an error: %v", eerr)
		}
		waited <- res
	}()
	// Let the waiter reach the gate before the run ends.
	for mem.reads.Load() == 0 {
		runtime.Gosched()
	}
	cancel()

	res := <-waited
	if res.Status != domain.StageFailed {
		t.Errorf("Status = %v, want Failed", res.Status)
	}
	if !strings.Contains(res.Error, "the run ended before the analysis could start") {
		t.Errorf("Error = %q, want it to say the analysis never started", res.Error)
	}
	if res.Cause != failurecause.Environment {
		t.Errorf("Cause = %q, want environment", res.Cause)
	}

	close(exec.release)
	held.Wait()
}
