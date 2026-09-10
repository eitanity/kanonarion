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

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	exapp "github.com/eitanity/kanonarion/internal/example/application"
	exdomain "github.com/eitanity/kanonarion/internal/example/domain"
	"github.com/eitanity/kanonarion/internal/extract/domain"
	"github.com/eitanity/kanonarion/internal/failurecause"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
)

// stubHostMemory is an injectable HostMemory. The host's own /proc/meminfo is
// not a fixture a test can vary, so the reading is supplied here.
type stubHostMemory struct {
	available uint64
	err       error
}

func (s stubHostMemory) AvailableBytes() (uint64, error) {
	if s.err != nil {
		return 0, s.err
	}
	return s.available, nil
}

func cpuCapForHost() int { return min(runtime.NumCPU(), CallgraphCPUCap) }

func debugLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestResolveCallgraphConcurrency_RequestedValueIsTakenAsGiven(t *testing.T) {
	var buf bytes.Buffer
	got := ResolveCallgraphConcurrency(7, stubHostMemory{available: 1}, debugLogger(&buf))
	if got != 7 {
		t.Fatalf("ResolveCallgraphConcurrency(7) on a memory-starved host = %d, want the requested 7", got)
	}
}

func TestResolveCallgraphConcurrency_AmpleMemoryLeavesTheCPUCap(t *testing.T) {
	var buf bytes.Buffer
	want := cpuCapForHost()
	mem := stubHostMemory{available: uint64(CallgraphCPUCap+4) * CallgraphBudgetBytes}
	if got := ResolveCallgraphConcurrency(0, mem, debugLogger(&buf)); got != want {
		t.Fatalf("ResolveCallgraphConcurrency(0) with ample memory = %d, want min(NumCPU, %d) = %d", got, CallgraphCPUCap, want)
	}
	if strings.Contains(buf.String(), "capped by available memory") {
		t.Errorf("a host with room said it was capped by memory: %s", buf.String())
	}
}

func TestResolveCallgraphConcurrency_TooLittleMemoryForOneBudgetStillAdmitsOne(t *testing.T) {
	var buf bytes.Buffer
	mem := stubHostMemory{available: CallgraphBudgetBytes - 1}
	if got := ResolveCallgraphConcurrency(0, mem, debugLogger(&buf)); got != 1 {
		t.Fatalf("ResolveCallgraphConcurrency(0) with %d bytes available = %d, want 1", CallgraphBudgetBytes-1, got)
	}
	for _, want := range []string{"capped by available memory", "available_bytes", "per_subprocess_budget_bytes", "callgraph_workers=1"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the capped log does not say %q: %s", want, buf.String())
		}
	}
}

func TestResolveCallgraphConcurrency_UnreadableMemoryFallsBackToTheCPUCap(t *testing.T) {
	var buf bytes.Buffer
	want := cpuCapForHost()
	mem := stubHostMemory{err: errors.New("no /proc/meminfo here")}
	if got := ResolveCallgraphConcurrency(0, mem, debugLogger(&buf)); got != want {
		t.Fatalf("ResolveCallgraphConcurrency(0) with an unreadable reading = %d, want the CPU cap %d", got, want)
	}
	if !strings.Contains(buf.String(), "available memory unreadable") {
		t.Errorf("the fallback was not stated: %s", buf.String())
	}
}

func TestResolveCallgraphConcurrency_NoReporterFallsBackToTheCPUCap(t *testing.T) {
	var buf bytes.Buffer
	want := cpuCapForHost()
	if got := ResolveCallgraphConcurrency(0, nil, debugLogger(&buf)); got != want {
		t.Fatalf("ResolveCallgraphConcurrency(0) with no reporter = %d, want the CPU cap %d", got, want)
	}
	if !strings.Contains(buf.String(), "no host-memory reporter wired") {
		t.Errorf("the fallback was not stated: %s", buf.String())
	}
}

func TestResolveCallgraphConcurrency_NilLoggerDoesNotPanic(t *testing.T) {
	if got := ResolveCallgraphConcurrency(0, stubHostMemory{available: CallgraphBudgetBytes - 1}, nil); got != 1 {
		t.Fatalf("ResolveCallgraphConcurrency with a nil logger = %d, want 1", got)
	}
}

// countingExecutor records the highest number of Execute calls in flight at
// once. It is what the bound is measured against: the semaphore's job is a
// property of the subprocesses running together, not of the field's value.
type countingExecutor struct {
	inFlight atomic.Int64
	peak     atomic.Int64
	release  chan struct{}
}

func (c *countingExecutor) Execute(ctx context.Context, args []string) ([]byte, error) {
	now := c.inFlight.Add(1)
	for {
		peak := c.peak.Load()
		if now <= peak || c.peak.CompareAndSwap(peak, now) {
			break
		}
	}
	// The context is honoured so a defect that lets an un-admitted stage through
	// fails on the assertion rather than by waiting for the package deadline.
	select {
	case <-c.release:
	case <-ctx.Done():
	}
	c.inFlight.Add(-1)
	return nil, nil
}

// staticCallGraphReader answers every read with one stored record. Unlike the
// counting fake beside it, it holds no mutable state, so a hundred concurrent
// stages can share one.
type staticCallGraphReader struct{ rec cgdomain.CallGraphRecord }

func (s staticCallGraphReader) GetCallGraphRecord(context.Context, coordinate.ModuleCoordinate, string) (cgdomain.CallGraphRecord, bool, error) {
	return s.rec, true, nil
}

func (s staticCallGraphReader) ListCallGraphRecordsFor(context.Context, coordinate.ModuleCoordinate, string) ([]cgdomain.CallGraphRecord, error) {
	return []cgdomain.CallGraphRecord{s.rec}, nil
}

// peakConcurrency runs stages call-graph extractions against adapter and
// returns the highest number of subprocesses that ran at once. Every Execute
// blocks until inFlight reaches waitFor, so the count is settled before
// anything is released rather than depending on scheduling.
func peakConcurrency(t *testing.T, adapter *AdapterExtractor, exec *countingExecutor, stages int, waitFor int64) int64 {
	t.Helper()

	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("building the coordinate: %v", err)
	}

	var wg sync.WaitGroup
	for range stages {
		wg.Go(func() {
			if _, eerr := adapter.Extract(t.Context(), coord, "callgraph", false, ""); eerr != nil {
				t.Errorf("Extract returned error: %v", eerr)
			}
		})
	}

	for exec.inFlight.Load() < waitFor {
		runtime.Gosched()
	}
	close(exec.release)
	wg.Wait()
	return exec.peak.Load()
}

func newBoundedTestAdapter(bound int) (*AdapterExtractor, *countingExecutor) {
	exec := &countingExecutor{release: make(chan struct{})}
	reader := staticCallGraphReader{rec: cgdomain.CallGraphRecord{
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		ContentHash:   "hash",
	}}
	return newCallgraphAdapter(exec, reader).WithCallgraphConcurrency(bound), exec
}

func TestCallgraphConcurrency_NeverExceedsTheBound(t *testing.T) {
	const bound = 3
	adapter, exec := newBoundedTestAdapter(bound)
	if peak := peakConcurrency(t, adapter, exec, 24, bound); peak > bound {
		t.Fatalf("%d subprocesses ran at once, want at most %d", peak, bound)
	}
}

// The bound is what holds the count down, not the harness: with nothing
// bounding it the same twenty-four stages all run together. Without this the
// test above would pass against an adapter that never spawns anything.
func TestCallgraphConcurrency_WithoutTheBoundEveryStageRunsAtOnce(t *testing.T) {
	const stages = 24
	exec := &countingExecutor{release: make(chan struct{})}
	adapter := &AdapterExtractor{
		cgExec: exec,
		cgReader: staticCallGraphReader{rec: cgdomain.CallGraphRecord{
			OverallStatus: cgdomain.CallGraphStatusExtracted,
			ContentHash:   "hash",
		}},
		cgPipelineVersion: "0.1.0",
	}
	if peak := peakConcurrency(t, adapter, exec, stages, stages); peak != stages {
		t.Fatalf("unbounded peak = %d, want %d", peak, stages)
	}
}

func TestCallgraphConcurrency_BelowOneRestoresTheDefault(t *testing.T) {
	adapter := newCallgraphAdapter(&fakeSubprocessExecutor{}, &fakeCallGraphReader{})
	for _, n := range []int{0, -1} {
		adapter = adapter.WithCallgraphConcurrency(n)
		if got := cap(adapter.cgSem); got != cpuCapForHost() {
			t.Errorf("WithCallgraphConcurrency(%d) left a bound of %d, want the default %d", n, got, cpuCapForHost())
		}
	}
}

func TestCallgraphConcurrency_ConstructorBoundsWithoutAnExplicitCall(t *testing.T) {
	adapter := newCallgraphAdapter(&fakeSubprocessExecutor{}, &fakeCallGraphReader{})
	if got := cap(adapter.cgSem); got != cpuCapForHost() {
		t.Fatalf("a constructed adapter admits %d subprocesses at once, want the default %d", got, cpuCapForHost())
	}
}

func TestCallgraphConcurrency_ARunThatEndsWhileWaitingRecordsTheHost(t *testing.T) {
	exec := &countingExecutor{release: make(chan struct{})}
	defer close(exec.release)
	reader := staticCallGraphReader{rec: cgdomain.CallGraphRecord{OverallStatus: cgdomain.CallGraphStatusExtracted}}
	adapter := newCallgraphAdapter(exec, reader).WithCallgraphConcurrency(1)

	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("building the coordinate: %v", err)
	}

	// Fill the single slot with a subprocess that does not return until the
	// deferred release at the end of the test.
	go func() { _, _ = adapter.Extract(context.Background(), coord, "callgraph", false, "") }()
	for exec.inFlight.Load() == 0 {
		runtime.Gosched()
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := adapter.Extract(ctx, coord, "callgraph", false, "")
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	if res.Status != domain.StageFailed {
		t.Errorf("Status = %v, want Failed", res.Status)
	}
	if res.Cause != failurecause.Environment {
		t.Errorf("Cause = %q, want environment", res.Cause)
	}
	if !strings.Contains(res.Error, "the run ended before the analysis could start") {
		t.Errorf("Error = %q, want the wait named", res.Error)
	}
}

// The bound is on the subprocess, not on the module pool: the in-process stages
// have no reason to queue behind an SSA build and must not.
func TestCallgraphConcurrency_CheapStagesAreNotBoundedByIt(t *testing.T) {
	exec := &countingExecutor{release: make(chan struct{})}
	defer close(exec.release)
	reader := staticCallGraphReader{rec: cgdomain.CallGraphRecord{OverallStatus: cgdomain.CallGraphStatusExtracted}}
	lic := &mockLicenseUseCase{res: licapp.ExtractResult{Record: licdomain.LicenseRecord{OverallStatus: licdomain.LicenseStatusDetected}}}
	iface := &mockInterfaceUseCase{res: ifaceapp.ExtractResult{Record: ifacedomain.InterfaceRecord{OverallStatus: ifacedomain.InterfaceStatusExtracted}}}
	ex := &mockExampleUseCase{res: exapp.ExtractResult{Record: exdomain.ExampleRecord{OverallStatus: exdomain.ExampleStatusFound}}}
	adapter := NewAdapterExtractor(lic, iface, exec, reader, "0.1.0", nil, ex).WithCallgraphConcurrency(1)

	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("building the coordinate: %v", err)
	}

	// One call-graph subprocess holds the only slot for the whole test.
	go func() { _, _ = adapter.Extract(context.Background(), coord, "callgraph", false, "") }()
	for exec.inFlight.Load() == 0 {
		runtime.Gosched()
	}

	for _, stage := range []string{"license", "interface", "example"} {
		res, serr := adapter.Extract(t.Context(), coord, stage, false, "")
		if serr != nil {
			t.Fatalf("%s stage returned error while a subprocess held the slot: %v", stage, serr)
		}
		if res.Status != domain.StageSucceeded {
			t.Errorf("%s stage = %v, want Succeeded", stage, res.Status)
		}
	}
}
