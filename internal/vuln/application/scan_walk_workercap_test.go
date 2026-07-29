package application

import (
	"bytes"
	"errors"
	"log/slog"
	"runtime"
	"strings"
	"testing"
)

// fakeHostMemory is an injectable ports.HostMemory. It exists because the
// host's own free memory is not something a test can vary, and the whole point
// of the cap is what it does at readings the test host will never present.
type fakeHostMemory struct {
	available uint64
	err       error
}

func (f fakeHostMemory) AvailableBytes() (uint64, error) {
	if f.err != nil {
		return 0, f.err
	}
	return f.available, nil
}

// newCapTestUseCase returns a use case wired with mem and a logger writing to
// buf, so a test can assert on both the chosen worker count and what the
// operator was told about it.
func newCapTestUseCase(mem *fakeHostMemory, buf *bytes.Buffer) *ScanWalkUseCase {
	uc := &ScanWalkUseCase{
		logger: slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if mem != nil {
		uc.hostMemory = *mem
	}
	return uc
}

func cpuCapForHost() int { return min(runtime.NumCPU(), cpuWorkerCap) }

// TestResolveWorkerCount_SmallMemoryRunsOneWorker pins the point of the memory
// budget: on a host that cannot hold a full pool of source-mode scans, the pool
// must shrink rather than be OOM-killed — which does not report a slow scan, it
// reports every module as unanalysed.
func TestResolveWorkerCount_SmallMemoryRunsOneWorker(t *testing.T) {
	var buf bytes.Buffer
	// Under one worker's budget: the floor of 1 applies, because a single scan
	// that might survive beats a pool of zero that certainly reports nothing.
	uc := newCapTestUseCase(&fakeHostMemory{available: perWorkerBudgetBytes - 1}, &buf)

	if got := uc.resolveWorkerCount(0); got != 1 {
		t.Fatalf("resolveWorkerCount(0) with %d bytes available = %d, want 1", perWorkerBudgetBytes-1, got)
	}

	// The operator is told why the scan is slow, with the numbers behind it.
	logged := buf.String()
	for _, want := range []string{"capped by available memory", "available_bytes", "per_worker_budget_bytes", "workers=1"} {
		if !strings.Contains(logged, want) {
			t.Errorf("info log missing %q; got: %s", want, logged)
		}
	}
}

// TestResolveWorkerCount_AmpleMemoryKeepsCPUCap proves the memory term only
// ever lowers the count: a host with room for a full pool is unaffected, and
// says nothing about a cap it did not apply.
func TestResolveWorkerCount_AmpleMemoryKeepsCPUCap(t *testing.T) {
	var buf bytes.Buffer
	uc := newCapTestUseCase(&fakeHostMemory{available: uint64(cpuWorkerCap+4) * perWorkerBudgetBytes}, &buf)

	want := cpuCapForHost()
	if got := uc.resolveWorkerCount(0); got != want {
		t.Fatalf("resolveWorkerCount(0) with ample memory = %d, want min(NumCPU, %d) = %d", got, cpuWorkerCap, want)
	}
	if strings.Contains(buf.String(), "capped by available memory") {
		t.Errorf("logged a memory cap that was never applied: %s", buf.String())
	}
}

// TestResolveWorkerCount_UnreadableMemoryFallsBack pins the never-fail rule: a
// reading that could not be taken degrades to the CPU-only cap and is reported
// at debug. An unreadable /proc is the normal case on every non-Linux host and
// must not read as a fault, still less abort a scan.
func TestResolveWorkerCount_UnreadableMemoryFallsBack(t *testing.T) {
	var buf bytes.Buffer
	uc := newCapTestUseCase(&fakeHostMemory{err: errors.New("no /proc/meminfo here")}, &buf)

	want := cpuCapForHost()
	if got := uc.resolveWorkerCount(0); got != want {
		t.Fatalf("resolveWorkerCount(0) with an unreadable reading = %d, want the CPU cap %d", got, want)
	}
	logged := buf.String()
	if !strings.Contains(logged, "available memory unreadable") {
		t.Errorf("fallback not reported at debug; got: %s", logged)
	}
	if strings.Contains(logged, "level=ERROR") || strings.Contains(logged, "level=WARN") {
		t.Errorf("a missing memory reading was escalated above debug: %s", logged)
	}
}

// TestResolveWorkerCount_NoReporterKeepsCPUCap covers the wiring default: a use
// case built without WithHostMemory behaves exactly as it did before the budget
// existed.
func TestResolveWorkerCount_NoReporterKeepsCPUCap(t *testing.T) {
	var buf bytes.Buffer
	uc := newCapTestUseCase(nil, &buf)

	want := cpuCapForHost()
	if got := uc.resolveWorkerCount(0); got != want {
		t.Fatalf("resolveWorkerCount(0) with no reporter = %d, want the CPU cap %d", got, want)
	}
}

// TestResolveWorkerCount_ExplicitRequestWins proves an operator override is
// taken as given. Silently shrinking an explicit --workers would make the flag
// lie about what the scan is doing.
func TestResolveWorkerCount_ExplicitRequestWins(t *testing.T) {
	var buf bytes.Buffer
	uc := newCapTestUseCase(&fakeHostMemory{available: 1}, &buf)

	if got := uc.resolveWorkerCount(7); got != 7 {
		t.Fatalf("resolveWorkerCount(7) on a memory-starved host = %d, want the requested 7", got)
	}
	if buf.Len() != 0 {
		t.Errorf("an explicit worker count consulted the memory budget: %s", buf.String())
	}
}
