package local

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/extract/domain"

	"github.com/eitanity/kanonarion/internal/adapters/childproc"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	exapp "github.com/eitanity/kanonarion/internal/example/application"
	exdomain "github.com/eitanity/kanonarion/internal/example/domain"
	"github.com/eitanity/kanonarion/internal/failurecause"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
)

type mockLicenseUseCase struct {
	res licapp.ExtractResult
	err error
}

func (m *mockLicenseUseCase) Execute(ctx context.Context, req licapp.ExtractRequest) (licapp.ExtractResult, error) {
	return m.res, m.err
}

type mockInterfaceUseCase struct {
	res ifaceapp.ExtractResult
	err error
}

func (m *mockInterfaceUseCase) Execute(ctx context.Context, req ifaceapp.ExtractRequest) (ifaceapp.ExtractResult, error) {
	return m.res, m.err
}

type mockExampleUseCase struct {
	res exapp.ExtractResult
	err error
}

func (m *mockExampleUseCase) Execute(ctx context.Context, req exapp.ExtractRequest) (exapp.ExtractResult, error) {
	return m.res, m.err
}

// fakeSubprocessExecutor is a controllable SubprocessExecutor for tests.
type fakeSubprocessExecutor struct {
	mu        sync.Mutex
	calls     [][]string // recorded arg slices per call
	stderr    []byte
	err       error
	onExecute func(args []string) // optional hook called under mu
}

func (f *fakeSubprocessExecutor) Execute(ctx context.Context, args []string) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, append([]string(nil), args...))
	if f.onExecute != nil {
		f.onExecute(args)
	}
	stderr := f.stderr
	err := f.err
	f.mu.Unlock()
	return stderr, err
}

// fakeExitStatus stands in for the *exec.ExitError a real child produces.
type fakeExitStatus struct{ code int }

func (f fakeExitStatus) Error() string { return fmt.Sprintf("exit status %d", f.code) }
func (f fakeExitStatus) ExitCode() int { return f.code }

// fakeCallGraphReader is a controllable CallGraphReader for tests.
type fakeCallGraphReader struct {
	out   cgports.CallGraphOutcome
	found bool
	err   error
	// reads counts the narrow read, so a test can tell whether the stage read
	// the ledger at all. Atomic because concurrency tests share one reader
	// across a pool.
	reads atomic.Int64
}

func (f *fakeCallGraphReader) LatestCallGraphOutcome(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (cgports.CallGraphOutcome, bool, error) {
	f.reads.Add(1)
	return f.out, f.found, f.err
}

func newCallgraphAdapter(exec SubprocessExecutor, reader CallGraphReader) *AdapterExtractor {
	return NewAdapterExtractor(nil, nil, exec, reader, "0.1.0", nil, nil)
}

func TestAdapterExtractor_Extract_License(t *testing.T) {
	ctx := t.Context()
	coord, _ := coordinate.NewModuleCoordinate("github.com/foo/bar", "v1.0.0")

	t.Run("license success", func(t *testing.T) {
		lic := &mockLicenseUseCase{
			res: licapp.ExtractResult{
				Record: licdomain.LicenseRecord{
					ContentHash:   "hash-lic",
					OverallStatus: licdomain.LicenseStatusDetected,
				},
			},
		}
		adapter := NewAdapterExtractor(lic, nil, nil, nil, "", nil, nil)
		res, err := adapter.Extract(ctx, coord, "license", false, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		if res.Status != domain.StageSucceeded {
			t.Errorf("Status = %v, want Succeeded", res.Status)
		}
		if res.RecordID != "hash-lic" {
			t.Errorf("RecordID = %s, want hash-lic", res.RecordID)
		}
	})

	t.Run("license unknown status", func(t *testing.T) {
		lic := &mockLicenseUseCase{
			res: licapp.ExtractResult{
				Record: licdomain.LicenseRecord{
					OverallStatus: licdomain.LicenceStatusUnknown,
				},
			},
		}
		adapter := NewAdapterExtractor(lic, nil, nil, nil, "", nil, nil)
		res, err := adapter.Extract(ctx, coord, "license", false, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		if res.Status != domain.StageFailed {
			t.Errorf("Status = %v, want Failed", res.Status)
		}
	})

	t.Run("license multiple status", func(t *testing.T) {
		lic := &mockLicenseUseCase{
			res: licapp.ExtractResult{
				Record: licdomain.LicenseRecord{
					OverallStatus: licdomain.LicenseStatusMultiple,
				},
			},
		}
		adapter := NewAdapterExtractor(lic, nil, nil, nil, "", nil, nil)
		res, err := adapter.Extract(ctx, coord, "license", false, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		if res.Status != domain.StageSucceeded {
			t.Errorf("Status = %v, want Succeeded", res.Status)
		}
	})

	t.Run("license failure status", func(t *testing.T) {
		lic := &mockLicenseUseCase{
			res: licapp.ExtractResult{
				Record: licdomain.LicenseRecord{
					OverallStatus: licdomain.LicenseStatusExtractionFailed,
				},
			},
		}
		adapter := NewAdapterExtractor(lic, nil, nil, nil, "", nil, nil)
		res, err := adapter.Extract(ctx, coord, "license", false, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		if res.Status != domain.StageFailed {
			t.Errorf("Status = %v, want Failed", res.Status)
		}
	})

	t.Run("license error", func(t *testing.T) {
		lic := &mockLicenseUseCase{err: errors.New("boom")}
		adapter := NewAdapterExtractor(lic, nil, nil, nil, "", nil, nil)
		_, err := adapter.Extract(ctx, coord, "license", false, "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestAdapterExtractor_Extract_Interface(t *testing.T) {
	ctx := t.Context()
	coord, _ := coordinate.NewModuleCoordinate("github.com/foo/bar", "v1.0.0")

	t.Run("interface success", func(t *testing.T) {
		iface := &mockInterfaceUseCase{
			res: ifaceapp.ExtractResult{
				Record: ifacedomain.InterfaceRecord{
					ContentHash:   "hash-iface",
					OverallStatus: ifacedomain.InterfaceStatusExtracted,
				},
			},
		}
		adapter := NewAdapterExtractor(nil, iface, nil, nil, "", nil, nil)
		res, err := adapter.Extract(ctx, coord, "interface", false, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		if res.Status != domain.StageSucceeded {
			t.Errorf("Status = %v, want Succeeded", res.Status)
		}
	})

	t.Run("interface unknown status", func(t *testing.T) {
		iface := &mockInterfaceUseCase{
			res: ifaceapp.ExtractResult{
				Record: ifacedomain.InterfaceRecord{
					OverallStatus: ifacedomain.InterfaceStatusUnknown,
				},
			},
		}
		adapter := NewAdapterExtractor(nil, iface, nil, nil, "", nil, nil)
		res, err := adapter.Extract(ctx, coord, "interface", false, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		if res.Status != domain.StageFailed {
			t.Errorf("Status = %v, want Failed", res.Status)
		}
	})

	t.Run("interface partial success", func(t *testing.T) {
		iface := &mockInterfaceUseCase{
			res: ifaceapp.ExtractResult{
				Record: ifacedomain.InterfaceRecord{
					OverallStatus: ifacedomain.InterfaceStatusPartial,
				},
			},
		}
		adapter := NewAdapterExtractor(nil, iface, nil, nil, "", nil, nil)
		res, err := adapter.Extract(ctx, coord, "interface", false, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		if res.Status != domain.StageSucceeded {
			t.Errorf("Status = %v, want Succeeded", res.Status)
		}
	})

	t.Run("interface failure status", func(t *testing.T) {
		iface := &mockInterfaceUseCase{
			res: ifaceapp.ExtractResult{
				Record: ifacedomain.InterfaceRecord{
					OverallStatus: ifacedomain.InterfaceStatusCancelled,
				},
			},
		}
		adapter := NewAdapterExtractor(nil, iface, nil, nil, "", nil, nil)
		res, err := adapter.Extract(ctx, coord, "interface", false, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		if res.Status != domain.StageFailed {
			t.Errorf("Status = %v, want Failed", res.Status)
		}
	})

	t.Run("interface error", func(t *testing.T) {
		iface := &mockInterfaceUseCase{err: errors.New("boom")}
		adapter := NewAdapterExtractor(nil, iface, nil, nil, "", nil, nil)
		_, err := adapter.Extract(ctx, coord, "interface", false, "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestAdapterExtractor_Extract_CallGraph(t *testing.T) {
	ctx := t.Context()
	coord, _ := coordinate.NewModuleCoordinate("github.com/foo/bar", "v1.0.0")

	t.Run("exit 0 reads record and marks succeeded", func(t *testing.T) {
		exec := &fakeSubprocessExecutor{}
		reader := &fakeCallGraphReader{
			found: true,
			out: cgports.CallGraphOutcome{
				ContentHash:   "hash-cg",
				OverallStatus: cgdomain.CallGraphStatusExtracted,
			},
		}
		adapter := newCallgraphAdapter(exec, reader)
		res, err := adapter.Extract(ctx, coord, "callgraph", false, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		if res.Status != domain.StageSucceeded {
			t.Errorf("Status = %v, want Succeeded", res.Status)
		}
		if res.RecordID != "hash-cg" {
			t.Errorf("RecordID = %s, want hash-cg", res.RecordID)
		}
		if len(exec.calls) != 1 {
			t.Fatalf("expected 1 subprocess call, got %d", len(exec.calls))
		}
		if exec.calls[0][0] != "callgraph" || exec.calls[0][1] != coord.String() {
			t.Errorf("subprocess args = %v, want [callgraph %s]", exec.calls[0], coord.String())
		}
	})

	t.Run("force flag is forwarded to subprocess", func(t *testing.T) {
		exec := &fakeSubprocessExecutor{}
		reader := &fakeCallGraphReader{found: true, out: cgports.CallGraphOutcome{OverallStatus: cgdomain.CallGraphStatusExtracted}}
		adapter := newCallgraphAdapter(exec, reader)
		_, err := adapter.Extract(ctx, coord, "callgraph", true, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		args := exec.calls[0]
		var hasForce bool
		for _, a := range args {
			if a == "--force" {
				hasForce = true
			}
		}
		if !hasForce {
			t.Errorf("--force not forwarded to subprocess; args = %v", args)
		}
	})

	t.Run("extra args are forwarded ahead of --force", func(t *testing.T) {
		exec := &fakeSubprocessExecutor{}
		reader := &fakeCallGraphReader{found: true, out: cgports.CallGraphOutcome{OverallStatus: cgdomain.CallGraphStatusExtracted}}
		adapter := NewAdapterExtractor(nil, nil, exec, reader, "0.1.0", []string{"--store-root=/tmp/store", "--from-modcache=/tmp/modcache"}, nil)
		_, err := adapter.Extract(ctx, coord, "callgraph", true, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		// --narrate-progress leads the extra args: the child must report its phases
		// to the process bounding it whatever the store's own preferences say.
		want := []string{"callgraph", coord.String(), "--narrate-progress", "--store-root=/tmp/store", "--from-modcache=/tmp/modcache", "--force"}
		got := exec.calls[0]
		if len(got) != len(want) {
			t.Fatalf("subprocess args = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("subprocess args = %v, want %v", got, want)
				break
			}
		}
	})

	t.Run("non-zero exit captures stderr and marks StageFailed", func(t *testing.T) {
		exec := &fakeSubprocessExecutor{
			stderr: []byte("OOM: killed by kernel"),
			err:    errors.New("exit status 137"),
		}
		adapter := newCallgraphAdapter(exec, &fakeCallGraphReader{})
		res, err := adapter.Extract(ctx, coord, "callgraph", false, "")
		if err != nil {
			t.Fatalf("Extract returned error: %v", err)
		}
		if res.Status != domain.StageFailed {
			t.Errorf("Status = %v, want Failed", res.Status)
		}
		if !strings.Contains(res.Error, "OOM: killed by kernel") {
			t.Errorf("Error = %q, want stderr captured", res.Error)
		}
		if !strings.Contains(res.Error, "callgraph") {
			t.Errorf("Error = %q, missing stage name", res.Error)
		}
	})

	t.Run("callgraph partial status treated as succeeded", func(t *testing.T) {
		exec := &fakeSubprocessExecutor{}
		reader := &fakeCallGraphReader{
			found: true,
			out:   cgports.CallGraphOutcome{OverallStatus: cgdomain.CallGraphStatusPartial},
		}
		adapter := newCallgraphAdapter(exec, reader)
		res, err := adapter.Extract(ctx, coord, "callgraph", false, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		if res.Status != domain.StageSucceeded {
			t.Errorf("Status = %v, want Succeeded", res.Status)
		}
	})

	t.Run("callgraph unknown store status marks StageFailed", func(t *testing.T) {
		exec := &fakeSubprocessExecutor{}
		reader := &fakeCallGraphReader{
			found: true,
			out:   cgports.CallGraphOutcome{OverallStatus: cgdomain.CallGraphStatusUnknown},
		}
		adapter := newCallgraphAdapter(exec, reader)
		res, err := adapter.Extract(ctx, coord, "callgraph", false, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		if res.Status != domain.StageFailed {
			t.Errorf("Status = %v, want Failed", res.Status)
		}
	})

	t.Run("subprocess exits 0 but no record in store marks StageFailed", func(t *testing.T) {
		exec := &fakeSubprocessExecutor{}
		reader := &fakeCallGraphReader{found: false}
		adapter := newCallgraphAdapter(exec, reader)
		res, err := adapter.Extract(ctx, coord, "callgraph", false, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		if res.Status != domain.StageFailed {
			t.Errorf("Status = %v, want Failed", res.Status)
		}
		if !strings.Contains(res.Error, "no record") {
			t.Errorf("Error = %q, missing 'no record' explanation", res.Error)
		}
	})

	t.Run("store read error surfaces as error", func(t *testing.T) {
		exec := &fakeSubprocessExecutor{}
		reader := &fakeCallGraphReader{err: errors.New("db locked")}
		adapter := newCallgraphAdapter(exec, reader)
		_, err := adapter.Extract(ctx, coord, "callgraph", false, "")
		if err == nil {
			t.Fatal("expected error from store read failure, got nil")
		}
	})

}

// TestAdapterExtractor_CallGraph_ReadsWhatWasJustWritten pins the question the
// stage asks the ledger.
//
// It asks what the child it just ran wrote, which the narrow read answers from
// one generation's columns. It does NOT ask which generation should be served —
// that read composes every generation the coordinate holds, rebuilds each one's
// whole edge set and re-marshals it to check the seal, and it is what made this
// stage the largest consumer of memory in an extraction run.
func TestAdapterExtractor_CallGraph_ReadsWhatWasJustWritten(t *testing.T) {
	ctx := t.Context()
	coord, _ := coordinate.NewModuleCoordinate("github.com/foo/bar", "v1.0.0")

	t.Run("the stage reports the generation the narrow read names", func(t *testing.T) {
		exec := &fakeSubprocessExecutor{}
		reader := &fakeCallGraphReader{
			found: true,
			out:   cgports.CallGraphOutcome{ContentHash: "hash-just-written", OverallStatus: cgdomain.CallGraphStatusExtracted},
		}
		adapter := newCallgraphAdapter(exec, reader)
		res, err := adapter.Extract(ctx, coord, "callgraph", false, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		if res.RecordID != "hash-just-written" {
			t.Errorf("RecordID = %s, want hash-just-written: the stage must report its own write", res.RecordID)
		}
		if res.Status != domain.StageSucceeded {
			t.Errorf("Status = %v, want Succeeded", res.Status)
		}
		if got := reader.reads.Load(); got != 1 {
			t.Errorf("the ledger was read %d times, want exactly 1", got)
		}
	})

	t.Run("a child that wrote nothing is still a failed stage", func(t *testing.T) {
		exec := &fakeSubprocessExecutor{}
		reader := &fakeCallGraphReader{}
		adapter := newCallgraphAdapter(exec, reader)

		res, err := adapter.Extract(ctx, coord, "callgraph", false, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		if res.Status != domain.StageFailed {
			t.Errorf("Status = %v, want Failed", res.Status)
		}
		if !strings.Contains(res.Error, "subprocess exited 0 but no record found in store") {
			t.Errorf("Error = %q, want the unchanged no-record explanation", res.Error)
		}
	})

	t.Run("a read that fails is still an error", func(t *testing.T) {
		exec := &fakeSubprocessExecutor{}
		reader := &fakeCallGraphReader{err: errors.New("db locked")}
		adapter := newCallgraphAdapter(exec, reader)
		if _, err := adapter.Extract(ctx, coord, "callgraph", false, ""); err == nil {
			t.Fatal("expected an error when the ledger cannot be read, got nil")
		}
	})
}

// TestAdapterExtractor_CallGraph_WorkerConcurrency asserts that the subprocess
// executor's Execute calls respect the caller's concurrency gate. This test
// uses a counting executor to verify at most N concurrent calls.
func TestAdapterExtractor_CallGraph_WorkerConcurrency(t *testing.T) {
	const workers = 2
	const modules = 6

	var (
		mu         sync.Mutex
		current    int
		maxCurrent int
	)

	exec := &fakeSubprocessExecutor{}
	exec.onExecute = func(_ []string) {
		mu.Lock()
		current++
		if current > maxCurrent {
			maxCurrent = current
		}
		mu.Unlock()
		// simulate some work
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		current--
		mu.Unlock()
	}

	reader := &fakeCallGraphReader{
		found: true,
		out:   cgports.CallGraphOutcome{OverallStatus: cgdomain.CallGraphStatusExtracted},
	}

	adapter := newCallgraphAdapter(exec, reader)

	// Dispatch `modules` concurrent Extract calls, bounded by `workers` semaphore.
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var callCount atomic.Int64
	for range modules {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			coord, _ := coordinate.NewModuleCoordinate("github.com/foo/mod", "v1.0.0")
			res, err := adapter.Extract(t.Context(), coord, "callgraph", false, "")
			if err != nil {
				t.Errorf("Extract failed: %v", err)
				return
			}
			if res.Status != domain.StageSucceeded {
				t.Errorf("Status = %v, want Succeeded", res.Status)
			}
			callCount.Add(1)
		})
	}
	wg.Wait()

	if callCount.Load() != modules {
		t.Errorf("completed %d extractions, want %d", callCount.Load(), modules)
	}
	mu.Lock()
	defer mu.Unlock()
	if maxCurrent > workers {
		t.Errorf("max concurrent subprocess calls = %d, want <= %d", maxCurrent, workers)
	}
}

func TestAdapterExtractor_Extract_Example(t *testing.T) {
	ctx := t.Context()
	coord, _ := coordinate.NewModuleCoordinate("github.com/foo/bar", "v1.0.0")

	t.Run("example success", func(t *testing.T) {
		ex := &mockExampleUseCase{
			res: exapp.ExtractResult{
				Record: exdomain.ExampleRecord{
					ContentHash:   "hash-ex",
					OverallStatus: exdomain.ExampleStatusFound,
				},
			},
		}
		adapter := NewAdapterExtractor(nil, nil, nil, nil, "", nil, ex)
		res, err := adapter.Extract(ctx, coord, "example", false, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		if res.Status != domain.StageSucceeded {
			t.Errorf("Status = %v, want Succeeded", res.Status)
		}
	})

	t.Run("example unknown status", func(t *testing.T) {
		ex := &mockExampleUseCase{
			res: exapp.ExtractResult{
				Record: exdomain.ExampleRecord{
					OverallStatus: exdomain.ExampleStatusUnknown,
				},
			},
		}
		adapter := NewAdapterExtractor(nil, nil, nil, nil, "", nil, ex)
		res, err := adapter.Extract(ctx, coord, "example", false, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		if res.Status != domain.StageFailed {
			t.Errorf("Status = %v, want Failed", res.Status)
		}
	})

	t.Run("example failure status", func(t *testing.T) {
		ex := &mockExampleUseCase{
			res: exapp.ExtractResult{
				Record: exdomain.ExampleRecord{
					OverallStatus: exdomain.ExampleStatusExtractionFailed,
				},
			},
		}
		adapter := NewAdapterExtractor(nil, nil, nil, nil, "", nil, ex)
		res, err := adapter.Extract(ctx, coord, "example", false, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		if res.Status != domain.StageFailed {
			t.Errorf("Status = %v, want Failed", res.Status)
		}
	})

	t.Run("example error", func(t *testing.T) {
		ex := &mockExampleUseCase{err: errors.New("boom")}
		adapter := NewAdapterExtractor(nil, nil, nil, nil, "", nil, ex)
		_, err := adapter.Extract(ctx, coord, "example", false, "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

// TestAdapterExtractor_FailureReason_Propagation asserts that every stage,
// when it promotes the underlying record's status to StageFailed, also
// populates ports.StageResult.Error with a non-empty diagnostic — either the
// record's FailureDetail or a status-only fallback when FailureDetail is
// blank.
func TestAdapterExtractor_FailureReason_Propagation(t *testing.T) {
	ctx := t.Context()
	coord, _ := coordinate.NewModuleCoordinate("github.com/foo/bar", "v1.0.0")

	t.Run("license failed with detail propagates detail", func(t *testing.T) {
		lic := &mockLicenseUseCase{
			res: licapp.ExtractResult{
				Record: licdomain.LicenseRecord{
					OverallStatus: licdomain.LicenseStatusExtractionFailed,
					FailureDetail: "license blob missing in module zip",
				},
			},
		}
		adapter := NewAdapterExtractor(lic, nil, nil, nil, "", nil, nil)
		res, _ := adapter.Extract(ctx, coord, "license", false, "")
		if res.Status != domain.StageFailed {
			t.Fatalf("Status = %v, want Failed", res.Status)
		}
		if res.Error == "" {
			t.Fatal("Error empty; expected non-empty reason propagated from FailureDetail")
		}
		for _, want := range []string{"license", "ExtractionFailed", "license blob missing in module zip"} {
			if !contains(res.Error, want) {
				t.Errorf("Error = %q, missing substring %q", res.Error, want)
			}
		}
	})

	t.Run("callgraph failed record without detail uses status fallback", func(t *testing.T) {
		exec := &fakeSubprocessExecutor{}
		reader := &fakeCallGraphReader{
			found: true,
			out: cgports.CallGraphOutcome{
				OverallStatus: cgdomain.CallGraphStatusLoadFailed,
				// FailureDetail intentionally empty
			},
		}
		adapter := newCallgraphAdapter(exec, reader)
		res, _ := adapter.Extract(ctx, coord, "callgraph", false, "")
		if res.Status != domain.StageFailed {
			t.Fatalf("Status = %v, want Failed", res.Status)
		}
		if res.Error == "" {
			t.Fatal("Error empty even on missing detail; expected status-only fallback")
		}
		for _, want := range []string{"callgraph", "LoadFailed"} {
			if !contains(res.Error, want) {
				t.Errorf("Error = %q, missing substring %q", res.Error, want)
			}
		}
	})

	t.Run("interface failed with detail propagates detail", func(t *testing.T) {
		iface := &mockInterfaceUseCase{
			res: ifaceapp.ExtractResult{
				Record: ifacedomain.InterfaceRecord{
					OverallStatus: ifacedomain.InterfaceStatusExtractionFailed,
					FailureDetail: "parser panic on type literal",
				},
			},
		}
		adapter := NewAdapterExtractor(nil, iface, nil, nil, "", nil, nil)
		res, _ := adapter.Extract(ctx, coord, "interface", false, "")
		if res.Status != domain.StageFailed {
			t.Fatalf("Status = %v, want Failed", res.Status)
		}
		if !contains(res.Error, "parser panic on type literal") {
			t.Errorf("Error = %q, missing FailureDetail", res.Error)
		}
	})

	t.Run("example failed with detail propagates detail", func(t *testing.T) {
		ex := &mockExampleUseCase{
			res: exapp.ExtractResult{
				Record: exdomain.ExampleRecord{
					OverallStatus: exdomain.ExampleStatusExtractionFailed,
					FailureDetail: "go/parser error: unexpected EOF",
				},
			},
		}
		adapter := NewAdapterExtractor(nil, nil, nil, nil, "", nil, ex)
		res, _ := adapter.Extract(ctx, coord, "example", false, "")
		if res.Status != domain.StageFailed {
			t.Fatalf("Status = %v, want Failed", res.Status)
		}
		if !contains(res.Error, "go/parser error: unexpected EOF") {
			t.Errorf("Error = %q, missing FailureDetail", res.Error)
		}
	})

	t.Run("succeeded stages do not pollute Error", func(t *testing.T) {
		t.Run("license", func(t *testing.T) {
			lic := &mockLicenseUseCase{res: licapp.ExtractResult{Record: licdomain.LicenseRecord{OverallStatus: licdomain.LicenseStatusDetected}}}
			res, _ := NewAdapterExtractor(lic, nil, nil, nil, "", nil, nil).Extract(ctx, coord, "license", false, "")
			if res.Error != "" {
				t.Errorf("succeeded license Error = %q, want empty", res.Error)
			}
		})
		t.Run("interface", func(t *testing.T) {
			iface := &mockInterfaceUseCase{res: ifaceapp.ExtractResult{Record: ifacedomain.InterfaceRecord{OverallStatus: ifacedomain.InterfaceStatusExtracted}}}
			res, _ := NewAdapterExtractor(nil, iface, nil, nil, "", nil, nil).Extract(ctx, coord, "interface", false, "")
			if res.Error != "" {
				t.Errorf("succeeded interface Error = %q, want empty", res.Error)
			}
		})
		t.Run("callgraph", func(t *testing.T) {
			exec := &fakeSubprocessExecutor{}
			reader := &fakeCallGraphReader{found: true, out: cgports.CallGraphOutcome{OverallStatus: cgdomain.CallGraphStatusExtracted}}
			res, _ := newCallgraphAdapter(exec, reader).Extract(ctx, coord, "callgraph", false, "")
			if res.Error != "" {
				t.Errorf("succeeded callgraph Error = %q, want empty", res.Error)
			}
		})
		t.Run("example", func(t *testing.T) {
			ex := &mockExampleUseCase{res: exapp.ExtractResult{Record: exdomain.ExampleRecord{OverallStatus: exdomain.ExampleStatusFound}}}
			res, _ := NewAdapterExtractor(nil, nil, nil, nil, "", nil, ex).Extract(ctx, coord, "example", false, "")
			if res.Error != "" {
				t.Errorf("succeeded example Error = %q, want empty", res.Error)
			}
		})
	})
}

// TestBuildSubprocessErrorDetail exercises every branch of the helper directly.
//
// The two deadlines and the lost lock are the branches that matter: each is this
// HOST rather than the module, and each names a different thing to do about it.
func TestBuildSubprocessErrorDetail(t *testing.T) {
	baseErr := errors.New("exit status 1")

	t.Run("stalled names the window and the environment", func(t *testing.T) {
		err := fmt.Errorf("%w for 10m0s: %w", childproc.ErrStalled, baseErr)
		detail, cause, _ := buildSubprocessErrorDetail(err, []byte("  oom  "), "01M0VG1267S1XDJGDFZTVRPM84")
		if !strings.Contains(detail, "no progress") {
			t.Errorf("expected the stall to be named, got %q", detail)
		}
		if !strings.Contains(detail, "oom") {
			t.Errorf("expected stderr in detail, got %q", detail)
		}
		if cause != failurecause.Environment {
			t.Errorf("cause = %q, want environment", cause)
		}
	})

	t.Run("ceiling names the flag that raises it", func(t *testing.T) {
		err := fmt.Errorf("%w of 2h0m0s: %w", childproc.ErrCeiling, baseErr)
		detail, cause, _ := buildSubprocessErrorDetail(err, nil, "01M0VG1267S1XDJGDFZTVRPM84")
		if !strings.Contains(detail, "--callgraph-timeout") {
			t.Errorf("expected the remedy flag, got %q", detail)
		}
		if !strings.Contains(detail, "01M0VG1267S1XDJGDFZTVRPM84") {
			t.Errorf("expected the walk the reader is already inside, got %q", detail)
		}
		if cause != failurecause.Environment {
			t.Errorf("cause = %q, want environment", cause)
		}
	})

	t.Run("ceiling without a walk names the flag alone", func(t *testing.T) {
		err := fmt.Errorf("%w of 2h0m0s: %w", childproc.ErrCeiling, baseErr)
		detail, _, _ := buildSubprocessErrorDetail(err, nil, "")
		if !strings.Contains(detail, "--callgraph-timeout") {
			t.Errorf("expected the remedy flag, got %q", detail)
		}
		if strings.Contains(detail, "kanonarion extract ") {
			t.Errorf("named an invocation with no walk to put in it: %q", detail)
		}
	})

	t.Run("lost lock is the environment, and says running again stores it", func(t *testing.T) {
		stderr := []byte("persisting callgraph record: " + sqlitestore.ContentionMarker + " for the whole retry budget")
		detail, cause, _ := buildSubprocessErrorDetail(baseErr, stderr, "")
		if !strings.Contains(detail, "store lock") {
			t.Errorf("expected contention to be named, got %q", detail)
		}
		if cause != failurecause.Environment {
			t.Errorf("cause = %q, want environment", cause)
		}
	})

	t.Run("an unrecognised exit states no cause", func(t *testing.T) {
		detail, cause, _ := buildSubprocessErrorDetail(baseErr, []byte("panic: nil pointer"), "")
		if !strings.Contains(detail, "subprocess failed") {
			t.Errorf("expected 'subprocess failed', got %q", detail)
		}
		if !strings.Contains(detail, "panic: nil pointer") {
			t.Errorf("expected stderr, got %q", detail)
		}
		if cause != failurecause.Unrecorded {
			t.Errorf("cause = %q, want unrecorded: an exit this classification does not recognise "+
				"is not evidence the module is at fault", cause)
		}
	})

	t.Run("without stderr", func(t *testing.T) {
		detail, _, _ := buildSubprocessErrorDetail(baseErr, nil, "")
		if !strings.Contains(detail, "subprocess failed") {
			t.Errorf("expected 'subprocess failed', got %q", detail)
		}
	})
}

// TestOsSubprocessExecutor exercises the real OS executor using built-in
// POSIX commands so the test stays self-contained without external fixtures.
func TestOsSubprocessExecutor(t *testing.T) {
	t.Run("exit 0 returns nil error and empty stderr", func(t *testing.T) {
		exec := NewOsSubprocessExecutor("/bin/true", 0, nil)
		stderr, err := exec.Execute(t.Context(), nil)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if len(stderr) != 0 {
			t.Errorf("expected empty stderr, got %q", stderr)
		}
	})

	t.Run("exit 1 returns non-nil error", func(t *testing.T) {
		exec := NewOsSubprocessExecutor("/bin/false", 0, nil)
		_, err := exec.Execute(t.Context(), nil)
		if err == nil {
			t.Fatal("expected non-nil error for exit 1")
		}
	})

	t.Run("stderr captured on failure", func(t *testing.T) {
		exec := NewOsSubprocessExecutor("/bin/sh", 0, nil)
		stderr, err := exec.Execute(t.Context(), []string{"-c", "echo captured >&2; exit 1"})
		if err == nil {
			t.Fatal("expected non-nil error")
		}
		if !strings.Contains(string(stderr), "captured") {
			t.Errorf("stderr = %q, want 'captured'", stderr)
		}
	})

	t.Run("context cancellation terminates subprocess", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		exec := NewOsSubprocessExecutor("/bin/sleep", 0, nil)
		_, err := exec.Execute(ctx, []string{"60"})
		if err == nil {
			t.Fatal("expected error from killed subprocess")
		}
	})
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func TestAdapterExtractor_Extract_Misc(t *testing.T) {
	ctx := t.Context()
	coord, _ := coordinate.NewModuleCoordinate("github.com/foo/bar", "v1.0.0")

	t.Run("unknown stage", func(t *testing.T) {
		adapter := NewAdapterExtractor(nil, nil, nil, nil, "", nil, nil)
		_, err := adapter.Extract(ctx, coord, "unknown", false, "")
		if err == nil {
			t.Fatal("expected error for unknown stage")
		}
	})
}

// The parent classifies the record its callgraph child wrote, not the child's
// exit status. Exit 1 is the child saying its graph is known-incomplete; reading
// that as an execution fault reported measured modules as unmeasured.
func TestAdapterExtractor_CallGraph_PartialChildExit(t *testing.T) {
	ctx := t.Context()
	coord, _ := coordinate.NewModuleCoordinate("github.com/foo/bar", "v1.0.0")

	// A child that exited Partial built a graph and stored it. The stage is
	// classified from that record, exactly as it is on a clean exit: reading the
	// exit status as an execution fault reported the module's call graph as
	// unmeasured when it had been measured, with named gaps.
	t.Run("partial exit is classified from the stored record, not the exit status", func(t *testing.T) {
		exec := &fakeSubprocessExecutor{
			stderr: []byte("error: github.com/foo/bar@v1.0.0: Partial — could not import example.com/plot"),
			err:    fakeExitStatus{code: 1},
		}
		reader := &fakeCallGraphReader{
			found: true,
			out: cgports.CallGraphOutcome{
				ContentHash:   "hash-cg-partial",
				OverallStatus: cgdomain.CallGraphStatusPartial,
			},
		}
		adapter := newCallgraphAdapter(exec, reader)
		res, err := adapter.Extract(ctx, coord, "callgraph", false, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		if res.Status != domain.StageSucceeded {
			t.Errorf("Status = %v, want Succeeded: the graph IS in the store", res.Status)
		}
		if res.RecordID != "hash-cg-partial" {
			t.Errorf("RecordID = %q, want the stored record's hash", res.RecordID)
		}
	})

	// A child that exited saying it produced no graph is still a failed stage.
	t.Run("no-graph exit still marks StageFailed", func(t *testing.T) {
		exec := &fakeSubprocessExecutor{
			stderr: []byte("error: github.com/foo/bar@v1.0.0: LoadFailed"),
			err:    fakeExitStatus{code: 2},
		}
		adapter := newCallgraphAdapter(exec, &fakeCallGraphReader{})
		res, err := adapter.Extract(ctx, coord, "callgraph", false, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		if res.Status != domain.StageFailed {
			t.Errorf("Status = %v, want Failed", res.Status)
		}
	})
}

// TestAdapterExtractor_CallGraph_NamesWhatAGapIsAStatementAbout pins the axis
// the three deadline and lock failures share: a module absent from coverage says
// whether THIS HOST or the module is why, because only the first is repaired by
// changing something and running again.
func TestAdapterExtractor_CallGraph_NamesWhatAGapIsAStatementAbout(t *testing.T) {
	coord, _ := coordinate.NewModuleCoordinate("github.com/foo/bar", "v1.0.0")

	t.Run("a stalled child marks StageFailed and says the host is why", func(t *testing.T) {
		// The executor owns both deadlines now, so what the stage classifies is the
		// sentinel it returns rather than a context it set itself. That is the point
		// of the change: elapsed time in the parent was never evidence of a hang.
		exec := &fakeSubprocessExecutor{
			err: fmt.Errorf("%w for 10m0s: signal: killed", childproc.ErrStalled),
		}
		reader := &fakeCallGraphReader{}
		adapter := &AdapterExtractor{
			cgExec:            exec,
			cgReader:          reader,
			cgPipelineVersion: "0.1.0",
		}

		res, err := adapter.Extract(t.Context(), coord, "callgraph", false, "")
		if err != nil {
			t.Fatalf("Extract returned error: %v", err)
		}
		if res.Status != domain.StageFailed {
			t.Errorf("Status = %v, want Failed", res.Status)
		}
		if !strings.Contains(res.Error, "no progress") {
			t.Errorf("Error = %q, want the stall named", res.Error)
		}
		if res.Cause != failurecause.Environment {
			t.Errorf("Cause = %q, want environment", res.Cause)
		}
	})

	t.Run("a record's own cause is what the stage reports", func(t *testing.T) {
		exec := &fakeSubprocessExecutor{}
		reader := &fakeCallGraphReader{found: true, out: cgports.CallGraphOutcome{
			OverallStatus: cgdomain.CallGraphStatusLoadFailed,
			FailureCause:  cgdomain.FailureCauseModule,
			FailureDetail: "no packages found",
		}}
		res, err := newCallgraphAdapter(exec, reader).Extract(t.Context(), coord, "callgraph", false, "")
		if err != nil {
			t.Fatalf("Extract failed: %v", err)
		}
		if res.Cause != failurecause.Module {
			t.Errorf("Cause = %q, want module: the record already decided, and the stage repeats it "+
				"rather than reaching a second answer", res.Cause)
		}
	})
}
