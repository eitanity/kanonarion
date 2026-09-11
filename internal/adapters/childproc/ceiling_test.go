package childproc

import (
	"bytes"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestEnforceMemoryCeiling_NoCeilingStartsNothing is the case every invocation an
// operator makes by hand takes: the variable is absent, so no watch runs and no
// memory limit is imposed.
func TestEnforceMemoryCeiling_NoCeilingStartsNothing(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"", "0", "not a number", "-1"} {
		var stderr bytes.Buffer
		got := EnforceMemoryCeiling(func(string) string { return raw }, &stderr,
			func() { t.Errorf("a process with no usable ceiling (%q) must not be stopped", raw) })
		if got != 0 {
			t.Errorf("EnforceMemoryCeiling(%q) = %d, want 0", raw, got)
		}
	}
}

// TestEnforceMemoryCeiling_StopsTheProcessThatPassesIt is the whole mechanism:
// an analysis that cannot fit ends itself and says what it reached, instead of
// being taken by the kernel with nothing recorded.
//
// A ceiling of one byte rather than a real allocation, because the point under
// test is that crossing it is noticed and reported — building a multi-gigabyte
// heap to prove that would put the test itself on the host's memory.
func TestEnforceMemoryCeiling_StopsTheProcessThatPassesIt(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var stderr bytes.Buffer
	stopped := make(chan struct{})
	var once sync.Once

	// The soft target is process-wide and a one-byte one would have the collector
	// running flat out for the rest of the test binary. It is put back the instant
	// it has been set; the watch, which is what is under test, is unaffected.
	prior := debug.SetMemoryLimit(-1)
	ceiling := EnforceMemoryCeiling(
		func(string) string { return "1" },
		&lockedWriter{mu: &mu, w: &stderr},
		func() { once.Do(func() { close(stopped) }) })
	debug.SetMemoryLimit(prior)
	if ceiling != 1 {
		t.Fatalf("adopted ceiling = %d, want 1", ceiling)
	}

	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("a process holding more than its ceiling was never stopped")
	}

	mu.Lock()
	said := stderr.String()
	mu.Unlock()
	if !strings.HasPrefix(said, MemoryCeilingMarker) {
		t.Errorf("stderr = %q, want it to open with %q so the parent can classify it", said, MemoryCeilingMarker)
	}
	if !strings.Contains(said, "ceiling of 1") {
		t.Errorf("stderr = %q, want the ceiling it reached named in it", said)
	}
}

// lockedWriter serialises the watch goroutine's write against the test's read.
type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p) //nolint:wrapcheck // bytes.Buffer.Write never returns an error
}

// TestMemoryInUse_ReportsWhatTheProcessHolds guards the reading the watch acts
// on. A ceiling enforced against a figure that is always zero would never fire,
// and the test above would still pass.
func TestMemoryInUse_ReportsWhatTheProcessHolds(t *testing.T) {
	t.Parallel()
	if got := MemoryInUse(); got == 0 {
		t.Fatal("MemoryInUse() = 0; a running Go process holds memory")
	}
}

// TestRunBounded_HandsTheChildItsCeiling is the other half: the env slice is the
// only route into a process that has not started, so the ceiling must be on it.
func TestRunBounded_HandsTheChildItsCeiling(t *testing.T) {
	t.Parallel()
	const ceiling = 12345678
	stderr, err := RunBounded(t.Context(), Bounds{MemoryCeiling: ceiling},
		"/bin/sh", "-c", `echo "ceiling=[$`+MemoryCeilingEnv+`]" >&2; echo "path=[$PATH]" >&2`)
	if err != nil {
		t.Fatalf("RunBounded: %v", err)
	}
	said := string(stderr)
	if want := "ceiling=[12345678]"; !strings.Contains(said, want) {
		t.Errorf("child's stderr = %q, want it to carry %q", said, want)
	}
	// The rest of the environment survives: a child handed only its ceiling
	// cannot find the go command, and the failure would look like the module's.
	if want := "path=[" + os.Getenv("PATH") + "]"; !strings.Contains(said, want) {
		t.Errorf("child's PATH is not the parent's; stderr = %q", said)
	}
}

// TestRunBounded_NoCeilingLeavesTheChildEnvironmentAlone is the control: without
// one, nothing is added and the child inherits exactly what it would have.
func TestRunBounded_NoCeilingLeavesTheChildEnvironmentAlone(t *testing.T) {
	t.Parallel()
	stderr, err := RunBounded(t.Context(), Bounds{}, "/bin/sh", "-c",
		`echo "[$`+MemoryCeilingEnv+`]" >&2`)
	if err != nil {
		t.Fatalf("RunBounded: %v", err)
	}
	if got := strings.TrimSpace(string(stderr)); got != "[]" {
		t.Errorf("child saw %s=%s, want it unset", MemoryCeilingEnv, got)
	}
}
