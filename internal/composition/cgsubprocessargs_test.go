package composition

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/eitanity/kanonarion/internal/driver"
	extextractor "github.com/eitanity/kanonarion/internal/extract/adapters/extractor/local"
)

// capturingExecutor stands in for the real callgraph child process. It records
// the argv the extractor built and reports success without spawning anything:
// the defect this guards is a WRITE to the wrong store, so reproducing it by
// running the child is exactly what must not happen.
type capturingExecutor struct {
	mu   sync.Mutex
	args [][]string
}

func (c *capturingExecutor) Execute(_ context.Context, args []string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.args = append(c.args, append([]string(nil), args...))
	return nil, nil
}

func (c *capturingExecutor) calls() [][]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.args
}

// writeDependencyFreeProject writes a Go module with no dependencies, so the
// walk stays offline.
func writeDependencyFreeProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":  "module example.test/proj\n\ngo 1.22\n",
		"lib.go":  "// Package proj is the project root.\npackage proj\n\n// Answer returns 42.\nfunc Answer() int { return 42 }\n",
		"LICENSE": "MIT License\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	return dir
}

// The callgraph stage runs as a child process that inherits none of the
// driver's state, so the driver's store root reaches it only through argv. A
// driver built on a scratch root must name THAT root on the child's command
// line; without it the child resolves the default store and reads, writes and
// migrates a store the caller never named.
//
// The composition integration tests exclude the callgraph stage entirely (no
// real binary is available in-process), which is the blind spot that let the
// missing argument survive. This test requests the callgraph stage through the
// real extraction orchestration and observes the argv at the executor seam.
func TestDriverCallGraphSubprocessNamesTheDriverStoreRoot(t *testing.T) {
	storeRoot := t.TempDir()
	projDir := writeDependencyFreeProject(t)

	exec := &capturingExecutor{}
	drv, cleanup, err := newDriver(storeRoot, exec)
	if err != nil {
		t.Fatalf("newDriver: %v", err)
	}
	defer func() { _ = cleanup() }()

	if _, err := drv.LocalWalkExtract.Run(context.Background(), driver.LocalWalkExtractRequest{
		Dir:              projDir,
		Stages:           []string{"callgraph"},
		AnalyseLocalRoot: true,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	calls := exec.calls()
	if len(calls) == 0 {
		t.Fatalf("callgraph subprocess was never invoked; the test no longer exercises the stage")
	}
	want := "--store-root=" + storeRoot
	for i, args := range calls {
		if !containsArg(args, want) {
			t.Errorf("child argv %d = %v, missing %q: the child would resolve the DEFAULT store root", i, args, want)
		}
		// The driver has no --from-modcache concept: it always reads bytes
		// through the content-addressed blob store. The asymmetry with the CLI's
		// arg list is deliberate, not a second omission.
		for _, a := range args {
			if strings.HasPrefix(a, "--from-modcache") {
				t.Errorf("child argv %d = %v, unexpected %q: the driver has no modcache mode to pass", i, args, a)
			}
		}
	}
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// Both composition roots build the child's argv through one constructor, so
// the CLI's shape and the driver's cannot drift apart. This pins both.
func TestCallGraphSubprocessArgs(t *testing.T) {
	tests := []struct {
		name        string
		storeRoot   string
		modcacheDir string
		want        []string
	}{
		{
			name:      "driver shape: store root only, no modcache concept",
			storeRoot: "/scratch/store",
			want:      []string{"--store-root=/scratch/store"},
		},
		{
			name:        "CLI shape in --from-modcache mode: both roots",
			storeRoot:   "/scratch/store",
			modcacheDir: "/gomodcache",
			want:        []string{"--store-root=/scratch/store", "--from-modcache=/gomodcache"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extextractor.CallGraphSubprocessArgs(tc.storeRoot, tc.modcacheDir)
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("CallGraphSubprocessArgs(%q, %q) = %v, want %v", tc.storeRoot, tc.modcacheDir, got, tc.want)
			}
		})
	}
}
