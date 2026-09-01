package staticcha

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// TestAnalyseDir_UnstageableGoBinaryFailsInsteadOfRunningAnotherToolchain is the
// hazard the swallowed staging errors carried.
//
// --go-binary exists to choose which Go measures the code. Staging it used to
// ignore both of its failures, and the analysis went on: the chosen toolchain was
// never linked, so `go` resolved from whatever came next on PATH and the record
// described a graph built by a toolchain nobody selected — with nothing on it
// saying so. A run that cannot honour the flag now reports an environment
// failure, which is what it is: nothing about the module was measured.
func TestAnalyseDir_UnstageableGoBinaryFailsInsteadOfRunningAnotherToolchain(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/probe\n\ngo 1.21\n",
		"a.go":   "package probe\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	chosen := filepath.Join(t.TempDir(), "go1.99.9")
	if err := os.WriteFile(chosen, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { // #nosec G306 -- a toolchain binary must be executable
		t.Fatalf("writing the chosen go: %v", err)
	}

	// A scratch directory nothing can be created in, which is where the staging
	// directory would go. This is the reachable half of the pair; the symlink half
	// fails the same way and by the same return.
	readOnly := filepath.Join(t.TempDir(), "no-scratch")
	if err := os.Mkdir(readOnly, 0o500); err != nil {
		t.Fatalf("creating the read-only scratch dir: %v", err)
	}
	t.Setenv("TMPDIR", readOnly)

	coord, err := coordinate.NewModuleCoordinate("example.com/probe", coordinate.LocalVersion)
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	a := New("0.0.0-test", chosen, slog.New(slog.NewTextHandler(io.Discard, nil)))

	rec, err := a.AnalyseDir(context.Background(), dir, coord)
	if err != nil {
		t.Fatalf("AnalyseDir: %v", err)
	}

	if rec.FailureCause != domain.FailureCauseEnvironment {
		t.Errorf("FailureCause = %q, want %q: the module was never touched, only the run's own setup failed",
			rec.FailureCause, domain.FailureCauseEnvironment)
	}
	if rec.OverallStatus != domain.CallGraphStatusLoadFailed {
		t.Errorf("OverallStatus = %q, want %q", rec.OverallStatus, domain.CallGraphStatusLoadFailed)
	}
	if !strings.Contains(rec.FailureDetail, chosen) {
		t.Errorf("FailureDetail = %q; it must name the toolchain that could not be staged, since that is the "+
			"input the operator chose and the only thing they can act on", rec.FailureDetail)
	}
}
