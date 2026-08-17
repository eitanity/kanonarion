package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// A root ingest that did not happen is a missing capability, not a failed
// walk. The record it produces carries a complete graph and a succeeded root,
// so the two things the output must do are name the capability the run lacks
// and refuse to present the run as the analysis that was asked for.
//
// Before this, the same condition marked the root fetch-failed, which made the
// walk fail outright and reported it as "project go.mod could not be resolved"
// — a sentence about a file that had in fact been read, printed over a fully
// fetched and cross-verified dependency closure that was then discarded.
func TestRunWalkProject_RootIngestFailureIsReportedAsDegraded(t *testing.T) {
	dir := t.TempDir()
	gomodPath := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomodPath, []byte("module example.com/app/v2\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target, err := coordinate.NewLocalCoordinate("example.com/app/v2")
	if err != nil {
		t.Fatal(err)
	}
	const reason = "creating zip from \"/work/app\": invalid version: should be v2, not v0"

	newRecord := func() walkdomain.WalkRecord {
		return walkdomain.WalkRecord{
			ID:            "W1",
			Target:        target,
			OverallStatus: walkdomain.WalkPartial,
			PerNodeResults: map[coordinate.ModuleCoordinate]walkdomain.NodeResult{
				target: {
					Coordinate: target,
					Status:     walkdomain.NodeSucceeded,
					Error: &walkdomain.StoredError{
						Type:    "local_root_ingest_failed",
						Message: reason,
					},
				},
			},
		}
	}

	run := func(t *testing.T, allowPartial bool) (string, error) {
		t.Helper()
		uc := &testfakes.FakeExecuteWalk{Result: walkapp.ExecuteWalkResult{Record: newRecord()}}
		progress := newWalkProgressReporter(io.Discard, true, activeConfig, logLevel)
		var stderr bytes.Buffer
		_, rerr := runWalkProject(context.Background(), gomodPath, false, allowPartial, 0, "", "", false,
			scopeComplete, walkdomain.WalkDepthFull, "", true, false, progress, uc, nil, io.Discard, &stderr)
		return stderr.String(), rerr
	}

	t.Run("states the missing capability", func(t *testing.T) {
		out, _ := run(t, true)
		if !strings.Contains(out, "--analyse-root did not ingest example.com/app/v2") {
			t.Errorf("stderr does not name the capability the walk lacks:\n%s", out)
		}
		if !strings.Contains(out, "does not cover the project's own packages") {
			t.Errorf("stderr does not say what is missing from the walk:\n%s", out)
		}
		if !strings.Contains(out, reason) {
			t.Errorf("stderr does not carry the underlying reason:\n%s", out)
		}
	})

	t.Run("exits partial, not failed", func(t *testing.T) {
		_, rerr := run(t, false)
		var ee *exitError
		if !errors.As(rerr, &ee) {
			t.Fatalf("error = %v, want an exitError", rerr)
		}
		if ee.code != ExitPartial {
			t.Errorf("exit code = %d, want %d (partial); a missing root ingest must not discard the walk", ee.code, ExitPartial)
		}
		if strings.Contains(ee.msg, "go.mod could not be resolved") {
			t.Errorf("message asserts the go.mod was unreadable when it was read: %q", ee.msg)
		}
		if !strings.Contains(ee.msg, "the dependency graph is complete") {
			t.Errorf("message = %q, want it to say the graph survived", ee.msg)
		}
	})

	t.Run("--allow-partial tolerates it", func(t *testing.T) {
		if _, rerr := run(t, true); rerr != nil {
			t.Errorf("with --allow-partial the run should succeed, got: %v", rerr)
		}
	})
}

// The note and the partial message are for a root ingest that failed. A walk
// with no such error must read exactly as it did before.
func TestRunWalkProject_NoRootIngestFailureIsSilent(t *testing.T) {
	dir := t.TempDir()
	gomodPath := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomodPath, []byte("module example.com/app\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	uc := &testfakes.FakeExecuteWalk{Result: walkapp.ExecuteWalkResult{
		Record: walkdomain.WalkRecord{ID: "W1", OverallStatus: walkdomain.WalkSucceeded},
	}}
	progress := newWalkProgressReporter(io.Discard, true, activeConfig, logLevel)
	var stderr bytes.Buffer
	if _, err := runWalkProject(context.Background(), gomodPath, false, false, 0, "", "", false,
		scopeComplete, walkdomain.WalkDepthFull, "", true, false, progress, uc, nil, io.Discard, &stderr); err != nil {
		t.Fatalf("runWalkProject: %v", err)
	}
	if strings.Contains(stderr.String(), "--analyse-root did not ingest") {
		t.Errorf("a clean walk must not mention a root-ingest failure:\n%s", stderr.String())
	}
}
