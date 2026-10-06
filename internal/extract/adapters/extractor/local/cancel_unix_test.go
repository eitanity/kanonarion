//go:build unix

package local

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/extract/domain"
)

// A call-graph child the run's cancellation killed is reported as cancelled. The
// SIGKILL that ends it is otherwise the shape the operating system's OOM kill
// has, and the stage would state that the host ran out of memory.
func TestCallgraph_ChildKilledByTheCancellationIsNotOutOfMemory(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("building the coordinate: %v", err)
	}
	child := filepath.Join(t.TempDir(), "child")
	if err := os.WriteFile(child, []byte("#!/bin/sh\nsleep 30\n"), 0o700); err != nil { // #nosec G306 -- the test's own executable
		t.Fatalf("writing the child: %v", err)
	}
	adapter := newCallgraphAdapter(NewOsSubprocessExecutor(child, time.Minute, nil), extractedOutcome())

	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(200*time.Millisecond, cancel)
	res, eerr := adapter.Extract(ctx, coord, "callgraph", false, "")
	if eerr != nil {
		t.Fatalf("Extract failed: %v", eerr)
	}
	if res.Status != domain.StageFailed {
		t.Fatalf("Status = %v, want Failed", res.Status)
	}
	if strings.Contains(res.Error, "status="+cgdomain.CallGraphStatusOutOfMemory.String()) {
		t.Errorf("a child the cancellation killed was reported as OutOfMemory: %q", res.Error)
	}
	if !strings.Contains(res.Error, "status="+cgdomain.CallGraphStatusCancelled.String()) {
		t.Errorf("Error = %q, want it to name status=Cancelled", res.Error)
	}
}
