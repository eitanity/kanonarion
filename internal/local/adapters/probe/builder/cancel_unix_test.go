//go:build unix

package builder

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stubGo stands in for the go command: `go list` names two main packages and
// `go build` runs buildBody after recording its TMPDIR and writing a work dir
// there, the way a real build does before it is killed.
func stubGo(t *testing.T, buildBody string) (bin, tmpRecord string) {
	t.Helper()
	dir := t.TempDir()
	tmpRecord = filepath.Join(dir, "tmpdir")
	bin = filepath.Join(dir, "go")
	script := "#!/bin/sh\ncase \"$1\" in\n" +
		"list) printf '%s' '{\"ImportPath\":\"example.com/p/a\",\"Name\":\"main\"}{\"ImportPath\":\"example.com/p/b\",\"Name\":\"main\"}' ;;\n" +
		"build) mkdir -p \"$TMPDIR/go-build-stub\" && echo \"$TMPDIR\" > " + tmpRecord + ".part && mv " + tmpRecord + ".part " + tmpRecord + "; " + buildBody + " ;;\n" +
		"esac\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { // #nosec G306 -- a test stand-in that must be executable
		t.Fatalf("writing the stand-in go: %v", err)
	}
	return bin, tmpRecord
}

// A probe build the run's cancellation killed returns the cancellation rather
// than a result naming the binary as one that failed to build, and the work dir
// the killed build left behind goes with the temp root this process gave it.
func TestProbe_BuildStoppedByTheCancellation(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	bin, rec := stubGo(t, "sleep 30")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if _, err := os.Stat(rec); err == nil {
				break
			}
		}
		cancel()
	}()

	res, err := New(bin).Probe(ctx, t.TempDir())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v (binaries %+v), want the cancellation", err, res.Binaries)
	}
	b, rerr := os.ReadFile(rec) // #nosec G304 -- this test's own file
	if rerr != nil {
		t.Fatalf("the stand-in build never ran: %v", rerr)
	}
	childTmp := strings.TrimSpace(string(b))
	if filepath.Dir(childTmp) != tmp {
		t.Errorf("the build's TMPDIR is %s, want a directory under %s", childTmp, tmp)
	}
	if _, serr := os.Stat(childTmp); !os.IsNotExist(serr) { // #nosec G703 -- a path this test's own child reported under its temp dir
		t.Errorf("the killed build's temp root %s survived (stat: %v)", childTmp, serr)
	}

	// The control: a build that genuinely fails is recorded against its binary.
	failing, _ := stubGo(t, "echo 'compile error' >&2; exit 1")
	res, err = New(failing).Probe(t.Context(), t.TempDir())
	if err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the build failure", err)
	}
	if !strings.Contains(err.Error(), "no main package of 2 could be probed") {
		t.Errorf("err = %v, want both binaries tried and reported", err)
	}
}
