//go:build unix

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The scope list `go list -deps -test` writes a work directory; one the run's
// cancellation kills leaves it in the temp root this process gave it, which
// goes once the child has exited.
func TestRunGoList_KilledListLeavesNoTempDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	stub := t.TempDir()
	rec := filepath.Join(stub, "tmpdir")
	script := "#!/bin/sh\nmkdir -p \"$TMPDIR/go-build-stub\" && echo \"$TMPDIR\" > " + rec + ".part && mv " + rec + ".part " + rec + "\nsleep 30\n"
	if err := os.WriteFile(filepath.Join(stub, "go"), []byte(script), 0o700); err != nil { // #nosec G306 -- a test stand-in that must be executable
		t.Fatalf("writing the stand-in go: %v", err)
	}
	t.Setenv("PATH", stub+string(os.PathListSeparator)+os.Getenv("PATH"))
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

	if _, err := runGoList(ctx, t.TempDir(), []string{"list", "-deps", "-test", "./..."}); err == nil {
		t.Fatal("a killed list returned no error")
	}
	b, err := os.ReadFile(rec) // #nosec G304 -- this test's own file
	if err != nil {
		t.Fatalf("the stand-in list never ran: %v", err)
	}
	childTmp := strings.TrimSpace(string(b))
	if filepath.Dir(childTmp) != tmp {
		t.Errorf("the list's TMPDIR is %s, want a directory under %s", childTmp, tmp)
	}
	if _, serr := os.Stat(childTmp); !os.IsNotExist(serr) { // #nosec G703 -- a path this test's own child reported under its temp dir
		t.Errorf("the killed list's temp root %s survived (stat: %v)", childTmp, serr)
	}
}
