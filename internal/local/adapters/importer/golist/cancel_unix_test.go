//go:build unix

package golist_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/local/adapters/importer/golist"
)

// A `go list -test` the run's cancellation kills cannot remove the work
// directory it wrote; the temp root this process gave it goes once it has
// exited, and the cancellation is what the analysis returns.
func TestAnalyseImports_KilledListLeavesNoTempDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	dir := t.TempDir()
	rec := filepath.Join(dir, "tmpdir")
	bin := filepath.Join(dir, "go")
	script := "#!/bin/sh\nmkdir -p \"$TMPDIR/go-build-stub\" && echo \"$TMPDIR\" > " + rec + ".part && mv " + rec + ".part " + rec + "\nsleep 30\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { // #nosec G306 -- a test stand-in that must be executable
		t.Fatalf("writing the stand-in go: %v", err)
	}
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

	if _, err := golist.New(bin).AnalyseImports(ctx, t.TempDir()); err == nil || !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("err = %v, want the killed list's error under a cancelled context", err)
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
