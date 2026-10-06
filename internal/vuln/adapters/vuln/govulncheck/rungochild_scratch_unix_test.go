//go:build unix

package govulncheck

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
)

// The binary-mode `go test -c` writes a work directory; one the run's
// cancellation kills leaves it in the temp root this process gave it, which
// goes once the child has exited.
func TestRunGoChild_KilledBuildLeavesNoTempDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	stub := t.TempDir()
	rec := filepath.Join(stub, "tmpdir")
	writeExecutable(t, filepath.Join(stub, "go"),
		"#!/bin/sh\nmkdir -p \"$TMPDIR/go-build-stub\" && echo \"$TMPDIR\" > "+rec+".part && mv "+rec+".part "+rec+"\nsleep 30\n")
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

	tc := goenv.NewToolchains()
	defer func() { _ = tc.Close() }()
	if _, err := runGoChild(ctx, tc, os.Environ(), t.TempDir(), "test", "-c"); err == nil {
		t.Fatal("a killed build returned no error")
	}
	b, err := os.ReadFile(rec) // #nosec G304 -- this test's own file
	if err != nil {
		t.Fatalf("the stand-in build never ran: %v", err)
	}
	childTmp := strings.TrimSpace(string(b))
	if filepath.Dir(childTmp) != tmp {
		t.Errorf("the build's TMPDIR is %s, want a directory under %s", childTmp, tmp)
	}
	if _, serr := os.Stat(childTmp); !os.IsNotExist(serr) { // #nosec G703 -- a path this test's own child reported under its temp dir
		t.Errorf("the killed build's temp root %s survived (stat: %v)", childTmp, serr)
	}
}
