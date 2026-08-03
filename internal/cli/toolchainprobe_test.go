package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestGoToolchainVersionProbe_AnswersOnThisBox is the control for the seam: the
// real probe must succeed in an environment that can run the test suite at all,
// or every load failure would be classed as environmental and nothing would
// ever cache.
func TestGoToolchainVersionProbe_AnswersOnThisBox(t *testing.T) {
	dir := t.TempDir()
	if err := goToolchainVersionProbe(context.Background(), dir); err != nil {
		t.Fatalf("the real toolchain probe failed in an environment running the test suite: %v", err)
	}
}

// TestGoToolchainVersionProbe_AsksTheGivenDirectory is the reproduction the
// directory argument exists for. A version manager resolves the toolchain from
// the tree it is invoked in, so the same `go` on PATH answers in one directory
// and fails in another. A probe that inherited this process's working directory
// would report both usable, and the failed load would be filed as a fact about
// the module and cached forever.
//
// The stand-in for the version manager is a script on PATH that decides by the
// directory it was run in — which is exactly the input under test, and needs no
// version manager installed to exercise it.
func TestGoToolchainVersionProbe_AsksTheGivenDirectory(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	usable := filepath.Join(root, "usable")
	unusable := filepath.Join(root, "unusable")
	for _, d := range []string{binDir, usable, unusable} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	script := "#!/bin/sh\ncase \"$PWD\" in\n*/unusable*) echo 'ERROR No version is set for shim: go' >&2; exit 1;;\n*) echo go1.0.0;;\nesac\n"
	if err := os.WriteFile(filepath.Join(binDir, "go"), []byte(script), 0o700); err != nil { // #nosec G306 -- a test fixture that must be executable
		t.Fatalf("writing the toolchain stand-in: %v", err)
	}

	t.Setenv("PATH", binDir)

	if err := goToolchainVersionProbe(context.Background(), usable); err != nil {
		t.Fatalf("the probe failed in a directory whose toolchain resolves: %v", err)
	}
	if err := goToolchainVersionProbe(context.Background(), unusable); err == nil {
		t.Error("the probe reported a usable toolchain for a directory that cannot resolve one")
	}
}
