package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGoToolchainVersionProbe_AnswersOnThisBox is the control for the seam: the
// real probe must succeed in an environment that can run the test suite at all,
// or every load failure would be classed as environmental and nothing would
// ever cache.
func TestGoToolchainVersionProbe_AnswersOnThisBox(t *testing.T) {
	dir := t.TempDir()
	version, err := goToolchainVersionProbe(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("the real toolchain probe failed in an environment running the test suite: %v", err)
	}
	// The version is the answer now, not just a liveness signal: a probe that
	// succeeded and named nothing would stamp every record "not recorded".
	if !strings.HasPrefix(version, "go1.") {
		t.Errorf("the probe answered %q, which is not a go env GOVERSION", version)
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

	version, err := goToolchainVersionProbe(context.Background(), usable, nil)
	if err != nil {
		t.Fatalf("the probe failed in a directory whose toolchain resolves: %v", err)
	}
	if version != "go1.0.0" {
		t.Errorf("the probe reported %q; the stand-in named go1.0.0", version)
	}
	if _, err := goToolchainVersionProbe(context.Background(), unusable, nil); err == nil {
		t.Error("the probe reported a usable toolchain for a directory that cannot resolve one")
	}
}

// TestGoSourceDirsProbe_AnswersOnThisBox is the control for the second seam. If
// the real probe cannot name the analysis's roots in an environment that runs
// the suite, every recorded position falls back to the host's own absolute paths
// and the build cache goes back inside the seal.
func TestGoSourceDirsProbe_AnswersOnThisBox(t *testing.T) {
	dirs, err := goSourceDirsProbe(context.Background(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("the real source-dirs probe failed in an environment running the test suite: %v", err)
	}
	for name, got := range map[string]string{
		"GOROOT": dirs.GOROOT, "GOCACHE": dirs.BuildCache, "GOMODCACHE": dirs.ModuleCache,
	} {
		if !filepath.IsAbs(got) {
			t.Errorf("%s = %q, which is not a directory the loader could resolve from", name, got)
		}
	}
}

// TestGoSourceDirsProbe_ReadsTheValuesInTheOrderAsked pins the mapping between
// the three lines `go env` prints and the three roots they become. Reading them
// in the wrong order would spell stdlib files against the build cache and give
// the standard library no position at all — silently, since every value is a
// plausible directory.
func TestGoSourceDirsProbe_ReadsTheValuesInTheOrderAsked(t *testing.T) {
	binDir := t.TempDir()
	script := "#!/bin/sh\necho /fake/goroot\necho /fake/gocache\necho /fake/gomodcache\n"
	if err := os.WriteFile(filepath.Join(binDir, "go"), []byte(script), 0o700); err != nil { // #nosec G306 -- a test fixture that must be executable
		t.Fatalf("writing the toolchain stand-in: %v", err)
	}
	t.Setenv("PATH", binDir)

	dirs, err := goSourceDirsProbe(context.Background(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("the probe failed against a stand-in that answered: %v", err)
	}
	if dirs.GOROOT != "/fake/goroot" || dirs.BuildCache != "/fake/gocache" || dirs.ModuleCache != "/fake/gomodcache" {
		t.Errorf("probe = %+v, want the three values in the order they were asked for", dirs)
	}
}

// TestGoSourceDirsProbe_ShortAnswerIsRefused is the fault seam. A toolchain that
// exits zero having named fewer than three directories has not answered the
// question, and taking what it did say would put one root's value in another
// root's slot.
func TestGoSourceDirsProbe_ShortAnswerIsRefused(t *testing.T) {
	binDir := t.TempDir()
	script := "#!/bin/sh\necho /fake/goroot\necho /fake/gocache\n"
	if err := os.WriteFile(filepath.Join(binDir, "go"), []byte(script), 0o700); err != nil { // #nosec G306 -- a test fixture that must be executable
		t.Fatalf("writing the toolchain stand-in: %v", err)
	}
	t.Setenv("PATH", binDir)

	if dirs, err := goSourceDirsProbe(context.Background(), t.TempDir(), nil); err == nil {
		t.Errorf("the probe accepted a two-line answer as three directories: %+v", dirs)
	}
}

// TestGoSourceDirsProbe_UnusableToolchainIsReported holds the other failure: a
// go on PATH that cannot run at all names no roots, and the analyser discloses
// that rather than treating the zero value as an answer.
func TestGoSourceDirsProbe_UnusableToolchainIsReported(t *testing.T) {
	binDir := t.TempDir()
	script := "#!/bin/sh\necho 'ERROR No version is set for shim: go' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(binDir, "go"), []byte(script), 0o700); err != nil { // #nosec G306 -- a test fixture that must be executable
		t.Fatalf("writing the toolchain stand-in: %v", err)
	}
	t.Setenv("PATH", binDir)

	if _, err := goSourceDirsProbe(context.Background(), t.TempDir(), nil); err == nil {
		t.Error("the probe named roots from a toolchain that could not run")
	}
}

// TestGoSourceDirsProbe_AnswersUnderTheGivenEnvironment is why the probe takes
// an environment at all. The roots it names are the ones a recorded path is
// rendered against, so they have to be the roots the LOAD resolved from — a
// probe left to inherit this process's environment would name this process's
// cache and leave the load's own paths unrecognised, which is the whole defect
// wearing a different hat.
func TestGoSourceDirsProbe_AnswersUnderTheGivenEnvironment(t *testing.T) {
	cache := t.TempDir()
	dirs, err := goSourceDirsProbe(context.Background(), t.TempDir(), append(os.Environ(), "GOCACHE="+cache))
	if err != nil {
		t.Fatalf("the probe failed under an environment naming a build cache: %v", err)
	}
	if dirs.BuildCache != cache {
		t.Errorf("BuildCache = %q, want %q — the probe answered about this process, not about the load", dirs.BuildCache, cache)
	}
}
