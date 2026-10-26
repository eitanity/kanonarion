package tinygo_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"code.eitanity.com/kanonarion/internal/walk/adapters/buildlist/tinygo"
	"code.eitanity.com/kanonarion/internal/walk/adapters/buildlist/tinygotest"
)

// With tinygo on PATH, a package is TinyGo's when its directory is under TINYGOROOT/src.
func TestProvides_ReadsTheInstalledSource(t *testing.T) {
	fake := tinygotest.Install(t, nil)
	t.Setenv("PATH", fake.Dir)
	if err := os.MkdirAll(filepath.Join(fake.SourceRoot, "src", "machine", "usb"), 0o750); err != nil {
		t.Fatal(err)
	}
	for pkg, want := range map[string]bool{
		"machine": true, "machine/usb": true, "device/arm": false, "foo/bar": false,
		"../machine": false, "/machine": false, "": false, "machine/../machine": false,
	} {
		if got := tinygo.Provides(context.Background(), pkg); got != want {
			t.Errorf("Provides(%q) = %v, want %v", pkg, got, want)
		}
	}
}

// Without tinygo, the top-level paths TinyGo adds name its packages.
func TestProvides_FallsBackWithoutTinyGo(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if !tinygo.Provides(context.Background(), "machine") {
		t.Error("machine is not named by the fallback list")
	}
	if tinygo.Provides(context.Background(), "foo/bar") {
		t.Error("foo/bar was named TinyGo's")
	}
}

// A tinygo that cannot report its root falls back to the list too.
func TestProvides_FallsBackWhenTinyGoCannotSay(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tinygo"), []byte("#!/bin/sh\nexit 3\n"), 0o700); err != nil { // #nosec G306 -- an executable test fixture
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if !tinygo.Provides(context.Background(), "runtime/volatile") || tinygo.Provides(context.Background(), "foo/bar") {
		t.Error("a failed tinygo env did not fall back to the list")
	}
}
