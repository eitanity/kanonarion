package golist

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
)

// listStub is a go that logs its arguments and frame variables and lists
// nothing.
func listStub(t *testing.T) (goBin, logPath string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stub is a shell script")
	}
	dir := t.TempDir()
	logPath = filepath.Join(dir, "children.log")
	body := "#!/bin/sh\n" + `echo "$* | GOOS=$GOOS GOARCH=$GOARCH GOARM=$GOARM GOROOT=$GOROOT CGO=$CGO_ENABLED" >> ` + logPath + "\n"
	goBin = filepath.Join(dir, "go")
	if err := os.WriteFile(goBin, []byte(body), 0o700); err != nil { // #nosec G306 -- test stub must be executable
		t.Fatal(err)
	}
	return goBin, logPath
}

func loggedChildren(t *testing.T, logPath string) []string {
	t.Helper()
	raw, err := os.ReadFile(logPath) // #nosec G304 -- the test's own log
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

// The declared frame reaches every go list: its platform and GOROOT in the
// environment, its tags as -tags right after the subcommand.
func TestBuildModules_ListsUnderTheDeclaredFrame(t *testing.T) {
	goBin, logPath := listStub(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o750); err != nil {
		t.Fatal(err)
	}
	pico, err := goenv.NewTinyGo("pico", "0.42.0", "go1.27.2", "linux", "arm", "6", root, []string{"tinygo", "pico"})
	if err != nil {
		t.Fatal(err)
	}
	a := New(goBin).WithTinyGo(pico)
	if _, err := a.BuildModules(context.Background(), t.TempDir()); err != nil {
		t.Fatalf("BuildModules: %v", err)
	}
	if _, err := a.AnalyseImports(context.Background(), t.TempDir()); err != nil {
		t.Fatalf("AnalyseImports: %v", err)
	}
	frame := " | GOOS=linux GOARCH=arm GOARM=6 GOROOT=" + root + " CGO=1"
	want := []string{"list -tags=tinygo,pico -json -deps ./..." + frame, "list -tags=tinygo,pico -json -deps -test ./..." + frame}
	if got := loggedChildren(t, logPath); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("children = %q, want %q", got, want)
	}
}

// With nothing declared the host pair is pinned, whatever the shell exports.
func TestBuildModules_PinsTheHostPair(t *testing.T) {
	goBin, logPath := listStub(t)
	t.Setenv("GOOS", "plan9")
	t.Setenv("GOARCH", "386")
	if _, err := New(goBin).BuildModules(context.Background(), t.TempDir()); err != nil {
		t.Fatalf("BuildModules: %v", err)
	}
	host := goenv.Host()
	got := loggedChildren(t, logPath)
	if len(got) != 1 || !strings.HasPrefix(got[0], "list -json -deps ./... | GOOS="+host.GOOS()+" GOARCH="+host.GOARCH()+" ") {
		t.Errorf("children = %q, want the host pair", got)
	}
}
