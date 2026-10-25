package tinycgo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeCompiler(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil { // #nosec G306 -- an executable test fixture
		t.Fatal(err)
	}
	return p
}

// Both branches of the rule: clang wins wherever it is on PATH, and without it
// the highest clang-N does, numerically rather than by name.
func TestFindCompiler_ClangFirstThenTheHighestVersion(t *testing.T) {
	versioned, plain := t.TempDir(), t.TempDir()
	fakeCompiler(t, versioned, "clang-19", "")
	want := fakeCompiler(t, versioned, "clang-21", "")
	fakeCompiler(t, versioned, "clang-3", "")
	fakeCompiler(t, versioned, "clang-format", "")
	fakeCompiler(t, versioned, "clang-21.1", "")
	if err := os.WriteFile(filepath.Join(versioned, "clang-99"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(versioned, "clang-100"), 0o750); err != nil {
		t.Fatal(err)
	}

	got, err := FindCompiler(versioned + string(os.PathListSeparator) + filepath.Join(versioned, "missing"))
	if err != nil || got != want {
		t.Errorf("versioned only: %q, %v; want %q (clang-99 is not executable, clang-100 is a directory)", got, err, want)
	}

	clang := fakeCompiler(t, plain, "clang", "")
	got, err = FindCompiler(versioned + string(os.PathListSeparator) + plain)
	if err != nil || got != clang {
		t.Errorf("with clang later on PATH: %q, %v; want %q", got, err, clang)
	}

	_, err = FindCompiler(t.TempDir())
	if !errors.Is(err, ErrNoCompiler) || err.Error() != "no C compiler found on PATH (looked for clang, then clang-<N>)" {
		t.Errorf("no compiler: %v", err)
	}
}

func TestCompiler_ReportsTheFirstDiagnosticLine(t *testing.T) {
	dir := t.TempDir()
	bin := fakeCompiler(t, dir, "clang", `if [ "$1" = --version ]; then echo "fake clang version 21.0.0"; echo "Target: x"; exit 0; fi
echo "In file included from a.c:1:" >&2
echo "a.go:3:5: error: expected expression" >&2
echo "1 error generated." >&2
exit 1`)
	c := compiler{path: bin}
	if v := c.version(context.Background()); v != "fake clang version 21.0.0" {
		t.Errorf("version = %q", v)
	}
	_, err := c.run(context.Background(), "x.c")
	if err == nil || err.Error() != "a.go:3:5: error: expected expression" {
		t.Errorf("run = %v", err)
	}
	quiet := compiler{path: fakeCompiler(t, dir, "quiet", "exit 3")}
	if _, err := quiet.run(context.Background()); err == nil || !strings.Contains(err.Error(), "exit status 3") {
		t.Errorf("a refusal with no stderr = %v", err)
	}
	if v := quiet.version(context.Background()); !strings.HasPrefix(v, "version unknown") {
		t.Errorf("a failed --version = %q", v)
	}
	if got := firstDiagnostic("warning: x\nnote: y"); got != "warning: x" {
		t.Errorf("no error line: %q", got)
	}
}

func TestEnvPath_IsTheLastPATHTheChildSees(t *testing.T) {
	if got := envPath([]string{"PATH=/a", "HOME=/h", "PATH=/b"}); got != "/b" {
		t.Errorf("envPath = %q", got)
	}
	t.Setenv("PATH", "/inherited")
	if got := envPath(nil); got != "/inherited" {
		t.Errorf("envPath(nil) = %q", got)
	}
}
