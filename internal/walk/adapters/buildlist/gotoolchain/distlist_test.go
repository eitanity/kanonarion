package gotoolchain_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/walk/adapters/buildlist/gotoolchain"
)

// requireToolchain skips a test that measures what a real go command does.
func requireToolchain(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("the go toolchain is not on PATH; this test measures real resolution")
	}
}

// TestSupportedTargets_ComesFromTheToolchainInHand pins the authority: the set
// of platforms is read off the installed Go, never compiled in, so a port added
// or dropped by a release moves this answer with it.
func TestSupportedTargets_ComesFromTheToolchainInHand(t *testing.T) {
	requireToolchain(t)

	got, err := gotoolchain.New("", nil).SupportedTargets(context.Background())
	if err != nil {
		t.Fatalf("SupportedTargets: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("the toolchain named no platform")
	}
	want, err := exec.Command("go", "tool", "dist", "list").Output() // #nosec G204 -- fixed binary, literal arguments
	if err != nil {
		t.Fatalf("go tool dist list: %v", err)
	}
	lines := 0
	for _, b := range want {
		if b == '\n' {
			lines++
		}
	}
	if len(got) != lines {
		t.Errorf("SupportedTargets returned %d pairs; `go tool dist list` printed %d", len(got), lines)
	}
	host := false
	for _, tt := range got {
		if tt == goenv.Host() {
			host = true
		}
	}
	if !host {
		t.Errorf("the list does not contain this host's own platform %s", goenv.Host())
	}
}

// TestSupports_RefusesAPairTheToolchainDoesNotBuild is the fail-closed half. The
// toolchain refuses an unlisted pair on its own, but its sentence names neither
// half of the pair, so the refusal has to happen here to be readable.
func TestSupports_RefusesAPairTheToolchainDoesNotBuild(t *testing.T) {
	requireToolchain(t)
	r := gotoolchain.New("", nil)
	unlisted, err := goenv.ParseTarget("windows/riscv64")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}

	ok, offered, err := r.Supports(context.Background(), unlisted)
	if err != nil {
		t.Fatalf("Supports: %v", err)
	}
	if ok {
		t.Errorf("%s reported as supported", unlisted)
	}
	if len(offered) == 0 {
		t.Error("the refusal carries no list of what the toolchain does offer")
	}
}

// TestSupports_UndeclaredAsksNothing is the friction guarantee, stated as a
// property rather than as a timing: the default path must not reach the
// toolchain at all. A go binary that does not exist would fail if it did.
func TestSupports_UndeclaredAsksNothing(t *testing.T) {
	r := gotoolchain.New(filepath.Join(t.TempDir(), "no-such-go"), nil)

	ok, offered, err := r.Supports(context.Background(), goenv.Target{})
	if err != nil {
		t.Fatalf("an undeclared target asked the toolchain a question: %v", err)
	}
	if !ok || offered != nil {
		t.Errorf("Supports(undeclared) = (%t, %d pairs), want (true, no list)", ok, len(offered))
	}
}

// TestBuildEnvironment_RecordsTheDeclaredTargetNotTheInheritedOne is the leak
// this ticket closes, measured where the walk record's frame is produced: an
// export in the parent process must reach no resolution, and a declaration must
// reach every one.
func TestBuildEnvironment_RecordsTheDeclaredTargetNotTheInheritedOne(t *testing.T) {
	requireToolchain(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/frame\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	t.Setenv("GOOS", "windows")
	t.Setenv("GOARCH", "arm64")

	_, goos, goarch := gotoolchain.New("", nil).BuildEnvironment(context.Background(), dir)
	if goos != goenv.Host().GOOS() || goarch != goenv.Host().GOARCH() {
		t.Errorf("with no target declared the probe recorded %s/%s; the inherited export chose the platform, "+
			"and the record cannot say so", goos, goarch)
	}

	declared, err := goenv.ParseTarget("wasip1/wasm")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	_, goos, goarch = gotoolchain.New("", nil).WithTarget(declared).BuildEnvironment(context.Background(), dir)
	if goos != "wasip1" || goarch != "wasm" {
		t.Errorf("the declared target reached the probe as %s/%s, want wasip1/wasm", goos, goarch)
	}
}

// fakeGo writes an executable standing in for the go command, printing the given
// lines on stdout and exiting with code. It is how the failure seams below are
// reached without breaking the real toolchain.
func fakeGo(t *testing.T, stdout string, code int) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "go")
	script := "#!/bin/sh\nprintf '%s' '" + stdout + "'\nexit " + strconv.Itoa(code) + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { // #nosec G306 -- a test stand-in that must be executable
		t.Fatalf("writing the stand-in go: %v", err)
	}
	return bin
}

// TestSupportedTargets_AToolchainThatCannotAnswerIsNotAnEmptyAnswer holds the
// three failure seams apart. Each one must refuse, because answering
// "unsupported" out of a probe that did not work would refuse every pair a
// caller could name.
func TestSupportedTargets_AToolchainThatCannotAnswerIsNotAnEmptyAnswer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stdout string
		code   int
		says   string
	}{
		{name: "non-zero exit", stdout: "", code: 1, says: "go tool dist list"},
		{name: "silence", stdout: "\n\n", code: 0, says: "named no platform"},
		{name: "not a pair", stdout: "linux-amd64\n", code: 0, says: "not a GOOS/GOARCH pair"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := gotoolchain.New(fakeGo(t, tc.stdout, tc.code), nil).SupportedTargets(context.Background())
			if err == nil {
				t.Fatal("a toolchain that could not answer was read as an answer")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("refusal %q does not say %q", err, tc.says)
			}
		})
	}
}

// TestSupportedTargets_IsAskedOncePerToolchain is the friction half of the
// validation: one operation validating several targets must not pay a
// subprocess each time. The stand-in records every invocation, so a second call
// that reached it would show up.
func TestSupportedTargets_IsAskedOncePerToolchain(t *testing.T) {
	dir := t.TempDir()
	bin, log := filepath.Join(dir, "go"), filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho call >> " + log + "\nprintf 'linux/amd64\\nwindows/amd64\\n'\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { // #nosec G306 -- a test stand-in that must be executable
		t.Fatalf("writing the stand-in go: %v", err)
	}
	r := gotoolchain.New(bin, nil)

	for range 3 {
		if _, err := r.SupportedTargets(context.Background()); err != nil {
			t.Fatalf("SupportedTargets: %v", err)
		}
	}

	calls, err := os.ReadFile(log) // #nosec G304 -- written by this test into its own t.TempDir()
	if err != nil {
		t.Fatalf("reading the call log: %v", err)
	}
	if got := strings.Count(string(calls), "call"); got != 1 {
		t.Errorf("the toolchain was asked %d times; the list is memoised per toolchain", got)
	}
}

// TestSupports_ReportsAProbeItCouldNotRun: a target that could not be checked is
// neither supported nor refused as unsupported — the caller is told the check
// failed.
func TestSupports_ReportsAProbeItCouldNotRun(t *testing.T) {
	declared, err := goenv.ParseTarget("windows/amd64")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}

	ok, offered, err := gotoolchain.New(filepath.Join(t.TempDir(), "no-such-go"), nil).
		Supports(context.Background(), declared)

	if err == nil {
		t.Fatal("a probe that could not run reported an answer")
	}
	if ok || offered != nil {
		t.Errorf("Supports = (%t, %d pairs) beside an error", ok, len(offered))
	}
}
