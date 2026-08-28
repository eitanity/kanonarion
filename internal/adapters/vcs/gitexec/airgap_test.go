package gitexec_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/adapters/vcs/gitexec"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// recordingGit puts a fake `git` at the front of $PATH which appends its argv to
// a log and answers an ls-remote with a plausible line.
//
// A stub rather than the real binary, and a log rather than a dial assertion,
// because this member is a CHILD PROCESS: an in-process transport hook cannot
// see the socket git opens, which is exactly how this egress survived the last
// sweep. What can be measured on this side of the fork is whether a process was
// started at all, and with which argv — so that is what these tests measure,
// and no test here needs a network or is satisfied by its absence.
func recordingGit(t *testing.T) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "argv.log")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$*\" >> " + logPath + "\n" +
		"for a in \"$@\"; do\n" +
		"  case \"$a\" in refs/*) printf '%s\\t%s\\n' 1111111111111111111111111111111111111111 \"$a\"; exit 0;; esac\n" +
		"done\n" +
		"exit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o700); err != nil { // #nosec G306 -- an executable stub must be executable
		t.Fatalf("writing git stub: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

func spawns(t *testing.T, logPath string) []string {
	t.Helper()
	data, err := os.ReadFile(logPath) // #nosec G304 -- path is this test's own temp file
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("reading spawn log: %v", err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func permittedGit(t *testing.T) {
	t.Helper()
	t.Setenv("GOENV", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("GOPROXY", "https://proxy.example.com")
}

func airGappedGit(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(path, []byte("GOPROXY=off\n"), 0o600); err != nil {
		t.Fatalf("writing env file: %v", err)
	}
	t.Setenv("GOENV", path)
	t.Setenv("GOPROXY", "")
}

// TestResolveTag_ControlSpawnsWithTheExpectedArgv is the non-zero control: with
// the contract absent a git subprocess IS started, and the argv it is started
// with is the remote lookup. Without this, a guard that refused unconditionally
// would look correct.
func TestResolveTag_ControlSpawnsWithTheExpectedArgv(t *testing.T) {
	permittedGit(t)
	logPath := recordingGit(t)

	commit, err := gitexec.New().ResolveTag(context.Background(), "https://example.com/o/r", "refs/tags/v1.0.0")
	if err != nil {
		t.Fatalf("ResolveTag with the network permitted: %v", err)
	}
	if commit != "1111111111111111111111111111111111111111" {
		t.Errorf("commit = %q", commit)
	}
	got := spawns(t, logPath)
	if len(got) != 1 {
		t.Fatalf("spawn count = %d, want 1; log: %v", len(got), got)
	}
	for _, want := range []string{"ls-remote", "--end-of-options", "https://example.com/o/r", "refs/tags/v1.0.0"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("constructed argv %q does not contain %q", got[0], want)
		}
	}
}

// TestResolveTag_RefusedUnderAirGap: the refusal lands before exec, so the
// stub — which would have recorded any invocation — records nothing.
func TestResolveTag_RefusedUnderAirGap(t *testing.T) {
	airGappedGit(t)
	logPath := recordingGit(t)

	_, err := gitexec.New().ResolveTag(context.Background(), "https://example.com/o/r", "refs/tags/v1.0.0")
	if err == nil {
		t.Fatal("ResolveTag succeeded under a declared air gap")
	}
	assertVCSRefusal(t, err)
	if got := spawns(t, logPath); len(got) != 0 {
		t.Errorf("spawn count = %d, want 0: the refusal must precede exec; log: %v", len(got), got)
	}
}

// TestCheckoutToDir_RefusedUnderAirGap covers the other forge-reaching
// operation. Its first step is a local `git init`, so a guard placed at the
// subprocess would refuse after work had begun; this asserts nothing runs.
func TestCheckoutToDir_RefusedUnderAirGap(t *testing.T) {
	airGappedGit(t)
	logPath := recordingGit(t)

	err := gitexec.New().CheckoutToDir(context.Background(),
		"https://example.com/o/r", "1111111111111111111111111111111111111111", t.TempDir())
	if err == nil {
		t.Fatal("CheckoutToDir succeeded under a declared air gap")
	}
	assertVCSRefusal(t, err)
	if got := spawns(t, logPath); len(got) != 0 {
		t.Errorf("spawn count = %d, want 0; log: %v", len(got), got)
	}
}

// assertVCSRefusal pins how the fetch pipeline is required to count this: as a
// missing VCS leg, exactly as an absent git or --skip-vcs-verify is counted, so
// a module whose checksum-database verification passed still lands on
// VerifiedBySumDBOnly rather than failing the run.
func assertVCSRefusal(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, gitexec.ErrNetworkForbidden) {
		t.Errorf("error %v does not carry ErrNetworkForbidden", err)
	}
	if !errors.Is(err, goenv.ErrNetworkForbidden) {
		t.Errorf("error %v does not carry the shared no-network fact", err)
	}
	if !errors.Is(err, ports.ErrVCSToolMissing) {
		t.Errorf("error %v is not counted as a missing VCS leg", err)
	}
	if !strings.Contains(err.Error(), "--skip-vcs-verify") {
		t.Errorf("refusal %q does not name the remedy", err)
	}
}
