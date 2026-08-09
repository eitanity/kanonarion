package gitlsremote_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/goenv"
	"github.com/eitanity/kanonarion/internal/stdlib/adapters/gitlsremote"
	"github.com/eitanity/kanonarion/internal/stdlib/domain"
)

// recordingGit installs a fake `git` that logs its argv and answers an
// ls-remote. The standard library's VCS anchor is a child process like the
// module cross-verifier's, so it is measured the same way: what was spawned,
// not what was dialled.
func recordingGit(t *testing.T) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "argv.log")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$*\" >> " + logPath + "\n" +
		"for a in \"$@\"; do\n" +
		"  case \"$a\" in refs/*) printf '%s\\t%s\\n' 2222222222222222222222222222222222222222 \"$a\"; exit 0;; esac\n" +
		"done\n" +
		"exit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o700); err != nil { // #nosec G306 -- an executable stub must be executable
		t.Fatalf("writing git stub: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

func spawnCount(t *testing.T, logPath string) int {
	t.Helper()
	data, err := os.ReadFile(logPath) // #nosec G304 -- path is this test's own temp file
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatalf("reading spawn log: %v", err)
	}
	if strings.TrimSpace(string(data)) == "" {
		return 0
	}
	return len(strings.Split(strings.TrimSpace(string(data)), "\n"))
}

// TestResolveCommit_ControlSpawns is the non-zero control: with the contract
// absent the lookup runs, and its argv names the Go source repository.
func TestResolveCommit_ControlSpawns(t *testing.T) {
	t.Setenv("GOENV", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("GOPROXY", "https://proxy.example.com")
	logPath := recordingGit(t)

	commit, err := gitlsremote.New().ResolveCommit(context.Background(), domain.VCSRepoURL, "go1.26.4")
	if err != nil {
		t.Fatalf("ResolveCommit with the network permitted: %v", err)
	}
	if commit != "2222222222222222222222222222222222222222" {
		t.Errorf("commit = %q", commit)
	}
	if n := spawnCount(t, logPath); n != 1 {
		t.Fatalf("spawn count = %d, want 1", n)
	}
	logged, err := os.ReadFile(logPath) // #nosec G304 -- path is this test's own temp file
	if err != nil {
		t.Fatalf("reading spawn log: %v", err)
	}
	for _, want := range []string{"ls-remote", "--tags", domain.VCSRepoURL, "refs/tags/go1.26.4"} {
		if !strings.Contains(string(logged), want) {
			t.Errorf("constructed argv %q does not contain %q", logged, want)
		}
	}
}

// TestResolveCommit_RefusedUnderAirGap: no subprocess is started, and the
// refusal names what the standard-library record loses — its VCS anchor, not
// its acquisition.
func TestResolveCommit_RefusedUnderAirGap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(path, []byte("GOPROXY=off\n"), 0o600); err != nil {
		t.Fatalf("writing env file: %v", err)
	}
	t.Setenv("GOENV", path)
	t.Setenv("GOPROXY", "")
	logPath := recordingGit(t)

	_, err := gitlsremote.New().ResolveCommit(context.Background(), domain.VCSRepoURL, "go1.26.4")
	if err == nil {
		t.Fatal("ResolveCommit succeeded under a declared air gap")
	}
	if !errors.Is(err, gitlsremote.ErrNetworkForbidden) {
		t.Errorf("error %v does not carry ErrNetworkForbidden", err)
	}
	if !errors.Is(err, goenv.ErrNetworkForbidden) {
		t.Errorf("error %v does not carry the shared no-network fact", err)
	}
	if n := spawnCount(t, logPath); n != 0 {
		t.Errorf("spawn count = %d, want 0: the refusal must precede exec", n)
	}
}
