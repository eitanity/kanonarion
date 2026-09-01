package goenv_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
)

// noScratchDir makes os.MkdirTemp fail for the rest of the test by pointing the
// temporary directory at one nothing can be created in.
//
// Every t.TempDir() a test wants must be taken BEFORE this is called, because
// t.TempDir() creates under the same setting. That ordering is the whole of the
// difficulty this branch was previously left untested for; it costs one line.
func noScratchDir(t *testing.T) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "no-scratch")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatalf("creating the read-only scratch dir: %v", err)
	}
	t.Setenv("TMPDIR", dir)
}

// TestToolchains_StagingFailureIsReportedAsThisHostsFault is the third outcome
// Escalate has, and the one no test held: the toolchain the module needs IS on
// this host, and the operation still cannot reach it.
//
// It must not be answered with the missing-toolchain refusal, which tells the
// reader to install something they already have, and it must not be answered
// with a retry, which would run the same child under the same toolchain again.
func TestToolchains_StagingFailureIsReportedAsThisHostsFault(t *testing.T) {
	home, _ := isolate(t)
	fakeSDK(t, filepath.Join(home, "sdk", "go1.30.0"), "go1.30.0")
	noScratchDir(t)
	tc := goenv.NewToolchains()
	reported := "go: go.mod requires go >= 1.28 (running go 1.26.5; GOTOOLCHAIN=local)"

	retry, refusal := tc.Escalate(reported)

	if retry {
		t.Fatal("Escalate asked for a retry after failing to stage the toolchain the retry would have used")
	}
	for _, want := range []string{"kanonarion found go1.30.0 on this host", "could not stage it", reported} {
		if !strings.Contains(refusal, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, refusal)
		}
	}
	if strings.Contains(refusal, "golang.org/dl/") {
		t.Errorf("the refusal tells the reader to install a toolchain this host already has:\n%s", refusal)
	}
	if tc.Selected() != "" {
		t.Errorf("Selected = %q after a staging failure; nothing was staged and no child ran under anything",
			tc.Selected())
	}
	if err := tc.Close(); err != nil {
		t.Errorf("Close after a staging failure: %v", err)
	}
}

// TestToolchainShims_ReportsAScratchDirectoryItCannotCreate holds the same
// failure at the producer, where the error is raised.
func TestToolchainShims_ReportsAScratchDirectoryItCannotCreate(t *testing.T) {
	home, _ := isolate(t)
	root := fakeSDK(t, filepath.Join(home, "sdk", "go1.30.0"), "go1.30.0")
	noScratchDir(t)

	dir, err := goenv.ToolchainShims([]goenv.OnDiskToolchain{{Name: "go1.30.0", Root: root}})

	if err == nil {
		t.Fatalf("ToolchainShims staged into %q with no directory it could create", dir)
	}
	if dir != "" {
		t.Errorf("ToolchainShims returned %q alongside an error; a caller putting that on PATH would lead it "+
			"with a directory holding no toolchain", dir)
	}
	if !strings.Contains(err.Error(), "creating toolchain directory") {
		t.Errorf("the error does not say what it failed to do: %v", err)
	}
}

// TestToolchainShims_LeavesNothingBehindWhenALinkFails: the directory is the
// caller's to remove only when it is handed one, so a producer that fails
// halfway has to clean up its own partial work rather than leak it.
func TestToolchainShims_LeavesNothingBehindWhenALinkFails(t *testing.T) {
	home, _ := isolate(t)
	good := fakeSDK(t, filepath.Join(home, "sdk", "go1.30.0"), "go1.30.0")

	// Two toolchains claiming the same name: the first link is made, the second
	// finds the name taken and fails.
	_, err := goenv.ToolchainShims([]goenv.OnDiskToolchain{
		{Name: "go1.30.0", Root: good},
		{Name: "go1.30.0", Root: good},
	})

	if err == nil {
		t.Fatal("ToolchainShims staged two toolchains under one name")
	}
	if !strings.Contains(err.Error(), "linking go1.30.0") {
		t.Errorf("the error does not name the link that failed: %v", err)
	}
}

// TestFor_UnknownPostureIsRefused: a caller naming a posture that does not exist
// must fail rather than assert nothing, which is the failure mode a table of
// this shape has.
func TestFor_UnknownPostureIsRefused(t *testing.T) {
	if _, ok := goenv.For("no-such-surface"); ok {
		t.Error("For answered for a posture nothing states")
	}
	if _, ok := goenv.For("worktree"); !ok {
		t.Error("For refused a posture the table states")
	}
}

// TestVerify_ReportsBothWaysAnEnvironmentCanDepart holds the checker itself. It
// is the thing every posture assertion in this repository is built on, so a
// checker that silently passed would take every one of them with it.
func TestVerify_ReportsBothWaysAnEnvironmentCanDepart(t *testing.T) {
	p, ok := goenv.For("worktree")
	if !ok {
		t.Fatal("the worktree posture is not stated")
	}
	base := []string{"PATH=/usr/bin"}

	got := goenv.Verify(p, base, []string{"PATH=/usr/bin", "GOPROXY=direct", "GOMODCACHE=/tmp/cache"})

	var required, forbidden bool
	for _, v := range got {
		switch {
		case strings.Contains(v, `child sees GOPROXY="direct"`):
			required = true
		case strings.Contains(v, `producer set GOMODCACHE="/tmp/cache"`):
			forbidden = true
		}
	}
	if !required {
		t.Errorf("a required variable set to the wrong value was not reported:\n%s", strings.Join(got, "\n"))
	}
	if !forbidden {
		t.Errorf("a forbidden variable the producer added was not reported:\n%s", strings.Join(got, "\n"))
	}
}

// TestWorktree_AnExplicitGOWORKDecidesForTheDirectory pins the go command's own
// resolution order for the case a directory search never reaches: GOWORK naming
// a file settles the question, and it settles it either way — a workspace that
// exists is in scope wherever the directory sits, and one that does not is not.
func TestWorktree_AnExplicitGOWORKDecidesForTheDirectory(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(t.TempDir(), "go.work")
	if err := os.WriteFile(work, []byte("go 1.21\n"), 0o600); err != nil {
		t.Fatalf("writing go.work: %v", err)
	}

	// A tree with no go.work of its own, and GOWORK naming one elsewhere.
	checkPosture(t, "worktree-workspace", []string{"PATH=/usr/bin", "GOWORK=" + work},
		goenv.Worktree([]string{"PATH=/usr/bin", "GOWORK=" + work}, dir))

	// GOWORK naming a file that is not there is not a workspace.
	absent := []string{"PATH=/usr/bin", "GOWORK=" + filepath.Join(dir, "absent.work")}
	checkPosture(t, "worktree", absent, goenv.Worktree(absent, dir))
}

// TestHigherGoVersion_AnUnparsableVersionIsNotAnOrdering: the conservative half
// of the rule these comparisons feed. A candidate nobody can parse is never
// offered to an analysis, and a requirement nobody can parse is never claimed to
// be satisfied — so both directions answer false rather than guessing.
func TestHigherGoVersion_AnUnparsableVersionIsNotAnOrdering(t *testing.T) {
	for _, tc := range []struct{ x, y string }{
		{"1.27rc1", "1.26.6"},
		{"1.26.6", "1.27rc1"},
		{"", "1.26.6"},
		{"1.26.6.1", "1.26.6"},
	} {
		if goenv.HigherGoVersion(tc.x, tc.y) {
			t.Errorf("HigherGoVersion(%q, %q) = true; an ordering that cannot be established is not an ordering", tc.x, tc.y)
		}
	}
}

// TestValue_ReadsTheUserConfigDirWhenGOENVIsUnset is the resolution branch every
// other test in this package steps around by pinning GOENV: with the variable
// unset the go command reads os.UserConfigDir()/go/env, and an operator who
// declared their air gap with `go env -w` is invisible to anything that does
// not.
func TestValue_ReadsTheUserConfigDirWhenGOENVIsUnset(t *testing.T) {
	config := t.TempDir()
	if err := os.MkdirAll(filepath.Join(config, "go"), 0o750); err != nil {
		t.Fatalf("creating the go config dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(config, "go", "env"), []byte("GOPROXY=off\n"), 0o600); err != nil {
		t.Fatalf("writing the env file: %v", err)
	}
	t.Setenv("GOENV", "")
	t.Setenv("XDG_CONFIG_HOME", config)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOPROXY", "")

	if got := goenv.Value("GOPROXY"); got != "off" {
		t.Errorf("Value(GOPROXY) = %q, want off read from the user config directory's go/env", got)
	}
	if !goenv.NetworkForbidden() {
		t.Error("an air gap declared with `go env -w GOPROXY=off` was not seen")
	}
}

// TestOnDiskToolchainsAtLeast_IgnoresADirectoryThatNamesNoRelease: a GOROOT
// built from source names itself "devel …", and a development toolchain cannot
// be ordered against a requirement — so it is not a candidate rather than an
// unknown one.
func TestOnDiskToolchainsAtLeast_IgnoresADirectoryThatNamesNoRelease(t *testing.T) {
	home, _ := isolate(t)
	fakeSDK(t, filepath.Join(home, "sdk", "go1.30.0"), "devel go1.31-abcdef")

	if got := goenv.OnDiskToolchainsAtLeast("1.28"); len(got) != 0 {
		t.Errorf("OnDiskToolchainsAtLeast offered %v; a toolchain that names no release cannot be shown to satisfy anything", names(got))
	}
}

// TestToolchains_IgnoresASentenceItCannotReadAVersionOutOf: the marker and the
// version are two separate reads, and prose can carry the first without the
// second. Answering anyway would mean inventing the requirement an escalation is
// then judged against.
func TestToolchains_IgnoresASentenceItCannotReadAVersionOutOf(t *testing.T) {
	home, _ := isolate(t)
	fakeSDK(t, filepath.Join(home, "sdk", "go1.30.0"), "go1.30.0")
	tc := goenv.NewToolchains()

	retry, refusal := tc.Escalate("go: something requires go >= latest (running go 1.26.5)")

	if retry || refusal != "" {
		t.Errorf("Escalate = (%t, %q) for a sentence naming no readable version", retry, refusal)
	}
}

// TestValue_NoConfigDirectoryIsNoEnvFile: with neither GOENV nor a user config
// directory there is nowhere to read, and that is an empty answer rather than a
// failure — a process that cannot locate the file is in exactly the position of
// one for which it does not exist.
func TestValue_NoConfigDirectoryIsNoEnvFile(t *testing.T) {
	t.Setenv("GOENV", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	t.Setenv("GOPROXY", "")

	if got := goenv.Value("GOPROXY"); got != "" {
		t.Errorf("Value(GOPROXY) = %q with no env file to read", got)
	}
}
