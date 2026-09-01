package goenv_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
)

// fakeSDK writes a directory that looks to this package exactly like an unpacked
// Go toolchain: a VERSION file naming itself and an executable bin/go. version is
// what the VERSION file says, which is deliberately a separate argument from the
// directory name so a test can make the two disagree.
func fakeSDK(t *testing.T, dir, version string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o750); err != nil {
		t.Fatalf("MkdirAll %s: %v", dir, err)
	}
	if version != "" {
		content := version + "\ntime 2026-08-11T00:40:52Z\n"
		if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte(content), 0o600); err != nil {
			t.Fatalf("writing VERSION: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "bin", "go"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { // #nosec G306 -- a toolchain command must be executable to be one
		t.Fatalf("writing bin/go: %v", err)
	}
	return dir
}

// isolate points the search at two empty directories, so a test says everything
// about what is on disk and the developer's own ~/sdk and module cache say
// nothing.
func isolate(t *testing.T) (home, modcache string) {
	t.Helper()
	home, modcache = t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GOMODCACHE", modcache)
	t.Setenv("GOENV", "off")
	return home, modcache
}

func names(tcs []goenv.OnDiskToolchain) []string {
	out := make([]string, 0, len(tcs))
	for _, tc := range tcs {
		out = append(out, tc.Name)
	}
	return out
}

// TestOnDiskToolchainsAtLeast_SearchesTheInstalledSDKBeforeTheModuleCache pins
// the stated order. Both copies are the same toolchain, so the choice only shows
// up in which root is offered — and it matters because the module cache is a
// cache: `go clean -modcache` removes its copy and nobody expects that to change
// which toolchain an analysis used.
func TestOnDiskToolchainsAtLeast_SearchesTheInstalledSDKBeforeTheModuleCache(t *testing.T) {
	home, modcache := isolate(t)
	sdk := fakeSDK(t, filepath.Join(home, "sdk", "go1.26.6"), "go1.26.6")
	fakeSDK(t, filepath.Join(modcache, "golang.org",
		"toolchain@v0.0.1-go1.26.6."+runtime.GOOS+"-"+runtime.GOARCH), "go1.26.6")

	found := goenv.OnDiskToolchainsAtLeast("1.26.6")

	if len(found) != 1 {
		t.Fatalf("found %v, want the one toolchain offered once", names(found))
	}
	if found[0].Root != sdk {
		t.Errorf("offered the toolchain at %s, want the installed SDK at %s", found[0].Root, sdk)
	}
}

// TestOnDiskToolchainsAtLeast_FindsAToolchainTheGoCommandUnpacked is the other
// half of that order: a host with no ~/sdk at all still has whatever the go
// command's own switch left in the module cache, and that is usable offline.
func TestOnDiskToolchainsAtLeast_FindsAToolchainTheGoCommandUnpacked(t *testing.T) {
	_, modcache := isolate(t)
	root := fakeSDK(t, filepath.Join(modcache, "golang.org",
		"toolchain@v0.0.1-go1.26.6."+runtime.GOOS+"-"+runtime.GOARCH), "go1.26.6")

	found := goenv.OnDiskToolchainsAtLeast("1.26.6")

	if len(found) != 1 || found[0].Root != root {
		t.Fatalf("found %v, want the module cache toolchain at %s", names(found), root)
	}
}

// TestOnDiskToolchainsAtLeast_NamesAToolchainByItsOwnVersionFile is the claim the
// name has to make good: it becomes the file name the go command reads a version
// off, so a directory that has been renamed — or an SDK upgraded in place under
// the old name — must be offered as what it IS, never as what it is filed under.
func TestOnDiskToolchainsAtLeast_NamesAToolchainByItsOwnVersionFile(t *testing.T) {
	home, _ := isolate(t)
	fakeSDK(t, filepath.Join(home, "sdk", "go1.20.0"), "go1.30.1")

	found := goenv.OnDiskToolchainsAtLeast("1.26.6")

	if len(found) != 1 || found[0].Name != "go1.30.1" {
		t.Fatalf("found %v, want go1.30.1 — the version the toolchain states, not the one its directory is called", names(found))
	}
}

// TestOnDiskToolchainsAtLeast_ExcludesWhatCannotServe covers every way a
// candidate is not an answer. Each of these would otherwise be offered to an
// analysis that then fails for a second reason, with the first one hidden.
func TestOnDiskToolchainsAtLeast_ExcludesWhatCannotServe(t *testing.T) {
	home, modcache := isolate(t)

	fakeSDK(t, filepath.Join(home, "sdk", "go1.24.0"), "go1.24.0")  // older than needed
	fakeSDK(t, filepath.Join(home, "sdk", "go1.27.0-unpacked"), "") // no VERSION file
	fakeSDK(t, filepath.Join(modcache, "golang.org",                // another platform
		"toolchain@v0.0.1-go1.28.0.plan9-sparc"), "go1.28.0")
	noCommand := filepath.Join(home, "sdk", "go1.29.0")
	fakeSDK(t, noCommand, "go1.29.0")
	if err := os.Chmod(filepath.Join(noCommand, "bin", "go"), 0o600); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	if found := goenv.OnDiskToolchainsAtLeast("1.26.6"); len(found) != 0 {
		t.Fatalf("found %v, want nothing offered", names(found))
	}
}

// TestOnDiskToolchainsAtLeast_RefusesAnUnreadableRequirement: a requirement this
// package cannot order — a prerelease, or anything that is not a Go version at
// all — is never claimed to be satisfied. Guessing would put a toolchain behind
// an analysis that asked for a different one.
func TestOnDiskToolchainsAtLeast_RefusesAnUnreadableRequirement(t *testing.T) {
	home, _ := isolate(t)
	fakeSDK(t, filepath.Join(home, "sdk", "go1.30.0"), "go1.30.0")

	for _, min := range []string{"1.27rc1", "", "tip", "1"} {
		if found := goenv.OnDiskToolchainsAtLeast(min); len(found) != 0 {
			t.Errorf("min %q offered %v, want nothing", min, names(found))
		}
	}
}

// TestToolchainShims_NamesEachLinkAsTheGoCommandLooksForIt. The go command
// searching PATH reads the version off the FILE NAME, so a link under any other
// name is invisible to it and the whole mechanism silently does nothing.
func TestToolchainShims_NamesEachLinkAsTheGoCommandLooksForIt(t *testing.T) {
	home, _ := isolate(t)
	sdk := fakeSDK(t, filepath.Join(home, "sdk", "go1.30.0"), "go1.30.0")

	dir, err := goenv.ToolchainShims(goenv.OnDiskToolchainsAtLeast("1.26.6"))
	if err != nil {
		t.Fatalf("ToolchainShims: %v", err)
	}
	t.Cleanup(func() {
		if rerr := os.RemoveAll(dir); rerr != nil {
			t.Errorf("removing %s: %v", dir, rerr)
		}
	})

	target, err := os.Readlink(filepath.Join(dir, "go1.30.0"))
	if err != nil {
		t.Fatalf("the shim directory holds no go1.30.0: %v", err)
	}
	if want := filepath.Join(sdk, "bin", "go"); target != want {
		t.Errorf("go1.30.0 links to %s, want %s", target, want)
	}
}

// TestWithOnDiskToolchain_ChangesTheToolchainAndNothingElse asserts the
// escalation against the stated posture, with the unescalated environment as the
// base — so every variable the analysis chose has to survive it. The network
// staying off across the switch is the guarantee this whole mechanism exists
// inside.
func TestWithOnDiskToolchain_ChangesTheToolchainAndNothingElse(t *testing.T) {
	base := goenv.Worktree([]string{"PATH=/usr/bin"}, t.TempDir())

	got := goenv.WithOnDiskToolchain(base, "/toolchains")

	checkPosture(t, "on-disk-toolchain", base, got)
	if path, _ := lastEnv(got, "PATH"); path != "/toolchains:/usr/bin" {
		t.Errorf("child PATH = %q, want the shim directory leading the inherited one", path)
	}
	if len(base) != len(goenv.Worktree([]string{"PATH=/usr/bin"}, t.TempDir())) {
		t.Error("WithOnDiskToolchain wrote into the environment it was given")
	}
}

// TestToolchainName_ResolvesALanguageVersionToItsFirstRelease. No toolchain is
// published under a bare language version, so a remedy naming `go1.27` would
// send the reader after a download that does not exist.
func TestToolchainName_ResolvesALanguageVersionToItsFirstRelease(t *testing.T) {
	for version, want := range map[string]string{
		"1.27":   "go1.27.0",
		"1.26.6": "go1.26.6",
		"go1.24": "go1.24.0",
	} {
		if got := goenv.ToolchainName(version); got != want {
			t.Errorf("ToolchainName(%q) = %q, want %q", version, got, want)
		}
	}
}

// TestGoCommand_PathModeCannotDownloadAToolchain is the guarantee the escalation
// rests on, measured against the real go command rather than reasoned about.
//
// `path` is what makes an on-disk toolchain reachable at all, and the reason it
// is safe to reach for is that the go command itself refuses to look anywhere but
// PATH in that mode. With a version nothing on this host provides, it must name
// the version it cannot find and stop — never reach for a proxy, and never leave
// the caller waiting on one.
func TestGoCommand_PathModeCannotDownloadAToolchain(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no go command on PATH: %v", err)
	}
	dir := t.TempDir()
	if werr := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.com/toonew\n\ngo 1.99.0\n"), 0o600); werr != nil {
		t.Fatalf("writing go.mod: %v", werr)
	}

	cmd := exec.Command(goBin, "list", "-m") // #nosec G204 -- binary path from exec.LookPath, literal arguments
	cmd.Dir = dir
	cmd.Env = []string{
		"HOME=" + t.TempDir(), "PATH=" + filepath.Dir(goBin), "GOENV=off",
		"GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=path",
	}
	out, err := cmd.CombinedOutput()

	if err == nil {
		t.Fatalf("go list -m succeeded for a module needing go 1.99.0: %s", out)
	}
	if !strings.Contains(string(out), "cannot find") || !strings.Contains(string(out), "go1.99.0") {
		t.Errorf("go said %q; want it to name the toolchain it could not find in PATH", out)
	}
	if strings.Contains(string(out), "downloading") || strings.Contains(string(out), "checksum database") {
		t.Errorf("go said %q; path mode must not attempt a download", out)
	}
}

// lastEnv resolves a key the way a child process does.
func lastEnv(env []string, key string) (string, bool) {
	value, found := "", false
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			value, found = v, true
		}
	}
	return value, found
}

// TestToolchains_SettlesOncePerOperation. An operation spawning six children
// must not pay six failed first attempts, and must not have two of its children
// measuring one tree under different toolchains. So the decision is taken on the
// first refusal and every later child runs under its answer — including a later
// refusal, which is then reported rather than retried.
func TestToolchains_SettlesOncePerOperation(t *testing.T) {
	home, _ := isolate(t)
	fakeSDK(t, filepath.Join(home, "sdk", "go1.30.0"), "go1.30.0")
	tc := goenv.NewToolchains()
	t.Cleanup(func() {
		if err := tc.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	base := []string{"PATH=/usr/bin", "GOTOOLCHAIN=local"}

	if got, _ := lastEnv(tc.Apply(base), "GOTOOLCHAIN"); got != "local" {
		t.Errorf("before any refusal the child sees GOTOOLCHAIN=%q, want the installed toolchain", got)
	}

	refusal := "go: go.mod requires go >= 1.28 (running go 1.26.5; GOTOOLCHAIN=local)"
	retry, unavailable := tc.Escalate(refusal)
	if !retry || unavailable != "" {
		t.Fatalf("Escalate = (%t, %q), want a retry: go1.30.0 is on this host and satisfies 1.28", retry, unavailable)
	}
	if got, _ := lastEnv(tc.Apply(base), "GOTOOLCHAIN"); got != "path" {
		t.Errorf("after the escalation the child sees GOTOOLCHAIN=%q, want path", got)
	}
	if tc.Selected() != "go1.30.0" {
		t.Errorf("Selected = %q, want the toolchain it staged", tc.Selected())
	}

	retry, unavailable = tc.Escalate(refusal)
	if retry || unavailable != "" {
		t.Errorf("a second Escalate returned (%t, %q); the retry happens once and the operation then reports "+
			"whatever it found", retry, unavailable)
	}
}

// TestToolchains_RefusesInKanonarionsOwnName. The go command's sentence cannot
// say who pinned the toolchain, so a reader sees GOTOOLCHAIN in an error and
// cannot tell their own shell from this tool's posture.
func TestToolchains_RefusesInKanonarionsOwnName(t *testing.T) {
	isolate(t)
	tc := goenv.NewToolchains()
	reported := "go: go.mod requires go >= 1.28 (running go 1.26.5; GOTOOLCHAIN=local)"

	retry, refusal := tc.Escalate(reported)

	if retry {
		t.Fatal("Escalate asked for a retry with no toolchain on this host to retry under")
	}
	for _, want := range []string{"kanonarion pins the toolchain", "go >= 1.28", "golang.org/dl/go1.28.0", reported} {
		if !strings.Contains(refusal, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, refusal)
		}
	}
}

// TestToolchains_IgnoresAFailureThatIsNotTheToolchainGap: a compile error, a
// cold module cache and a missing checksum line all arrive on the same channel,
// and none of them is answered by a different Go.
func TestToolchains_IgnoresAFailureThatIsNotTheToolchainGap(t *testing.T) {
	home, _ := isolate(t)
	fakeSDK(t, filepath.Join(home, "sdk", "go1.30.0"), "go1.30.0")
	tc := goenv.NewToolchains()

	for _, detail := range []string{
		"go: module lookup disabled by GOPROXY=off",
		"./doc.go:3:2: this package requires go >= 1.22 to build",
		"",
	} {
		retry, refusal := tc.Escalate(detail)
		if retry || refusal != "" {
			t.Errorf("Escalate(%q) = (%t, %q), want neither", detail, retry, refusal)
		}
	}
}
