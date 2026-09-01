package goenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsToolchainTooOld pins the marker against the wording the go command
// emits and against two strings that must not match it. Both halves of the
// sentence are required, because the phrase alone appears in module prose.
func TestIsToolchainTooOld(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		detail string
		want   bool
	}{
		{
			name:   "unpinned",
			detail: "meta load: err: exit status 1: stderr: go: go.mod requires go >= 1.26.6 (running go 1.26.5)\n",
			want:   true,
		},
		{
			name:   "pinned names the setting too",
			detail: "go: go.mod requires go >= 1.26.6 (running go 1.26.5; GOTOOLCHAIN=local)\n",
			want:   true,
		},
		{
			name:   "the message this replaces",
			detail: "go: golang.org/toolchain@v0.0.1-go1.26.6.linux-amd64: verifying module: checksum database disabled by GOSUMDB=off\n",
			want:   false,
		},
		{
			name:   "half the phrase in the module's own prose",
			detail: "./doc.go:3:2: this package requires go >= 1.22 to build",
			want:   false,
		},
	} {
		if got := IsToolchainTooOld(tc.detail); got != tc.want {
			t.Errorf("%s: IsToolchainTooOld = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestRequiredGoVersion reads the versions out of the go command's own sentence.
// The highest requirement wins because one load can refuse for several modules
// at once and a toolchain satisfying the largest satisfies them all.
func TestRequiredGoVersion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name             string
		detail           string
		required, runing string
		ok               bool
	}{
		{
			name:     "the main module's own go line",
			detail:   "meta load: err: exit status 1: stderr: go: go.mod requires go >= 1.26.6 (running go 1.26.5; GOTOOLCHAIN=local)",
			required: "1.26.6", runing: "1.26.5", ok: true,
		},
		{
			name:     "a dependency deeper in the graph",
			detail:   "go: module example.com/dep@v1.2.3 requires go >= 1.28 (running go 1.26.5)",
			required: "1.28", runing: "1.26.5", ok: true,
		},
		{
			name: "several refusals in one load",
			detail: "go: a.mod requires go >= 1.27.0 (running go 1.26.5; GOTOOLCHAIN=local)\n" +
				"go: b.mod requires go >= 1.30.2 (running go 1.26.5; GOTOOLCHAIN=local)",
			required: "1.30.2", runing: "1.26.5", ok: true,
		},
		{
			name:   "a module quoting the phrase",
			detail: "package doc says: requires go >= 1.30 to build",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			required, running, ok := requiredGoVersion(c.detail)
			if ok != c.ok || required != c.required || running != c.runing {
				t.Errorf("requiredGoVersion = (%q, %q, %t), want (%q, %q, %t)",
					required, running, ok, c.required, c.runing, c.ok)
			}
		})
	}
}

// TestModCacheDir_ResolvesTheWayTheGoCommandDoes covers the fallbacks the
// happy path never reaches. Getting this wrong silently narrows the search for
// an already-unpacked toolchain to a directory that holds none, and the analysis
// then refuses on a host that could have served it.
func TestModCacheDir_ResolvesTheWayTheGoCommandDoes(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOENV", "off")
	t.Setenv("HOME", home)

	t.Setenv("GOMODCACHE", "/explicit/cache")
	if got, want := modCacheDir(), "/explicit/cache"; got != want {
		t.Errorf("modCacheDir = %q, want the explicit %q", got, want)
	}

	t.Setenv("GOMODCACHE", "")
	t.Setenv("GOPATH", "/first"+string(os.PathListSeparator)+"/second")
	if got, want := modCacheDir(), filepath.Join("/first", "pkg", "mod"); got != want {
		t.Errorf("modCacheDir = %q, want %q: a list is legal in GOPATH and the module cache lives under its first entry", got, want)
	}

	t.Setenv("GOPATH", "")
	if got, want := modCacheDir(), filepath.Join(home, "go", "pkg", "mod"); got != want {
		t.Errorf("modCacheDir = %q, want the default GOPATH %q", got, want)
	}

	t.Setenv("HOME", "")
	if got := modCacheDir(); got != "" {
		t.Errorf("modCacheDir = %q with no home to derive one from; an invented path would be searched and "+
			"silently find nothing", got)
	}
}

// TestClose_ReportsADirectoryItCannotRemove: the staged directory holds symlinks
// into the host's toolchains, and an operation that cannot clean it up must say
// so rather than leak it silently on every scan.
func TestClose_ReportsADirectoryItCannotRemove(t *testing.T) {
	parent := t.TempDir()
	staged := filepath.Join(parent, "shims")
	if err := os.Mkdir(staged, 0o750); err != nil {
		t.Fatalf("creating the staged dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(staged, "go1.30.0"), []byte("x"), 0o600); err != nil {
		t.Fatalf("writing into the staged dir: %v", err)
	}
	if err := os.Chmod(parent, 0o500); err != nil { // #nosec G302 -- making a directory unwritable is the condition under test
		t.Fatalf("making the parent read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o750) }) // #nosec G302 -- restoring the directory so t.TempDir can remove it

	tc := &Toolchains{shimDir: staged}
	err := tc.Close()

	if err == nil {
		t.Fatal("Close reported success for a directory it could not remove")
	}
	if !strings.Contains(err.Error(), staged) {
		t.Errorf("the error does not name the directory left behind: %v", err)
	}
	if err := tc.Close(); err != nil {
		t.Errorf("a second Close reported %v; the directory is no longer this value's to remove", err)
	}
}
