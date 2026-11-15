package cgchild

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/goenv"
	"code.eitanity.com/kanonarion/internal/exitcode"
	"code.eitanity.com/kanonarion/internal/walk/adapters/buildlist/tinygotest"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// The frame is merged from the toolchain the tree resolves: every tinygo child
// names it in GOTOOLCHAIN and leads PATH with its bin. A tree no toolchain here
// satisfies is an invocation error.
func TestProbeTinyGo_MergesFromTheTreesToolchain(t *testing.T) {
	fake := tinygotest.Install(t, map[string]tinygotest.Target{"pico": tinygotest.Pico()})
	t.Setenv("PATH", fake.Dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOMODCACHE", t.TempDir())
	t.Setenv("GOENV", "off")
	root := t.TempDir()
	goBin := filepath.Join(t.TempDir(), "go")
	script := "#!/bin/sh\n[ -f \"$(pwd)/too-old\" ] && { echo 'go: go.mod requires go >= 1.99.0 (running go 1.27.2; GOTOOLCHAIN=local)' >&2; exit 1; }\n" +
		"[ \"$1\" = env ] && printf 'go1.27.9\\n" + root + "\\n'\nexit 0\n"
	if err := os.WriteFile(goBin, []byte(script), 0o700); err != nil { // #nosec G306 -- a stand-in go must be executable
		t.Fatal(err)
	}

	if _, _, err := ProbeTinyGo(context.Background(), "pico", goBin, t.TempDir()); err != nil {
		t.Fatalf("ProbeTinyGo: %v", err)
	}
	envs := fake.Envs(t)
	if len(envs) == 0 {
		t.Fatal("no tinygo child ran")
	}
	for _, e := range envs {
		if f := strings.Fields(e); len(f) < 2 || f[0] != "go1.27.9" || f[1] != filepath.Join(root, "bin") {
			t.Errorf("a tinygo child saw %q, want GOTOOLCHAIN=go1.27.9 and %s first on PATH", e, filepath.Join(root, "bin"))
		}
	}

	old := t.TempDir()
	if err := os.WriteFile(filepath.Join(old, "too-old"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := ProbeTinyGo(context.Background(), "pico", goBin, old)
	var ee *exitcode.Error
	if !errors.As(err, &ee) || ee.Code != exitcode.Config || !strings.Contains(err.Error(), "go1.99.0") {
		t.Errorf("ProbeTinyGo on a tree no toolchain here satisfies = %v, want a Config refusal naming go1.99.0", err)
	}
}

// A walk's TinyGo frame merges from the toolchain the walk resolved under, not
// the installed one; a host without it refuses by name.
func TestAdoptBuildEnv_MergesFromTheWalksToolchain(t *testing.T) {
	fake := tinygotest.Install(t, map[string]tinygotest.Target{"pico": tinygotest.Pico()})
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GOMODCACHE", t.TempDir())
	t.Setenv("GOENV", "off")
	sdk := filepath.Join(home, "sdk", "go1.27.9")
	if err := os.MkdirAll(filepath.Join(sdk, "bin"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sdk, "VERSION"), []byte("go1.27.9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sdk, "bin", "go"), []byte("#!/bin/sh\n"), 0o700); err != nil { // #nosec G306 -- a toolchain command must be executable
		t.Fatal(err)
	}
	goDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(goDir, "go"), []byte("#!/bin/sh\nprintf 'go1.27.2\\n/opt/go\\n'\n"), 0o700); err != nil { // #nosec G306 -- a stand-in go must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", strings.Join([]string{fake.Dir, goDir, "/usr/bin", "/bin"}, string(os.PathListSeparator)))
	env := walkdomain.BuildEnv{GOOS: "linux", GOARCH: "arm", GoVersion: "go1.27.9", TinyGoTarget: "pico"}

	var got goenv.TinyGo
	if err := AdoptBuildEnv(context.Background(), env, func(_ goenv.Target, f goenv.TinyGo) { got = f }); err != nil {
		t.Fatalf("AdoptBuildEnv: %v", err)
	}
	if !got.Declared() {
		t.Fatal("no frame was declared")
	}
	for _, e := range fake.Envs(t) {
		if f := strings.Fields(e); len(f) < 2 || f[0] != "go1.27.9" || f[1] != filepath.Join(sdk, "bin") {
			t.Errorf("a tinygo child saw %q, want GOTOOLCHAIN=go1.27.9 and %s first on PATH", e, filepath.Join(sdk, "bin"))
		}
	}

	env.GoVersion = "go1.99.0"
	err := AdoptBuildEnv(context.Background(), env, func(goenv.Target, goenv.TinyGo) {})
	var ee *exitcode.Error
	if !errors.As(err, &ee) || ee.Code != exitcode.Config || !strings.Contains(err.Error(), "go1.99.0") {
		t.Errorf("AdoptBuildEnv for an absent toolchain = %v, want a Config refusal naming go1.99.0", err)
	}
}
