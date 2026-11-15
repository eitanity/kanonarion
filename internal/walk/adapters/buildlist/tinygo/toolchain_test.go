package tinygo_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/goenv"
	"code.eitanity.com/kanonarion/internal/walk/adapters/buildlist/tinygo"
)

// fakeGo writes a stand-in go answering with body, logging per call its working
// directory, GOTOOLCHAIN, GOPROXY and arguments, and returns it with its log.
func fakeGo(t *testing.T, body string) (bin, log string) {
	t.Helper()
	dir := t.TempDir()
	bin, log = filepath.Join(dir, "go"), filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\necho \"$(pwd -P)|$GOTOOLCHAIN|$GOPROXY|$*\" >> " + log + "\n" + body + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test fixture
		t.Fatal(err)
	}
	return bin, log
}

func calls(t *testing.T, log string) []string {
	t.Helper()
	b, err := os.ReadFile(log) // #nosec G304 -- the log fakeGo wrote
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

// isolate leaves no toolchain on disk but the ones a test unpacks.
func isolate(t *testing.T) (home string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GOMODCACHE", t.TempDir())
	t.Setenv("GOENV", "off")
	return home
}

const refuses = `echo "go: go.mod requires go >= %s (running go 1.27.2; GOTOOLCHAIN=local)" >&2; exit 1`

func TestToolchain_IsTheInstalledOneWhenItSatisfiesTheTree(t *testing.T) {
	isolate(t)
	bin, log := fakeGo(t, `if [ "$1" = env ]; then printf 'go1.27.2\n/opt/go\n'; fi`)
	dir := t.TempDir()
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}

	tc, err := tinygo.Toolchain(context.Background(), bin, dir)

	if err != nil || tc != (goenv.OnDiskToolchain{Name: "go1.27.2", Root: "/opt/go"}) {
		t.Fatalf("Toolchain = %+v, %v", tc, err)
	}
	for _, c := range calls(t, log) {
		if !strings.HasPrefix(c, real+"|local|off|") {
			t.Errorf("a child ran as %q, want in %s with GOTOOLCHAIN=local and GOPROXY=off", c, real)
		}
	}
}

// A tree whose go line the installed Go does not satisfy merges from one
// already unpacked here, as goenv.Toolchains settles it.
func TestToolchain_IsOneUnpackedHereWhenTheInstalledOneIsTooOld(t *testing.T) {
	home := isolate(t)
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
	bin, _ := fakeGo(t, `if [ "$GOTOOLCHAIN" != path ]; then `+strings.Replace(refuses, "%s", "1.27.9", 1)+`; fi
if [ "$1" = env ]; then printf 'go1.27.9\n`+sdk+`\n'; fi`)

	tc, err := tinygo.Toolchain(context.Background(), bin, t.TempDir())

	if err != nil || tc != (goenv.OnDiskToolchain{Name: "go1.27.9", Root: sdk}) {
		t.Fatalf("Toolchain = %+v, %v", tc, err)
	}
}

// A tree no toolchain on this host satisfies is refused by name, never served
// by a download.
func TestToolchain_RefusesATreeNoHostToolchainSatisfies(t *testing.T) {
	isolate(t)
	bin, _ := fakeGo(t, strings.Replace(refuses, "%s", "1.99.0", 1))

	_, err := tinygo.Toolchain(context.Background(), bin, t.TempDir())

	if err == nil || !strings.Contains(err.Error(), "needs go >= 1.99.0") || !strings.Contains(err.Error(), "go1.99.0") {
		t.Fatalf("Toolchain = %v, want the refusal naming go1.99.0", err)
	}
}

// Any other failure of the list is the tree's, reported by the child that meets
// it, so the installed toolchain is named.
func TestToolchain_LeavesAnotherFailureToTheChildThatMeetsIt(t *testing.T) {
	isolate(t)
	bin, _ := fakeGo(t, `if [ "$1" = list ]; then echo "go: errors parsing go.mod" >&2; exit 1; fi
printf 'go1.27.2\n/opt/go\n'`)

	tc, err := tinygo.Toolchain(context.Background(), bin, t.TempDir())

	if err != nil || tc.Name != "go1.27.2" {
		t.Fatalf("Toolchain = %+v, %v", tc, err)
	}
}

func TestToolchain_ReportsAToolchainThatCannotNameItself(t *testing.T) {
	isolate(t)
	for name, body := range map[string]string{
		"env fails":   `if [ "$1" = env ]; then echo "env broke" >&2; exit 2; fi`,
		"one line":    `if [ "$1" = env ]; then echo go1.27.2; fi`,
		"prints none": `exit 0`,
	} {
		t.Run(name, func(t *testing.T) {
			bin, _ := fakeGo(t, body)
			_, err := tinygo.Toolchain(context.Background(), bin, t.TempDir())
			if err == nil {
				t.Fatal("a toolchain that named nothing was accepted")
			}
			if name == "env fails" && !strings.Contains(err.Error(), "env broke") {
				t.Errorf("%v does not carry the go command's own account", err)
			}
		})
	}
}

// With no tree, go from PATH is asked in a directory of its own, never in this
// process's working directory.
func TestToolchain_AsksATreelessQuestionInAFreshDirectory(t *testing.T) {
	isolate(t)
	bin, log := fakeGo(t, `if [ "$1" = env ]; then printf 'go1.27.2\n/opt/go\n'; fi`)
	t.Setenv("PATH", filepath.Dir(bin))
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if wd, err = filepath.EvalSymlinks(wd); err != nil {
		t.Fatal(err)
	}

	if _, err := tinygo.Toolchain(context.Background(), "", ""); err != nil {
		t.Fatalf("Toolchain: %v", err)
	}
	for _, c := range calls(t, log) {
		if strings.HasPrefix(c, wd+"|") {
			t.Errorf("a treeless question ran in this process's directory: %q", c)
		}
	}

	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))
	if _, err := tinygo.Toolchain(context.Background(), "", ""); err == nil || !strings.Contains(err.Error(), "a directory to ask") {
		t.Errorf("Toolchain with no temp directory = %v", err)
	}
}

// unpack writes an SDK named name under home's sdk and returns its root.
func unpack(t *testing.T, home, name string) string {
	t.Helper()
	sdk := filepath.Join(home, "sdk", name)
	if err := os.MkdirAll(filepath.Join(sdk, "bin"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sdk, "VERSION"), []byte(name+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sdk, "bin", "go"), []byte("#!/bin/sh\n"), 0o700); err != nil { // #nosec G306 -- a toolchain command must be executable
		t.Fatal(err)
	}
	return sdk
}

// A walk's toolchain is the installed go when it is that version, otherwise
// the one unpacked under exactly that name, never a newer one, never a download.
func TestNamedToolchain_IsTheWalksToolchain(t *testing.T) {
	home := isolate(t)
	newer := unpack(t, home, "go1.27.4")
	exact := unpack(t, home, "go1.27.3")
	bin, log := fakeGo(t, `printf 'go1.27.2\n/opt/go\n'`)
	ctx := context.Background()

	if tc, err := tinygo.NamedToolchain(ctx, bin, "go1.27.2"); err != nil || tc != (goenv.OnDiskToolchain{Name: "go1.27.2", Root: "/opt/go"}) {
		t.Errorf("NamedToolchain(installed) = %+v, %v", tc, err)
	}
	if tc, err := tinygo.NamedToolchain(ctx, bin, "go1.27.3"); err != nil || tc != (goenv.OnDiskToolchain{Name: "go1.27.3", Root: exact}) {
		t.Errorf("NamedToolchain(unpacked) = %+v, %v; not %s", tc, err, newer)
	}
	_, err := tinygo.NamedToolchain(ctx, bin, "go1.99.0")
	if err == nil || !strings.Contains(err.Error(), "go1.99.0") || !strings.Contains(err.Error(), "never downloads") {
		t.Errorf("NamedToolchain(absent) = %v, want a refusal naming go1.99.0", err)
	}
	for _, c := range calls(t, log) {
		if !strings.Contains(c, "|local|off|env GOVERSION GOROOT") {
			t.Errorf("a child ran as %q, want only the pinned, offline env query", c)
		}
	}
}

func TestNamedToolchain_ReportsWhatItCouldNotAsk(t *testing.T) {
	isolate(t)
	bin, _ := fakeGo(t, `echo "env broke" >&2; exit 2`)
	if _, err := tinygo.NamedToolchain(context.Background(), bin, "go1.27.3"); err == nil || !strings.Contains(err.Error(), "env broke") {
		t.Errorf("NamedToolchain = %v", err)
	}
	t.Setenv("PATH", filepath.Dir(bin))
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))
	if _, err := tinygo.NamedToolchain(context.Background(), "", "go1.27.3"); err == nil || !strings.Contains(err.Error(), "a directory to ask") {
		t.Errorf("NamedToolchain with no temp directory = %v", err)
	}
}
