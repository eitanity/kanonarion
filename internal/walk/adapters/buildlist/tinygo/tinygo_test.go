package tinygo_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/adapters/goenv"
	"code.eitanity.com/kanonarion/internal/walk/adapters/buildlist/tinygo"
	"code.eitanity.com/kanonarion/internal/walk/adapters/buildlist/tinygotest"
)

// toolchain is a Go toolchain a frame is merged from; the fake reads only its name.
func toolchain(t *testing.T) goenv.OnDiskToolchain {
	t.Helper()
	return goenv.OnDiskToolchain{Name: "go1.27.9", Root: t.TempDir()}
}

func TestProbe_ReadsTheFourOutputs(t *testing.T) {
	fake := tinygotest.Install(t, map[string]tinygotest.Target{"pico": tinygotest.Pico()})

	f, err := tinygo.Probe(context.Background(), fake.Bin, "pico", toolchain(t))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	if f.Target() != "pico" || f.Version() != "0.42.0" || f.GoVersion() != "go1.27.2" {
		t.Errorf("versions = %s %s %s", f.Target(), f.Version(), f.GoVersion())
	}
	if f.GOOS() != "linux" || f.GOARCH() != "arm" || f.GOARM() != "6" {
		t.Errorf("platform = %s/%s GOARM=%s", f.GOOS(), f.GOARCH(), f.GOARM())
	}
	if f.HostGOOS() != "linux" || f.HostGOARCH() != "amd64" {
		t.Errorf("host = %s/%s, want the platform tinygo version names, which names its release archive", f.HostGOOS(), f.HostGOARCH())
	}
	if want := tinygotest.Pico().Tags; !reflect.DeepEqual(f.Tags(), want) {
		t.Errorf("tags = %v, want %v", f.Tags(), want)
	}
	if want := filepath.Join(fake.Dir, "goroot-pico"); f.GOROOT() != want {
		t.Errorf("GOROOT = %s, want the parent of list's src %s; info's goroot is never read", f.GOROOT(), want)
	}
	if f.SourceRoot() != fake.SourceRoot || f.LLVMTriple() != "thumbv6m-unknown-unknown-eabi" {
		t.Errorf("TINYGOROOT = %s and triple = %s, want %s from env and info's llvm_triple", f.SourceRoot(), f.LLVMTriple(), fake.SourceRoot)
	}
}

func TestProbe_IsMemoisedPerBinaryAndTarget(t *testing.T) {
	fake := tinygotest.Install(t, map[string]tinygotest.Target{"pico": tinygotest.Pico(), "other": tinygotest.Pico()})
	ctx := context.Background()
	tc := toolchain(t)

	for range 3 {
		if _, err := tinygo.Probe(ctx, fake.Bin, "pico", tc); err != nil {
			t.Fatalf("Probe: %v", err)
		}
	}
	if n := len(fake.Calls(t)); n != 4 {
		t.Errorf("three probes of one target ran %d tinygo commands, want the 4 of the first", n)
	}
	if _, err := tinygo.Probe(ctx, fake.Bin, "other", tc); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if n := len(fake.Calls(t)); n != 8 {
		t.Errorf("a second target ran %d commands in all, want 8", n)
	}
}

func TestProbe_NoTinyGoOnPath(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	_, err := tinygo.Probe(context.Background(), "", "pico", toolchain(t))

	if err == nil || err.Error() != "a TinyGo build target needs the tinygo command on PATH" {
		t.Fatalf("Probe = %v", err)
	}
	if !errors.Is(err, tinygo.ErrNotOnPath) {
		t.Error("the refusal is not ErrNotOnPath")
	}
}

func TestProbe_UnknownTarget(t *testing.T) {
	fake := tinygotest.Install(t, nil)

	_, err := tinygo.Probe(context.Background(), fake.Bin, "nosuchboard", toolchain(t))

	want := "tinygo does not know the target \"nosuchboard\": run `tinygo targets` for the names it offers"
	if err == nil || err.Error() != want {
		t.Fatalf("Probe = %v, want %q", err, want)
	}
	if !errors.As(err, new(*tinygo.UnknownTargetError)) {
		t.Error("the refusal is not an UnknownTargetError")
	}
}

// script writes a stand-in tinygo answering with body.
func script(t *testing.T, body string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "tinygo")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil { // #nosec G306 -- an executable test fixture
		t.Fatal(err)
	}
	return bin
}

const versionOK = `if [ "$1" = version ]; then echo "` + tinygotest.VersionLine + `"; exit 0; fi`

func TestProbe_ReportsAFailedProbeWithItsCommandAndStderr(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       []string
	}{
		{"version fails", `echo "broken install" >&2; exit 3`, []string{"tinygo version", "broken install"}},
		{"version unparsable", `echo "tinygo 9"`, []string{"tinygo version printed", "tinygo 9"}},
		{"info not JSON", versionOK + "\necho nope", []string{"tinygo info -json -target=pico", "not its JSON"}},
		{"list fails", versionOK + `
if [ "$1" = info ]; then echo '{"goos":"linux","goarch":"arm"}'; exit 0; fi
echo "list broke" >&2; exit 4`, []string{"tinygo list -target=pico -json runtime", "list broke"}},
		{"list not JSON", versionOK + `
if [ "$1" = info ]; then echo '{"goos":"linux","goarch":"arm"}'; exit 0; fi
echo nope`, []string{"tinygo list -target=pico -json runtime", "not a package's JSON"}},
		{"runtime not under src", versionOK + `
if [ "$1" = info ]; then echo '{"goos":"linux","goarch":"arm"}'; exit 0; fi
echo '{"Dir":"/opt/runtime"}'`, []string{"not under a GOROOT's src"}},
		{"env fails", versionOK + `
if [ "$1" = info ]; then echo '{"goos":"linux","goarch":"arm"}'; exit 0; fi
if [ "$1" = list ]; then echo '{"Dir":"/opt/src/runtime"}'; exit 0; fi
echo "env broke" >&2; exit 5`, []string{"tinygo env TINYGOROOT", "env broke"}},
		{"incomplete frame", versionOK + `
if [ "$1" = info ]; then echo '{"goarch":"arm"}'; exit 0; fi
echo '{"Dir":"/opt/src/runtime"}'`, []string{"described the target \"pico\" incompletely", "GOOS"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tinygo.Probe(context.Background(), script(t, tc.body), "pico", toolchain(t))
			if err == nil {
				t.Fatal("a failed probe was accepted")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("%q does not say %q", err, w)
				}
			}
		})
	}
}

// An info that could not be started is not tinygo saying the target is
// unknown, so it keeps its own error.
func TestProbe_AnInfoThatCouldNotStartIsNotAnUnknownTarget(t *testing.T) {
	bin := script(t, versionOK)
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"+`if [ "$1" = version ]; then rm -f "$0"; echo "`+tinygotest.VersionLine+`"; fi`+"\n"), 0o700); err != nil { // #nosec G306 -- an executable test fixture
		t.Fatal(err)
	}

	_, err := tinygo.Probe(context.Background(), bin, "pico", toolchain(t))

	if err == nil || !strings.Contains(err.Error(), "tinygo info") {
		t.Fatalf("Probe = %v", err)
	}
	if errors.As(err, new(*tinygo.UnknownTargetError)) {
		t.Errorf("a missing binary was reported as an unknown target: %v", err)
	}
}

func TestProbe_ACancelledInfoIsNotAnUnknownTarget(t *testing.T) {
	bin := script(t, versionOK+"\nsleep 30")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := tinygo.Probe(ctx, bin, "pico", toolchain(t))

	if err == nil {
		t.Fatal("a cancelled probe succeeded")
	}
	if errors.As(err, new(*tinygo.UnknownTargetError)) {
		t.Errorf("a cancelled probe was reported as an unknown target: %v", err)
	}
}

// TestProbe_AVersionLineWithoutAPlatformLeavesTheHostUnnamed: the frame is
// still complete, and the release leg then says it cannot name an archive.
func TestProbe_AVersionLineWithoutAPlatformLeavesTheHostUnnamed(t *testing.T) {
	fake := tinygotest.Install(t, map[string]tinygotest.Target{"pico": tinygotest.Pico()})
	bin := script(t, `if [ "$1" = version ]; then echo "tinygo version 0.42.0 (using go version go1.27.2 and LLVM version 22.1.4)"; exit 0; fi
exec "`+fake.Bin+`" "$@"`)
	f, err := tinygo.Probe(context.Background(), bin, "pico", toolchain(t))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if f.Version() != "0.42.0" || f.GoVersion() != "go1.27.2" || f.HostGOOS() != "" || f.HostGOARCH() != "" {
		t.Errorf("version %s %s host %q/%q", f.Version(), f.GoVersion(), f.HostGOOS(), f.HostGOARCH())
	}
}

// Every tinygo child runs with GOTOOLCHAIN naming the toolchain and its bin
// first on PATH, in a directory of its own, so neither the caller's shell nor
// its working directory picks the Go TinyGo merges from.
func TestProbe_RunsEveryChildUnderTheToolchain(t *testing.T) {
	fake := tinygotest.Install(t, map[string]tinygotest.Target{"pico": tinygotest.Pico()})
	tc := toolchain(t)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if wd, err = filepath.EvalSymlinks(wd); err != nil {
		t.Fatal(err)
	}

	if _, err := tinygo.Probe(context.Background(), fake.Bin, "pico", tc); err != nil {
		t.Fatalf("Probe: %v", err)
	}

	envs := fake.Envs(t)
	if len(envs) != 4 {
		t.Fatalf("the probe ran %d tinygo children, want 4: %v", len(envs), envs)
	}
	for _, e := range envs {
		f := strings.Fields(e)
		if len(f) != 3 || f[0] != tc.Name || f[1] != filepath.Join(tc.Root, "bin") || f[2] == wd {
			t.Errorf("a tinygo child saw %q, want GOTOOLCHAIN=%s, %s first on PATH and a directory other than %s",
				e, tc.Name, filepath.Join(tc.Root, "bin"), wd)
		}
	}
}

// One target merged from two toolchains is two frames, each memoised: TinyGo
// merges a different GOROOT from each.
func TestProbe_TwoToolchainsGiveTwoMemoisedFrames(t *testing.T) {
	fake := tinygotest.Install(t, map[string]tinygotest.Target{"pico": tinygotest.Pico()})
	// list names the runtime under the root its PATH leads with, as tinygo's own
	// merge follows the go it finds.
	bin := script(t, `if [ "$1" = list ]; then r=$(dirname "${PATH%%:*}"); echo "{\"Dir\":\"$r/src/runtime\"}"; exit 0; fi
exec "`+fake.Bin+`" "$@"`)
	a, b := toolchain(t), goenv.OnDiskToolchain{Name: "go1.27.8", Root: t.TempDir()}
	for _, tc := range []goenv.OnDiskToolchain{a, b} {
		if err := os.MkdirAll(filepath.Join(tc.Root, "src", "runtime"), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()

	fa, err := tinygo.Probe(ctx, bin, "pico", a)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	fb, err := tinygo.Probe(ctx, bin, "pico", b)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	again, err := tinygo.Probe(ctx, bin, "pico", a)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	if fa.GOROOT() != a.Root || fb.GOROOT() != b.Root {
		t.Errorf("GOROOTs = %s and %s, want each toolchain's own: %s and %s", fa.GOROOT(), fb.GOROOT(), a.Root, b.Root)
	}
	if again.GOROOT() != a.Root {
		t.Errorf("the first toolchain's frame came back as %s", again.GOROOT())
	}
	if n := len(fake.Calls(t)); n != 6 {
		t.Errorf("two toolchains ran %d commands through the fake, want 6: each frame's own, the second probe of the first memoised", n)
	}
}

func TestProbe_RefusesAnUnnamedToolchain(t *testing.T) {
	fake := tinygotest.Install(t, map[string]tinygotest.Target{"pico": tinygotest.Pico()})

	_, err := tinygo.Probe(context.Background(), fake.Bin, "pico", goenv.OnDiskToolchain{})

	if err == nil || !strings.Contains(err.Error(), "resolved for a Go toolchain") {
		t.Fatalf("Probe = %v", err)
	}
	if n := len(fake.Calls(t)); n != 0 {
		t.Errorf("an unnamed toolchain ran %d tinygo commands", n)
	}
}

func TestProbe_ReportsADirectoryItCannotCreate(t *testing.T) {
	fake := tinygotest.Install(t, map[string]tinygotest.Target{"pico": tinygotest.Pico()})
	tc := toolchain(t)
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))

	_, err := tinygo.Probe(context.Background(), fake.Bin, "pico", tc)

	if err == nil || !strings.Contains(err.Error(), "a directory to ask tinygo in") {
		t.Fatalf("Probe = %v", err)
	}
}
