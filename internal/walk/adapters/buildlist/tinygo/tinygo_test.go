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

	"github.com/eitanity/kanonarion/internal/walk/adapters/buildlist/tinygo"
	"github.com/eitanity/kanonarion/internal/walk/adapters/buildlist/tinygotest"
)

func TestProbe_ReadsTheFourOutputs(t *testing.T) {
	fake := tinygotest.Install(t, map[string]tinygotest.Target{"pico": tinygotest.Pico()})

	f, err := tinygo.Probe(context.Background(), fake.Bin, "pico")
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

	for range 3 {
		if _, err := tinygo.Probe(ctx, fake.Bin, "pico"); err != nil {
			t.Fatalf("Probe: %v", err)
		}
	}
	if n := len(fake.Calls(t)); n != 4 {
		t.Errorf("three probes of one target ran %d tinygo commands, want the 4 of the first", n)
	}
	if _, err := tinygo.Probe(ctx, fake.Bin, "other"); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if n := len(fake.Calls(t)); n != 8 {
		t.Errorf("a second target ran %d commands in all, want 8", n)
	}
}

func TestProbe_NoTinyGoOnPath(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	_, err := tinygo.Probe(context.Background(), "", "pico")

	if err == nil || err.Error() != "declaring --tinygo needs the tinygo command on PATH" {
		t.Fatalf("Probe = %v", err)
	}
	if !errors.Is(err, tinygo.ErrNotOnPath) {
		t.Error("the refusal is not ErrNotOnPath")
	}
}

func TestProbe_UnknownTarget(t *testing.T) {
	fake := tinygotest.Install(t, nil)

	_, err := tinygo.Probe(context.Background(), fake.Bin, "nosuchboard")

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
			_, err := tinygo.Probe(context.Background(), script(t, tc.body), "pico")
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

	_, err := tinygo.Probe(context.Background(), bin, "pico")

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

	_, err := tinygo.Probe(ctx, bin, "pico")

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
	f, err := tinygo.Probe(context.Background(), bin, "pico")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if f.Version() != "0.42.0" || f.GoVersion() != "go1.27.2" || f.HostGOOS() != "" || f.HostGOARCH() != "" {
		t.Errorf("version %s %s host %q/%q", f.Version(), f.GoVersion(), f.HostGOOS(), f.HostGOARCH())
	}
}
