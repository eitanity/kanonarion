package staticcha

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// frameProbeTree writes a one-package module and a go stand-in that records the
// environment and the arguments it was run with, then fails, so the load fails
// after the child has been handed both.
func frameProbeTree(t *testing.T) (dir, fakeGo, envOut, argsOut string) {
	t.Helper()
	dir = t.TempDir()
	for name, body := range map[string]string{"go.mod": "module example.com/probe\n\ngo 1.21\n", "a.go": "package probe\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	out := t.TempDir()
	envOut, argsOut = filepath.Join(out, "child.env"), filepath.Join(out, "child.args")
	t.Setenv("KANONARION_CHILD_ENV_OUT", envOut)
	t.Setenv("KANONARION_CHILD_ARGS_OUT", argsOut)
	fakeGo = filepath.Join(t.TempDir(), "fake-go")
	// The release-tag query go/packages asks first is answered, so the load
	// itself runs and its arguments are recorded.
	script := "#!/bin/sh\nenv > \"$KANONARION_CHILD_ENV_OUT\"\necho \"$@\" >> \"$KANONARION_CHILD_ARGS_OUT\"\n" +
		"case \"$*\" in *ReleaseTags*) echo '[go1.1 go1.21]'; exit 0;; esac\nexit 1\n"
	if err := os.WriteFile(fakeGo, []byte(script), 0o700); err != nil { // #nosec G306 -- a binary this test execs must be executable
		t.Fatalf("writing fake go: %v", err)
	}
	return dir, fakeGo, envOut, argsOut
}

// childValues reads the last value of each key the child was given.
func childValues(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- written by this test into its own t.TempDir()
	if err != nil {
		t.Fatalf("the loader never ran a child: %v", err)
	}
	child := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			child[k] = v
		}
	}
	return child
}

func testTinyGo(t *testing.T) goenv.TinyGo {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "src"), 0o700); err != nil {
		t.Fatalf("making the TinyGo GOROOT: %v", err)
	}
	f, err := goenv.NewTinyGo("pico", "0.42.0", "go1.27.2", "linux", "arm", "6", root, root, "thumbv6m-unknown-unknown-eabi", []string{"cortexm", "baremetal"})
	if err != nil {
		t.Fatalf("NewTinyGo: %v", err)
	}
	return f
}

// A declared TinyGo frame reaches the child last: its platform, GOARM, GOROOT
// and cgo in the environment and its tags as -tags, and the record a failed load
// writes names that frame.
func TestAnalyseDir_DeclaredFrameReachesTheChild(t *testing.T) {
	dir, fakeGo, envOut, argsOut := frameProbeTree(t)
	tg := testTinyGo(t)
	pair, err := goenv.NewTarget("linux", "arm")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	coord, err := coordinate.NewModuleCoordinate("example.com/probe", coordinate.LocalVersion)
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	a := New("0.0.0-test", fakeGo, slog.New(slog.NewTextHandler(io.Discard, nil))).WithTarget(pair).WithTinyGo(tg)
	rec, err := a.AnalyseDir(context.Background(), dir, coord)
	if err != nil {
		t.Fatalf("AnalyseDir: %v", err)
	}
	child := childValues(t, envOut)
	for k, want := range map[string]string{
		"GOOS": "linux", "GOARCH": "arm", "GOARM": "6", "GOROOT": tg.GOROOT(), "CGO_ENABLED": "1",
	} {
		if child[k] != want {
			t.Errorf("the child was given %s=%q, want %q", k, child[k], want)
		}
	}
	args, err := os.ReadFile(argsOut) // #nosec G304 -- written by this test into its own t.TempDir()
	if err != nil {
		t.Fatalf("reading the child's arguments: %v", err)
	}
	if !strings.Contains(string(args), "-tags=cortexm,baremetal") {
		t.Errorf("the child was not handed the TinyGo tags as -tags: %s", args)
	}
	if strings.Contains(child["GOFLAGS"], "-tags") {
		t.Errorf("the tags travelled through GOFLAGS=%q", child["GOFLAGS"])
	}

	if rec.OverallStatus != domain.CallGraphStatusLoadFailed {
		t.Fatalf("status = %s, want LoadFailed from a go that exits 1", rec.OverallStatus)
	}
	want := domain.BuildFrame{GOOS: "linux", GOARCH: "arm", GOARM: "6", TinyGoTarget: "pico", TinyGoVersion: "0.42.0",
		TinyGoTags: []string{"cortexm", "baremetal"}}
	if !reflect.DeepEqual(rec.Frame, want) {
		t.Errorf("the failure record names frame %+v, want %+v", rec.Frame, want)
	}
}

// With nothing declared the child is handed the host pair, last, as a walk is:
// a GOOS/GOARCH exported in the calling shell reaches no analysis, and the
// record names the host. GOARM and cgo are left as they were.
func TestAnalyseDir_NoFramePinsTheHostPair(t *testing.T) {
	a := New("0.0.0-test", "go", slog.New(slog.NewTextHandler(io.Discard, nil)))
	base := []string{"PATH=/bin", "GOFLAGS=-mod=readonly", "GOOS=plan9"}
	want := append(slices.Clone(base), "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH)
	if got := a.applyFrame(base); !slices.Equal(got, want) {
		t.Errorf("an undeclared frame wrote %q, want the host pair appended: %q", got, want)
	}
	if flags := a.buildFlags(); flags != nil {
		t.Errorf("an undeclared frame passes build flags %q", flags)
	}

	dir, fakeGo, envOut, _ := frameProbeTree(t)
	coord, err := coordinate.NewModuleCoordinate("example.com/probe", coordinate.LocalVersion)
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	t.Setenv("GOOS", "windows")
	t.Setenv("GOARCH", "arm64")
	t.Setenv("GOARM", "")
	t.Setenv("CGO_ENABLED", "")
	rec, err := New("0.0.0-test", fakeGo, slog.New(slog.NewTextHandler(io.Discard, nil))).AnalyseDir(context.Background(), dir, coord)
	if err != nil {
		t.Fatalf("AnalyseDir: %v", err)
	}
	child := childValues(t, envOut)
	if child["GOOS"] != runtime.GOOS || child["GOARCH"] != runtime.GOARCH {
		t.Errorf("the child was given %s/%s under an exported windows/arm64, want this host's %s/%s",
			child["GOOS"], child["GOARCH"], runtime.GOOS, runtime.GOARCH)
	}
	for _, k := range []string{"GOARM", "CGO_ENABLED"} {
		if v := child[k]; v != "" {
			t.Errorf("an undeclared analysis handed the child %s=%q", k, v)
		}
	}
	if rec.Frame.GOOS != runtime.GOOS || rec.Frame.GOARCH != runtime.GOARCH || rec.Frame.TinyGoTarget != "" {
		t.Errorf("an undeclared failure record names frame %+v, want this host's", rec.Frame)
	}
}

// The recorded platform is what the loader's own go command answered, and the
// TinyGo half is the declaration's; a probe that could not answer leaves the
// declared frame rather than none.
func TestMeasuredFrame_IsTheLoadersAnswer(t *testing.T) {
	t.Parallel()
	a := New("0.0.0-test", "go", slog.New(slog.NewTextHandler(io.Discard, nil))).WithTinyGo(testTinyGo(t))
	got := a.measuredFrame(SourceDirs{GOOS: "linux", GOARCH: "arm", GOARM: "7"})
	if got.GOARM != "7" || got.TinyGoTarget != "pico" {
		t.Errorf("measured frame = %+v, want GOARM from the probe and the TinyGo target declared", got)
	}
	if got := a.measuredFrame(SourceDirs{}); !reflect.DeepEqual(got, a.declaredFrame()) {
		t.Errorf("an unanswered probe left %+v, want the declared frame", got)
	}
	host := New("0.0.0-test", "go", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got := host.frameOr(domain.BuildFrame{}); !domain.SameFrame(got, host.declaredFrame()) || got.IsZero() {
		t.Errorf("frameOr on an unframed record = %+v", got)
	}
	if arm := defaultGOARM("amd64"); arm != "" {
		t.Errorf("defaultGOARM(amd64) = %q", arm)
	}
}

// An analyser with a declared frame says so in the identity a run compares a
// held record against, and in the metadata an exclusion record is stamped from.
func TestTreeIdentityAndMetadata_NameTheFrame(t *testing.T) {
	t.Parallel()
	pair, err := goenv.NewTarget("wasip1", "wasm")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	a := New("0.0.0-test", "go", slog.New(slog.NewTextHandler(io.Discard, nil))).WithTarget(pair)
	id, err := a.TreeIdentity(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("TreeIdentity: %v", err)
	}
	want := domain.BuildFrame{GOOS: "wasip1", GOARCH: "wasm"}
	if !reflect.DeepEqual(id.Frame, want) {
		t.Errorf("identity frame = %+v, want %+v", id.Frame, want)
	}
	if got := a.AnalyserMetadata().Frame; !reflect.DeepEqual(got, want) {
		t.Errorf("metadata frame = %+v, want %+v", got, want)
	}
}
