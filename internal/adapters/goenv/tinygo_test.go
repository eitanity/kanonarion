package goenv_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
)

// tinyGoRoot is a GOROOT with the src directory NewTinyGo requires.
func tinyGoRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src", "runtime"), 0o750); err != nil {
		t.Fatalf("creating the fake GOROOT: %v", err)
	}
	return root
}

func TestTinyGoApply_MatchesTheDeclaredTinyGoTargetPosture(t *testing.T) {
	base := []string{"PATH=/usr/bin"}

	checkPosture(t, "declared-tinygo-target", base, goenv.PostureTinyGo.Apply(base))
}

// The frame is layered after Target.Apply at every call site, so the composed
// environment must state the posture too.
func TestTinyGoApply_AfterTargetApplyStillMatchesThePosture(t *testing.T) {
	base := []string{"PATH=/usr/bin"}
	pair, err := goenv.NewTarget(goenv.PostureTinyGo.GOOS(), goenv.PostureTinyGo.GOARCH())
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}

	checkPosture(t, "declared-tinygo-target", base, goenv.PostureTinyGo.Apply(pair.Apply(base)))
}

// The control: a frame stated on this host's platform could not catch a
// producer that dropped it.
func TestPostureTinyGo_IsNotThisHost(t *testing.T) {
	pair, err := goenv.NewTarget(goenv.PostureTinyGo.GOOS(), goenv.PostureTinyGo.GOARCH())
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	if pair.IsHost() {
		t.Errorf("the TinyGo posture is stated against %s, which is this host", pair)
	}
	if goenv.PostureTinyGo.GOARM() == "" {
		t.Error("the TinyGo posture states no GOARM, so the assertion cannot catch a producer that drops it")
	}
}

func TestTinyGoApply_WinsOverAnInheritedExportAndKeepsTheCallersSlice(t *testing.T) {
	root := tinyGoRoot(t)
	f, err := goenv.NewTinyGo("pico", "0.42.0", "go1.27.2", "linux", "arm", "6", root, []string{"tinygo", "pico"})
	if err != nil {
		t.Fatalf("NewTinyGo: %v", err)
	}
	base := make([]string, 0, 8)
	base = append(base, "GOOS=windows", "GOROOT=/elsewhere", "CGO_ENABLED=0")

	got := f.Apply(base)

	for k, want := range map[string]string{"GOOS": "linux", "GOARCH": "arm", "GOARM": "6", "GOROOT": root, "CGO_ENABLED": "1"} {
		if v := lastEnvValue(got, k); v != want {
			t.Errorf("the child sees %s=%q, want %q", k, v, want)
		}
	}
	if len(base) != 3 || base[0] != "GOOS=windows" {
		t.Errorf("Apply rewrote the caller's environment: %v", base)
	}
}

func TestTinyGoApply_NoGOARMWritesNone(t *testing.T) {
	f, err := goenv.NewTinyGo("wasip1", "0.42.0", "go1.27.2", "wasip1", "wasm", "", tinyGoRoot(t), nil)
	if err != nil {
		t.Fatalf("NewTinyGo: %v", err)
	}
	for _, kv := range f.Apply(nil) {
		if strings.HasPrefix(kv, "GOARM=") {
			t.Errorf("an empty GOARM was written as %q", kv)
		}
	}
	if args := f.ListArgs(); args != nil {
		t.Errorf("a frame with no tags passes %v", args)
	}
}

func TestTinyGoApply_UndeclaredLeavesTheEnvironment(t *testing.T) {
	var f goenv.TinyGo
	base := []string{"PATH=/usr/bin", "GOOS=windows"}
	if got := f.Apply(base); !reflect.DeepEqual(got, base) {
		t.Errorf("an undeclared frame changed the environment: %v", got)
	}
	if f.Declared() {
		t.Error("the zero value reports itself as a declaration")
	}
}

func TestTinyGo_AccessorsAndListArgs(t *testing.T) {
	root := tinyGoRoot(t)
	tags := []string{"tinygo", "baremetal", "pico"}
	f, err := goenv.NewTinyGo("pico", "0.42.0", "go1.27.2", "linux", "arm", "6", root, tags)
	if err != nil {
		t.Fatalf("NewTinyGo: %v", err)
	}
	tags[0] = "mutated"

	if got := []string{f.Target(), f.Version(), f.GoVersion(), f.GOOS(), f.GOARCH(), f.GOARM(), f.GOROOT()}; !reflect.DeepEqual(got,
		[]string{"pico", "0.42.0", "go1.27.2", "linux", "arm", "6", root}) {
		t.Errorf("accessors = %v", got)
	}
	if !f.Declared() {
		t.Error("a complete frame reports itself undeclared")
	}
	if got := f.Tags(); !reflect.DeepEqual(got, []string{"tinygo", "baremetal", "pico"}) {
		t.Errorf("Tags() = %v; the caller's slice must not reach the frame", got)
	}
	f.Tags()[0] = "mutated"
	if got := f.ListArgs(); !reflect.DeepEqual(got, []string{"-tags=tinygo,baremetal,pico"}) {
		t.Errorf("ListArgs() = %v", got)
	}
}

func TestNewTinyGo_RefusesAPartialFrameByName(t *testing.T) {
	root := tinyGoRoot(t)
	noSrc := t.TempDir()
	for _, tc := range []struct {
		name                                              string
		target, version, goos, goarch, goroot, wantInText string
	}{
		{"target", "", "0.42.0", "linux", "arm", root, "target"},
		{"version", "pico", "", "linux", "arm", root, "TinyGo version"},
		{"goos", "pico", "0.42.0", "", "arm", root, "GOOS"},
		{"goarch", "pico", "0.42.0", "linux", "", root, "GOARCH"},
		{"goroot", "pico", "0.42.0", "linux", "arm", "", "GOROOT"},
		{"goroot without src", "pico", "0.42.0", "linux", "arm", noSrc, "no src directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := goenv.NewTinyGo(tc.target, tc.version, "go1.27.2", tc.goos, tc.goarch, "6", tc.goroot, nil)
			if err == nil {
				t.Fatal("a partial frame was accepted")
			}
			if !strings.Contains(err.Error(), tc.wantInText) {
				t.Errorf("refusal %q does not name %q", err, tc.wantInText)
			}
		})
	}
}

// A refusal raised under the frame names it; an undeclared frame adds nothing.
func TestTinyGo_ResolutionClause(t *testing.T) {
	f, err := goenv.NewTinyGo("pico", "0.42.0", "go1.27.2", "linux", "arm", "6", tinyGoRoot(t), nil)
	if err != nil {
		t.Fatalf("NewTinyGo: %v", err)
	}
	if got := f.ResolutionClause(); !strings.Contains(got, "--tinygo pico") {
		t.Errorf("ResolutionClause() = %q, want it to name --tinygo pico", got)
	}
	if got := (goenv.TinyGo{}).ResolutionClause(); got != "" {
		t.Errorf("an undeclared frame's clause = %q, want empty", got)
	}
}

// A wasm artefact is told by GOARCH or by TinyGo's own tag: tinygo reports
// wasip2 and wasm-unknown as linux/arm.
func TestTinyGoBuildsWasm(t *testing.T) {
	for _, tc := range []struct {
		target, goos, goarch string
		tags                 []string
		want                 bool
	}{
		{"wasip1", "wasip1", "wasm", []string{"tinygo.wasm"}, true},
		{"wasip2", "linux", "arm", []string{"tinygo.wasm", "wasip2"}, true},
		{"wasm-unknown", "linux", "arm", []string{"tinygo.wasm", "wasm_unknown"}, true},
		{"pico", "linux", "arm", []string{"tinygo", "pico"}, false},
	} {
		f, err := goenv.NewTinyGo(tc.target, "0.42.0", "go1.27.2", tc.goos, tc.goarch, "", tinyGoRoot(t), tc.tags)
		if err != nil {
			t.Fatal(err)
		}
		if got := f.BuildsWasm(); got != tc.want {
			t.Errorf("%s: BuildsWasm = %v, want %v", tc.target, got, tc.want)
		}
	}
}
