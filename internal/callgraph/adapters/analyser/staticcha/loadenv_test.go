package staticcha

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// TestIsolatedModuleEnv_DisablesWorkspaceMode is the regression guard for
// modules that ship a go.work in their published zip. Left in workspace mode the
// loader tries to open sibling go.mod files that are not in the zip, and the
// module is stored as a load failure with an empty call graph — its reachability
// and capability results silently degraded for a packaging artefact rather than
// anything about the module's own code.
func TestIsolatedModuleEnv_DisablesWorkspaceMode(t *testing.T) {
	env := isolatedModuleEnv()

	if !slices.Contains(env, "GOWORK=off") {
		t.Fatal("isolatedModuleEnv must disable workspace mode for an extracted module directory")
	}
}

// TestIsolatedModuleEnv_OverridesInheritedWorkspace guards that an ambient GOWORK
// pointing at the invoking user's workspace cannot leak into an isolated module
// analysis. The Go toolchain resolves a duplicate key to its last value, so the
// override must come after anything inherited.
func TestIsolatedModuleEnv_OverridesInheritedWorkspace(t *testing.T) {
	t.Setenv("GOWORK", "/home/dev/go.work")

	env := isolatedModuleEnv()

	last := ""
	for _, kv := range env {
		if strings.HasPrefix(kv, "GOWORK=") {
			last = kv
		}
	}
	if last != "GOWORK=off" {
		t.Errorf("effective GOWORK = %q, want GOWORK=off to win over the inherited workspace", last)
	}
}

// TestIsolatedModuleEnv_PreservesAmbientEnvironment guards that disabling
// workspace mode does not discard the rest of the environment — the loader still
// needs PATH, HOME and the caller's GOMODCACHE/GOFLAGS to resolve anything.
func TestIsolatedModuleEnv_PreservesAmbientEnvironment(t *testing.T) {
	t.Setenv("KANONARION_LOADENV_PROBE", "present")

	env := isolatedModuleEnv()

	if len(env) < len(os.Environ()) {
		t.Errorf("env has %d entries, want at least the ambient %d", len(env), len(os.Environ()))
	}
	if !slices.Contains(env, "KANONARION_LOADENV_PROBE=present") {
		t.Error("ambient environment variables must survive")
	}
}

// TestAnalyseDir_ChildProcessEnvironmentIsHermetic asserts on what the SUBPROCESS
// received, not on what the builder returns in isolation — the two disagreed when
// the slice was built before setupGoEnv installed the analysis PATH.
//
// The go binary is a script that dumps its environment, so the load fails; the
// child was handed the environment before it did.
func TestAnalyseDir_ChildProcessEnvironmentIsHermetic(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/probe\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package probe\n"), 0o600); err != nil {
		t.Fatalf("writing a.go: %v", err)
	}

	// Works only because the ambient environment survives into the child.
	recorded := filepath.Join(t.TempDir(), "child.env")
	t.Setenv("KANONARION_CHILD_ENV_OUT", recorded)

	fakeGo := filepath.Join(t.TempDir(), "fake-go")
	script := "#!/bin/sh\nenv > \"$KANONARION_CHILD_ENV_OUT\"\nexit 1\n"
	if err := os.WriteFile(fakeGo, []byte(script), 0o700); err != nil { // #nosec G306 -- a binary this test execs must be executable
		t.Fatalf("writing fake go: %v", err)
	}

	coord, err := coordinate.NewModuleCoordinate("example.com/probe", coordinate.LocalVersion)
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	a := New("0.0.0-test", fakeGo, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := a.AnalyseDir(context.Background(), dir, coord); err != nil {
		t.Fatalf("AnalyseDir: %v", err)
	}

	raw, err := os.ReadFile(recorded) // #nosec G304 -- written by this test into its own t.TempDir()
	if err != nil {
		t.Fatalf("the loader never ran a child, so nothing about its environment was measured: %v", err)
	}
	child := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			child[k] = v
		}
	}

	// The offline posture, read off the child.
	for k, want := range map[string]string{
		"GOPROXY":     "off",
		"GOSUMDB":     "off",
		"GOTOOLCHAIN": "local",
		"GOWORK":      "off",
		"GOFLAGS":     "-mod=readonly",
	} {
		if child[k] != want {
			t.Errorf("the subprocess was given %s=%q, want %q", k, child[k], want)
		}
	}

	// And the toolchain the analysis installed.
	if want := filepath.Dir(fakeGo); !strings.Contains(child["PATH"], "kanonarion-bin-") && !strings.Contains(child["PATH"], want) {
		t.Errorf("the subprocess PATH does not lead with the toolchain setupGoEnv installed: %q", child["PATH"])
	}
	if goroot, ok := child["GOROOT"]; ok {
		t.Errorf("the subprocess was given GOROOT=%q; setupGoEnv clears it so the chosen go decides its own", goroot)
	}
}

// checkPosture asserts one producer's output against the posture of that name.
func checkPosture(t *testing.T, name string, base, got []string) {
	t.Helper()
	p, ok := goenv.For(name)
	if !ok {
		t.Fatalf("no posture named %q is stated", name)
	}
	for _, v := range goenv.Verify(p, base, got) {
		t.Error(v)
	}
}

// TestLoadProducersMatchTheStatedPostures holds this package's environments
// against the one table that states every analysis posture in the repository, so
// a variable that enters one producer and not the others fails here rather than
// in a user's report.
func TestLoadProducersMatchTheStatedPostures(t *testing.T) {
	base := os.Environ()

	checkPosture(t, "extracted-module", base, isolatedModuleEnv())
	checkPosture(t, "extracted-module-analysis", base, analysisEnv())
}

// TestAnalyseDir_WorkingTreeUnderAWorkspaceKeepsIt is the other direction of the
// contract loadenv.go states, measured on the child rather than on a builder: an
// extracted module's shipped go.work is packaging, and a working tree's is the
// build the record is describing.
func TestAnalyseDir_WorkingTreeUnderAWorkspaceKeepsIt(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":  "module example.com/probe\n\ngo 1.21\n",
		"a.go":    "package probe\n",
		"go.work": "go 1.21\n\nuse .\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	t.Setenv("GOWORK", "")

	recorded := filepath.Join(t.TempDir(), "child.env")
	t.Setenv("KANONARION_CHILD_ENV_OUT", recorded)
	fakeGo := filepath.Join(t.TempDir(), "fake-go")
	script := "#!/bin/sh\nenv > \"$KANONARION_CHILD_ENV_OUT\"\nexit 1\n"
	if err := os.WriteFile(fakeGo, []byte(script), 0o700); err != nil { // #nosec G306 -- a binary this test execs must be executable
		t.Fatalf("writing fake go: %v", err)
	}

	coord, err := coordinate.NewModuleCoordinate("example.com/probe", coordinate.LocalVersion)
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	a := New("0.0.0-test", fakeGo, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := a.AnalyseDir(context.Background(), dir, coord); err != nil {
		t.Fatalf("AnalyseDir: %v", err)
	}

	raw, err := os.ReadFile(recorded) // #nosec G304 -- written by this test into its own t.TempDir()
	if err != nil {
		t.Fatalf("the loader never ran a child, so nothing about its environment was measured: %v", err)
	}
	child := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			child[k] = v
		}
	}
	if child["GOWORK"] == "off" {
		t.Error("the working tree's own go.work was disabled: a local record must describe the build the developer has")
	}
	if child["GOFLAGS"] != "-mod=readonly" {
		t.Errorf("the subprocess was given GOFLAGS=%q, want -mod=readonly: workspace mode refuses -mod=mod", child["GOFLAGS"])
	}
}
