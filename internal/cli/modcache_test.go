package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// resetModcacheGlobals restores the process-wide --from-modcache state so tests
// that flip it do not leak into one another.
func resetModcacheGlobals(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		modcacheMode = false
		modcacheDir = ""
		goSumPath = ""
		projectGoSumPath = ""
	})
}

func TestResolveModcacheMode_FlagAbsentLeavesModeOff(t *testing.T) {
	resetModcacheGlobals(t)
	if err := resolveModcacheMode("", "/anywhere/go.mod"); err != nil {
		t.Fatalf("resolveModcacheMode: %v", err)
	}
	if modcacheMode {
		t.Errorf("modcacheMode = true, want false when flag absent")
	}
}

func TestResolveModcacheMode_ExplicitDirSetsGlobals(t *testing.T) {
	resetModcacheGlobals(t)
	projectDir := t.TempDir()
	gomod := filepath.Join(projectDir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module x\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "go.sum"), []byte(""), 0o600); err != nil {
		t.Fatalf("write go.sum: %v", err)
	}
	cacheDir := t.TempDir()

	if err := resolveModcacheMode(cacheDir, gomod); err != nil {
		t.Fatalf("resolveModcacheMode: %v", err)
	}
	if !modcacheMode {
		t.Errorf("modcacheMode = false, want true")
	}
	if modcacheDir != cacheDir {
		t.Errorf("modcacheDir = %q, want %q", modcacheDir, cacheDir)
	}
	if goSumPath != filepath.Join(projectDir, "go.sum") {
		t.Errorf("goSumPath = %q, want the project go.sum", goSumPath)
	}
}

// Passed bare, the flag arrives as the sentinel and the cache directory comes
// from `go env GOMODCACHE` - the third of the three forms the flag has to keep
// apart (absent, bare, explicit directory).
func TestResolveModcacheMode_BareFlagResolvesFromGoEnv(t *testing.T) {
	resetModcacheGlobals(t)
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not on PATH: %v", err)
	}
	projectDir := t.TempDir()
	gomod := filepath.Join(projectDir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module x\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "go.sum"), []byte(""), 0o600); err != nil {
		t.Fatalf("write go.sum: %v", err)
	}
	cacheDir := t.TempDir()
	t.Setenv("GOMODCACHE", cacheDir)
	t.Setenv("GOFLAGS", "")

	if err := resolveModcacheMode(modcacheFlagSentinel, gomod); err != nil {
		t.Fatalf("resolveModcacheMode(bare): %v", err)
	}
	if !modcacheMode {
		t.Errorf("modcacheMode = false, want true")
	}
	if modcacheDir != cacheDir {
		t.Errorf("modcacheDir = %q, want the GOMODCACHE dir %q", modcacheDir, cacheDir)
	}
}

// The sentinel is ordinary text, so a directory could carry that exact name. The
// bare flag and an explicit value are indistinguishable by then, so the run
// stops and says how to spell the directory unambiguously rather than silently
// choosing `go env GOMODCACHE`.
func TestResolveModcacheMode_SentinelNamedDirectoryIsRefusedNotReinterpreted(t *testing.T) {
	resetModcacheGlobals(t)
	projectDir := t.TempDir()
	gomod := filepath.Join(projectDir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module x\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "go.sum"), []byte(""), 0o600); err != nil {
		t.Fatalf("write go.sum: %v", err)
	}
	work := t.TempDir()
	if err := os.Mkdir(filepath.Join(work, modcacheFlagSentinel), 0o750); err != nil {
		t.Fatalf("mkdir sentinel-named dir: %v", err)
	}
	t.Chdir(work)

	err := resolveModcacheMode(modcacheFlagSentinel, gomod)
	if err == nil {
		t.Fatalf("want a refusal when a directory carries the sentinel's name, got nil")
	}
	if !strings.Contains(err.Error(), "absolute path") {
		t.Errorf("refusal %q does not say how to name the directory instead", err)
	}
	if modcacheMode {
		t.Errorf("modcacheMode = true after a refusal; want false")
	}

	// Named unambiguously, the same directory is accepted.
	if err := resolveModcacheMode(filepath.Join(work, modcacheFlagSentinel), gomod); err != nil {
		t.Fatalf("explicit path to the same directory: %v", err)
	}
	if modcacheDir != filepath.Join(work, modcacheFlagSentinel) {
		t.Errorf("modcacheDir = %q, want the explicitly named directory", modcacheDir)
	}
}

// The three spellings the flag has to keep apart, at the parser: absent binds
// the empty string (mode off), bare binds the sentinel (resolve from `go env
// GOMODCACHE`), and an attached value binds that directory. The value is
// attached because a NoOptDefVal detaches the space-separated form - the same
// property TestGoModFlag_AcceptsTheSpaceSeparatedFormEverywhere pins the other
// way for --gomod.
func TestFromModcacheFlag_ParsesAllThreeForms(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"absent", nil, ""},
		{"bare", []string{"--from-modcache"}, modcacheFlagSentinel},
		{"attached directory", []string{"--from-modcache=/some/cache"}, "/some/cache"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var target string
			cmd := &cobra.Command{Use: "x"}
			registerFromModcacheFlag(cmd, &target)
			if err := cmd.ParseFlags(tc.args); err != nil {
				t.Fatalf("parsing %v: %v", tc.args, err)
			}
			if target != tc.want {
				t.Errorf("--from-modcache bound %q, want %q", target, tc.want)
			}
		})
	}
}

func TestResolveModcacheMode_MissingCacheDirErrors(t *testing.T) {
	resetModcacheGlobals(t)
	projectDir := t.TempDir()
	gomod := filepath.Join(projectDir, "go.mod")
	_ = os.WriteFile(gomod, []byte("module x\n"), 0o600)
	_ = os.WriteFile(filepath.Join(projectDir, "go.sum"), []byte(""), 0o600)

	if err := resolveModcacheMode(filepath.Join(t.TempDir(), "does-not-exist"), gomod); err == nil {
		t.Fatalf("want error for a missing cache dir, got nil")
	}
	if modcacheMode {
		t.Errorf("modcacheMode = true after a failed resolve; want false")
	}
}

func TestResolveModcacheMode_MissingGoSumErrors(t *testing.T) {
	resetModcacheGlobals(t)
	projectDir := t.TempDir()
	gomod := filepath.Join(projectDir, "go.mod")
	_ = os.WriteFile(gomod, []byte("module x\n"), 0o600)
	// No go.sum written.
	if err := resolveModcacheMode(t.TempDir(), gomod); err == nil {
		t.Fatalf("want error when go.sum is absent, got nil")
	}
}

func makeNode(path, version string, src walkdomain.ResolutionSource, detail string) walkdomain.GraphNode {
	return walkdomain.GraphNode{
		Coordinate:       coordinatetest.MustNew(path, version),
		ResolutionSource: src,
		ErrorDetail:      detail,
	}
}

func TestModcacheWalkGate_FailsOnFetchFailedNode(t *testing.T) {
	resetModcacheGlobals(t)
	modcacheMode = true
	local := coordinatetest.MustNew("example.com/proj", coordinate.LocalVersion)
	rec := walkdomain.WalkRecord{Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{
		{Coordinate: local, ResolutionSource: walkdomain.ResolutionLocalMainModule},
		makeNode("github.com/good/dep", "v1.0.0", walkdomain.ResolutionMVS, ""),
		makeNode("github.com/bad/dep", "v2.0.0", walkdomain.ResolutionFetchFailed, "go.sum verification failed"),
	}}}

	err := modcacheWalkGate(rec, local)
	if err == nil {
		t.Fatalf("want error for a fetch-failed node, got nil")
	}
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != ExitIntegrity {
		t.Fatalf("err = %v, want exitError with ExitIntegrity", err)
	}
}

func TestModcacheWalkGate_CleanWalkPasses(t *testing.T) {
	resetModcacheGlobals(t)
	modcacheMode = true
	local := coordinatetest.MustNew("example.com/proj", coordinate.LocalVersion)
	rec := walkdomain.WalkRecord{Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{
		makeNode("github.com/good/dep", "v1.0.0", walkdomain.ResolutionMVS, ""),
	}}}
	if err := modcacheWalkGate(rec, local); err != nil {
		t.Fatalf("clean walk: want nil, got %v", err)
	}
}

func TestModcacheWalkGate_ModeOffIsNoop(t *testing.T) {
	resetModcacheGlobals(t)
	modcacheMode = false
	local := coordinatetest.MustNew("example.com/proj", coordinate.LocalVersion)
	rec := walkdomain.WalkRecord{Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{
		makeNode("github.com/bad/dep", "v2.0.0", walkdomain.ResolutionFetchFailed, "boom"),
	}}}
	if err := modcacheWalkGate(rec, local); err != nil {
		t.Fatalf("mode off: want nil, got %v", err)
	}
}
