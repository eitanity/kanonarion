package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
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
		Coordinate:       fetchdomain.ModuleCoordinate{Path: path, Version: version},
		ResolutionSource: src,
		ErrorDetail:      detail,
	}
}

func TestModcacheWalkGate_FailsOnFetchFailedNode(t *testing.T) {
	resetModcacheGlobals(t)
	modcacheMode = true
	local := fetchdomain.ModuleCoordinate{Path: "example.com/proj", Version: fetchdomain.LocalVersion}
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
	local := fetchdomain.ModuleCoordinate{Path: "example.com/proj", Version: fetchdomain.LocalVersion}
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
	local := fetchdomain.ModuleCoordinate{Path: "example.com/proj", Version: fetchdomain.LocalVersion}
	rec := walkdomain.WalkRecord{Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{
		makeNode("github.com/bad/dep", "v2.0.0", walkdomain.ResolutionFetchFailed, "boom"),
	}}}
	if err := modcacheWalkGate(rec, local); err != nil {
		t.Fatalf("mode off: want nil, got %v", err)
	}
}
