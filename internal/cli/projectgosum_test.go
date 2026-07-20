package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"

	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

func TestResolveProjectGoSum_PresentGoSumSetsPath(t *testing.T) {
	resetModcacheGlobals(t)
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module x\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	goSum := filepath.Join(dir, "go.sum")
	if err := os.WriteFile(goSum, []byte(""), 0o600); err != nil {
		t.Fatalf("write go.sum: %v", err)
	}

	resolveProjectGoSum(gomod)
	if projectGoSumPath != goSum {
		t.Errorf("projectGoSumPath = %q, want %q", projectGoSumPath, goSum)
	}
}

func TestResolveProjectGoSum_MissingGoSumLeavesPathEmpty(t *testing.T) {
	resetModcacheGlobals(t)
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module x\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	// No go.sum: the normal path treats go.sum as an optional complement.
	resolveProjectGoSum(gomod)
	if projectGoSumPath != "" {
		t.Errorf("projectGoSumPath = %q, want empty when go.sum is absent", projectGoSumPath)
	}
}

func TestResolveProjectGoSum_NoopInModcacheMode(t *testing.T) {
	resetModcacheGlobals(t)
	modcacheMode = true
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	_ = os.WriteFile(gomod, []byte("module x\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "go.sum"), []byte(""), 0o600)

	resolveProjectGoSum(gomod)
	if projectGoSumPath != "" {
		t.Errorf("projectGoSumPath = %q, want empty in --from-modcache mode", projectGoSumPath)
	}
}

func TestGoSumWalkGate_FailsOnGoSumMismatchNode(t *testing.T) {
	resetModcacheGlobals(t)
	local := coordinate.ModuleCoordinate{Path: "example.com/proj", Version: coordinate.LocalVersion}
	rec := walkdomain.WalkRecord{Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{
		{Coordinate: local, ResolutionSource: walkdomain.ResolutionLocalMainModule},
		makeNode("github.com/good/dep", "v1.0.0", walkdomain.ResolutionMVS, ""),
		makeNode("github.com/bad/dep", "v2.0.0", walkdomain.ResolutionFetchFailed,
			"fetching module: "+fetchapp.ErrGoSumVerification.Error()+": tampered"),
	}}}

	err := goSumWalkGate(rec, local)
	if err == nil {
		t.Fatalf("want error for a go.sum-mismatch node, got nil")
	}
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != ExitIntegrity {
		t.Fatalf("err = %v, want exitError with ExitIntegrity", err)
	}
}

func TestGoSumWalkGate_ToleratesOrdinaryFetchFailure(t *testing.T) {
	resetModcacheGlobals(t)
	local := coordinate.ModuleCoordinate{Path: "example.com/proj", Version: coordinate.LocalVersion}
	rec := walkdomain.WalkRecord{Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{
		// An ordinary network fetch failure (not a go.sum tamper) stays tolerated
		// as a partial walk — the gate must not fire on it.
		makeNode("github.com/net/dep", "v1.0.0", walkdomain.ResolutionFetchFailed, "proxy download: connection refused"),
	}}}
	if err := goSumWalkGate(rec, local); err != nil {
		t.Fatalf("ordinary fetch failure: want nil, got %v", err)
	}
}

func TestGoSumWalkGate_NoopInModcacheMode(t *testing.T) {
	resetModcacheGlobals(t)
	modcacheMode = true
	local := coordinate.ModuleCoordinate{Path: "example.com/proj", Version: coordinate.LocalVersion}
	rec := walkdomain.WalkRecord{Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{
		makeNode("github.com/bad/dep", "v2.0.0", walkdomain.ResolutionFetchFailed,
			fetchapp.ErrGoSumVerification.Error()),
	}}}
	// In --from-modcache mode modcacheWalkGate owns the failure; goSumWalkGate
	// defers so the same node is not reported twice.
	if err := goSumWalkGate(rec, local); err != nil {
		t.Fatalf("modcache mode: want nil, got %v", err)
	}
}

func TestGoSumWalkGate_CleanWalkPasses(t *testing.T) {
	resetModcacheGlobals(t)
	local := coordinate.ModuleCoordinate{Path: "example.com/proj", Version: coordinate.LocalVersion}
	rec := walkdomain.WalkRecord{Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{
		makeNode("github.com/good/dep", "v1.0.0", walkdomain.ResolutionMVS, ""),
	}}}
	if err := goSumWalkGate(rec, local); err != nil {
		t.Fatalf("clean walk: want nil, got %v", err)
	}
}
