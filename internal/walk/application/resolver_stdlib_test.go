package application_test

import (
	"context"
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	domain3 "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// stdlibNode returns the injected standard-library node from g, or fails.
func stdlibNode(t *testing.T, g domain3.Graph) domain3.GraphNode {
	t.Helper()
	for _, n := range g.Nodes {
		if n.ResolutionSource == domain3.ResolutionStdlib {
			return n
		}
	}
	t.Fatalf("no stdlib node in graph")
	return domain3.GraphNode{}
}

// buildListWithEnv is sampleBuildList extended with a captured build environment,
// mirroring what the gotoolchain resolver reports from `go env`.
func buildListWithEnv() walkports.BuildList {
	bl := sampleBuildList()
	bl.GoVersion = "go1.26.4"
	bl.GOOS = "linux"
	bl.GOARCH = "amd64"
	return bl
}

// TestResolveProject_Stdlib_FromToolchain verifies the stdlib node is pinned to
// the effective build toolchain (go env GOVERSION) by default, and that a
// root→stdlib edge is recorded.
func TestResolveProject_Stdlib_FromToolchain(t *testing.T) {
	r, _ := buildListResolver(t, &fakeBuildListResolver{list: buildListWithEnv()})
	target := coord("example.com/project", domain2.LocalVersion)

	// go.mod declares an OLDER directive than the toolchain; the default must
	// track the toolchain (v1.26.4), not the directive (v1.21).
	goMod := []byte("module example.com/project\n\ngo 1.21\n")
	g, err := r.ResolveProject(context.Background(), target, goMod, "/proj", domain3.DefaultDepthPolicy().FetchStage(), nil, false)
	if err != nil {
		t.Fatalf("ResolveProject: %v", err)
	}

	node := stdlibNode(t, g)
	if node.Coordinate.Version != "v1.26.4" {
		t.Errorf("stdlib version = %q, want v1.26.4 (effective toolchain)", node.Coordinate.Version)
	}

	// The root→stdlib edge must exist so downstream consumers see the dependency.
	found := false
	for _, e := range g.Edges {
		if e.From == target && e.To == node.Coordinate {
			found = true
		}
	}
	if !found {
		t.Errorf("missing root→stdlib edge")
	}
}

// TestResolveProject_Stdlib_FromGoModOverride verifies the opt-in override pins
// the stdlib node to the go.mod directive instead of the toolchain.
func TestResolveProject_Stdlib_FromGoModOverride(t *testing.T) {
	r, _ := buildListResolver(t, &fakeBuildListResolver{list: buildListWithEnv()})
	target := coord("example.com/project", domain2.LocalVersion)

	goMod := []byte("module example.com/project\n\ngo 1.21\n\ntoolchain go1.24.2\n")
	g, err := r.ResolveProject(context.Background(), target, goMod, "/proj", domain3.DefaultDepthPolicy().FetchStage(), nil, true)
	if err != nil {
		t.Fatalf("ResolveProject: %v", err)
	}

	node := stdlibNode(t, g)
	if node.Coordinate.Version != "v1.24.2" {
		t.Errorf("stdlib version = %q, want v1.24.2 (go.mod toolchain directive)", node.Coordinate.Version)
	}
}

// TestResolveProject_BuildEnvCaptured verifies the resolved graph records the
// build environment reported by the toolchain, so a downstream SBOM can state
// the platform the component set is valid for.
func TestResolveProject_BuildEnvCaptured(t *testing.T) {
	r, _ := buildListResolver(t, &fakeBuildListResolver{list: buildListWithEnv()})
	target := coord("example.com/project", domain2.LocalVersion)

	g, err := r.ResolveProject(context.Background(), target, nil, "/proj", domain3.DefaultDepthPolicy().FetchStage(), nil, false)
	if err != nil {
		t.Fatalf("ResolveProject: %v", err)
	}
	want := domain3.BuildEnv{GOOS: "linux", GOARCH: "amd64", GoVersion: "go1.26.4"}
	if g.BuildEnv != want {
		t.Errorf("BuildEnv = %+v, want %+v", g.BuildEnv, want)
	}
}

// TestResolveProject_Stdlib_NoVersion verifies that when neither the toolchain
// nor the go.mod declares a version, no stdlib node is injected (a best-effort
// gap, never a fatal error).
func TestResolveProject_Stdlib_NoVersion(t *testing.T) {
	r, _ := buildListResolver(t, &fakeBuildListResolver{list: sampleBuildList()})
	target := coord("example.com/project", domain2.LocalVersion)

	// go.mod with no go/toolchain directive, and a build list with no GoVersion.
	goMod := []byte("module example.com/project\n")
	g, err := r.ResolveProject(context.Background(), target, goMod, "/proj", domain3.DefaultDepthPolicy().FetchStage(), nil, false)
	if err != nil {
		t.Fatalf("ResolveProject: %v", err)
	}
	for _, n := range g.Nodes {
		if n.ResolutionSource == domain3.ResolutionStdlib {
			t.Errorf("stdlib node injected despite no determinable toolchain version")
		}
	}
}
