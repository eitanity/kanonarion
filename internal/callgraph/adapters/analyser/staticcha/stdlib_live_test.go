package staticcha_test

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	cganalyser "github.com/eitanity/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// liveToolchain names the toolchain this test can read a standard library from,
// skipping where the host offers none with source.
func liveToolchain(t *testing.T) cgports.ToolchainSource {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "go", "env", "GOROOT", "GOVERSION").Output() // #nosec G204 -- fixed command
	if err != nil {
		t.Skipf("no usable go command on PATH: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) != 2 {
		t.Skipf("go env did not name GOROOT and GOVERSION: %q", string(out))
	}
	root := strings.TrimSpace(lines[0])
	if _, serr := os.Stat(filepath.Join(root, "src", "go.mod")); serr != nil {
		t.Skipf("the toolchain at %s ships no standard-library source: %v", root, serr)
	}
	return cgports.ToolchainSource{
		GoRoot:   root,
		GoBinary: filepath.Join(root, "bin", "go"),
		Version:  strings.TrimSpace(lines[1]),
	}
}

// TestAnalyseStdlib_LiveToolchain is the measurement this whole path exists for:
// the standard library of the toolchain on PATH, analysed from its own source
// tree, with the symbols a consumer's graph leaves dangling present as owned
// nodes under the stdlib coordinate.
//
// It is skipped in short mode, like every other test here that drives the real
// toolchain.
func TestAnalyseStdlib_LiveToolchain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the live standard-library analysis in short mode")
	}
	src := liveToolchain(t)
	coord, err := coordinate.NewStdlibCoordinateAt("v" + strings.TrimPrefix(src.Version, "go"))
	if err != nil {
		t.Skipf("the toolchain version %q is not a coordinate version: %v", src.Version, err)
	}

	a := cganalyser.New("0.0.0-test", "", slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	rec, err := a.AnalyseStdlib(context.Background(), src, coord)
	if err != nil {
		t.Fatalf("AnalyseStdlib: %v", err)
	}

	if rec.OverallStatus != domain.CallGraphStatusExtracted {
		t.Fatalf("overall status = %s (%s), want Extracted", rec.OverallStatus, rec.FailureDetail)
	}
	if rec.Completeness != domain.CompletenessBuiltWithBodies {
		t.Errorf("completeness = %s, want %s — a negative can only be confirmed over a graph with bodies",
			rec.Completeness, domain.CompletenessBuiltWithBodies)
	}
	if rec.AnalysisSource != domain.AnalysisSourceToolchainSource {
		t.Errorf("analysis source = %q, want %q", rec.AnalysisSource, domain.AnalysisSourceToolchainSource)
	}
	if rec.AnalysisRoot != filepath.Join(src.GoRoot, "src") {
		t.Errorf("analysis root = %q, want the toolchain's own src", rec.AnalysisRoot)
	}
	if rec.WorktreeDigest == "" {
		t.Error("the record names no source-tree digest, so nothing says which standard library it read")
	}

	// Membership: a std package belongs to the coordinate, and the vendored
	// trees the toolchain links in belong to it too — they carry advisories of
	// their own and "./..." would have missed them.
	owned := map[string]bool{}
	for _, n := range rec.Nodes {
		if n.IsExternal {
			// The only nodes outside the coordinate are the shared functions SSA
			// synthesises for an interface method, which belong to no package at all
			// — see funcPackage. A node that names a package and is still external
			// would mean the membership rule missed part of the standard library.
			if n.Package != "" {
				t.Errorf("node %s in package %s is external to the standard library's own graph", n.ID, n.Package)
			}
			continue
		}
		if n.Module != coord.Path() {
			t.Fatalf("owned node %s is attributed to module %q, want %q", n.ID, n.Module, coord.Path())
		}
		owned[n.Package] = true
	}
	for _, pkg := range []string{"net/http", "crypto/tls", "vendor/golang.org/x/net/idna"} {
		if !owned[pkg] {
			t.Errorf("the graph holds no node of %s", pkg)
		}
	}

	// The join depends on the node ID of a standard-library symbol being the same
	// here as it is where a consumer's graph records it as an external leaf.
	want := "net/http.(*Client).Do"
	found := false
	for _, n := range rec.Nodes {
		if n.ID == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("the graph holds no node with id %q, so a consumer's external leaf would never join to it", want)
	}

	t.Logf("stdlib %s: %d nodes, %d edges, %d packages", src.Version, len(rec.Nodes), len(rec.Edges), len(owned))
}
