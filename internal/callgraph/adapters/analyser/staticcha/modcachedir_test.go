package staticcha_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// recordingCache is a cgports.ModuleCache that records what it was asked to
// materialise and writes nothing. The analyses below fail at the load — the go
// binary is a script — which is the point: what is under test is the
// environment the child was handed, not the graph.
type recordingCache struct {
	calls  int
	dir    string
	main   cgports.MainModule
	report cgports.ModuleCacheReport
	// plantReadOnlyEntry writes the shape the go command leaves behind: a file
	// inside a read-only directory, which os.RemoveAll cannot unlink.
	plantReadOnlyEntry bool
}

func (c *recordingCache) Materialise(_ context.Context, dir string, main cgports.MainModule) cgports.ModuleCacheReport {
	c.calls++
	c.dir = dir
	c.main = main
	if c.plantReadOnlyEntry {
		extracted := filepath.Join(dir, "example.com", "dep@v1.2.3")
		if err := os.MkdirAll(extracted, 0o700); err == nil {
			_ = os.WriteFile(filepath.Join(extracted, "a.go"), []byte("package dep\n"), 0o400)
			_ = os.Chmod(extracted, 0o500) // #nosec G302 -- the read-only mode the go command itself writes, which is the shape under test
		}
	}
	return c.report
}

// refusingCache fails the test if anything asks it to materialise a cache.
type refusingCache struct{ t *testing.T }

func (c refusingCache) Materialise(context.Context, string, cgports.MainModule) cgports.ModuleCacheReport {
	c.t.Error("a cache was materialised for a run that named an existing one")
	return cgports.ModuleCacheReport{}
}

// dependentModule ships a go.mod naming one requirement, which is what the
// materialiser is expected to be seeded with.
var dependentModuleFiles = map[string]string{
	"go.mod": "module example.com/cgtestmod\n\ngo 1.21\n\nrequire example.com/dep v1.2.3\n",
	"a.go":   "package cgtestmod\n",
}

// childEnv runs one analysis of a module zip with a go binary that dumps its
// environment, and returns what the child was given.
func childEnv(t *testing.T, a *staticcha.Analyser, recorded string, files map[string]string) map[string]string {
	t.Helper()
	zipPath := writeZipToTemp(t, makeZip(t, testCoord, files))
	if _, err := a.Analyse(context.Background(), zipPath, testCoord, domain.AnalysisInputs{}); err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	return readChildEnv(t, recorded)
}

// fakeGoAnalyser builds an Analyser driving a go binary that records its
// environment and then fails, so every load reports rather than compiles.
func fakeGoAnalyser(t *testing.T) (*staticcha.Analyser, string) {
	t.Helper()
	recorded := filepath.Join(t.TempDir(), "child.env")
	t.Setenv("KANONARION_CHILD_ENV_OUT", recorded)

	fakeGo := filepath.Join(t.TempDir(), "fake-go")
	script := "#!/bin/sh\nenv > \"$KANONARION_CHILD_ENV_OUT\"\nexit 1\n"
	if err := os.WriteFile(fakeGo, []byte(script), 0o700); err != nil { // #nosec G306 -- a binary this test execs must be executable
		t.Fatalf("writing fake go: %v", err)
	}
	return staticcha.New("0.0.0-test", fakeGo, slog.New(slog.NewTextHandler(io.Discard, nil))), recorded
}

func readChildEnv(t *testing.T, recorded string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(recorded) // #nosec G304 -- a path this test made under its own t.TempDir()
	if err != nil {
		t.Fatalf("the loader never ran a child, so nothing about its environment was measured: %v", err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			out[k] = v
		}
	}
	return out
}

// TestAnalyse_ChildResolvesFromTheMaterialisedCache is the whole of the fix,
// measured on the child: an isolated analysis reads a module cache this run
// built, seeded with the requirements the analysed module declares, rather than
// whatever the host's own cache happens to hold.
func TestAnalyse_ChildResolvesFromTheMaterialisedCache(t *testing.T) {
	cache := &recordingCache{}
	a, recorded := fakeGoAnalyser(t)
	a = a.WithModuleCache(cache)

	child := childEnv(t, a, recorded, dependentModuleFiles)

	if cache.calls != 1 {
		t.Fatalf("the cache was materialised %d times, want exactly once", cache.calls)
	}
	if got := child["GOMODCACHE"]; got != cache.dir {
		t.Errorf("the child read GOMODCACHE=%q, want the materialised cache %q", got, cache.dir)
	}
	if got := cache.main.Requires; len(got) != 1 || got[0].Path() != "example.com/dep" || got[0].Version() != "v1.2.3" {
		t.Errorf("the cache was seeded with %v, want the module's own requirement example.com/dep@v1.2.3", got)
	}
	// The directive travels with the requirements: it is what decides whether the
	// toolchain reads past them into the unpruned graph.
	if cache.main.GoVersion != "1.21" {
		t.Errorf("the cache was told go %q, want the directive the analysed tree declares", cache.main.GoVersion)
	}
	// The offline posture is what makes the cache load-bearing; it must not have
	// been relaxed to pay for it.
	if got := child["GOPROXY"]; got != "off" {
		t.Errorf("the child read GOPROXY=%q, want off", got)
	}
}

// TestAnalyse_MaterialisedCacheIsRemoved guards that a per-analysis cache does
// not outlive the analysis. One left behind per module accumulates under the
// system temp root for as long as the host lives — measured at 6.7GB over 86
// analyses when the removal was a plain os.RemoveAll.
//
// The read-only entry is what makes this more than a stat: the go command writes
// what it extracts read-only, and RemoveAll cannot unlink a child of a read-only
// directory. The cache is planted with one here so the test fails against that
// removal rather than only against a missing one.
func TestAnalyse_MaterialisedCacheIsRemoved(t *testing.T) {
	cache := &recordingCache{plantReadOnlyEntry: true}
	a, recorded := fakeGoAnalyser(t)
	a = a.WithModuleCache(cache)

	childEnv(t, a, recorded, dependentModuleFiles)

	if _, err := os.Stat(cache.dir); err == nil {
		t.Errorf("the materialised cache %s survived the analysis", cache.dir)
	}
}

// TestAnalyse_FromModcacheReadsTheOperatorsCache pins the --from-modcache
// decision: an operator who has pointed at a populated cache gets it, and
// nothing is duplicated per module.
func TestAnalyse_FromModcacheReadsTheOperatorsCache(t *testing.T) {
	real := t.TempDir()
	a, recorded := fakeGoAnalyser(t)
	a = a.WithModuleCache(refusingCache{t: t}).WithRealModcache(real)

	child := childEnv(t, a, recorded, dependentModuleFiles)

	if got := child["GOMODCACHE"]; got != real {
		t.Errorf("the child read GOMODCACHE=%q, want the operator's cache %q", got, real)
	}
}

// TestAnalyse_WithoutAMaterialiserKeepsTheHostCache holds the behaviour a
// composition root that wires no store still gets: the host's own cache, which
// is what every analysis read before one could be built.
func TestAnalyse_WithoutAMaterialiserKeepsTheHostCache(t *testing.T) {
	a, recorded := fakeGoAnalyser(t)
	t.Setenv("GOMODCACHE", "/kanonarion-test/host-modcache")

	child := childEnv(t, a, recorded, dependentModuleFiles)

	if got := child["GOMODCACHE"]; got != "/kanonarion-test/host-modcache" {
		t.Errorf("the child read GOMODCACHE=%q, want the host's own cache untouched", got)
	}
}

// TestAnalyse_ModuleRequiringNothingMaterialisesNothing: a module that resolves
// from the standard library alone has no closure to populate, and an empty cache
// serves it exactly as well as a full one.
func TestAnalyse_ModuleRequiringNothingMaterialisesNothing(t *testing.T) {
	cache := &recordingCache{}
	a, recorded := fakeGoAnalyser(t)
	a = a.WithModuleCache(cache)

	childEnv(t, a, recorded, testModuleFiles)

	if cache.calls != 0 {
		t.Errorf("a module with no requirements had a cache materialised for it %d times", cache.calls)
	}
}

// TestAnalyseDir_WorkingTreeKeepsTheDevelopersCache is the other side of the
// split loadenv.go draws on the workspace: a working tree is the developer's own
// build, and a cache materialised from the store would describe a different one.
func TestAnalyseDir_WorkingTreeKeepsTheDevelopersCache(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/probe\n\ngo 1.21\n\nrequire example.com/dep v1.2.3\n",
		"a.go":   "package probe\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	cache := &recordingCache{}
	a, recorded := fakeGoAnalyser(t)
	a = a.WithModuleCache(cache)
	t.Setenv("GOMODCACHE", "/kanonarion-test/developer-modcache")

	coord, err := coordinate.NewModuleCoordinate("example.com/probe", coordinate.LocalVersion)
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	if _, err := a.AnalyseDir(context.Background(), dir, coord); err != nil {
		t.Fatalf("AnalyseDir: %v", err)
	}

	if cache.calls != 0 {
		t.Errorf("a working tree had a cache materialised for it %d times", cache.calls)
	}
	if got := readChildEnv(t, recorded)["GOMODCACHE"]; got != "/kanonarion-test/developer-modcache" {
		t.Errorf("the child read GOMODCACHE=%q, want the developer's own cache", got)
	}
}
