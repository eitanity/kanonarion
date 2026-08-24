package staticcha

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

func mustCoord(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate(%q, %q): %v", path, version, err)
	}
	return c
}

// TestSynthesiseGoMod_WritesCoordinatePathAndPinnedDirective covers the two
// constraints a synthesised file has to satisfy for its graph to join the rest
// of the ledger: the module path is the coordinate's, and the go directive is
// the pinned constant rather than whatever the host toolchain would default to.
func TestSynthesiseGoMod_WritesCoordinatePathAndPinnedDirective(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	synth, err := synthesiseGoMod(dir, mustCoord(t, "example.com/premod", "v0.0.0-20180430131211-7c2a214ada46"), domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("synthesiseGoMod: %v", err)
	}
	if synth.ModulePath != "example.com/premod" {
		t.Errorf("ModulePath = %q, want the coordinate's path", synth.ModulePath)
	}
	if synth.GoDirective != synthesisedGoDirective {
		t.Errorf("GoDirective = %q, want the pinned %q", synth.GoDirective, synthesisedGoDirective)
	}
	if synth.VendorTreePresent {
		t.Error("VendorTreePresent = true for a tree with no vendor directory")
	}

	body, err := os.ReadFile(filepath.Join(dir, "go.mod")) /* #nosec G304 -- dir is this test's own t.TempDir() */
	if err != nil {
		t.Fatalf("reading synthesised go.mod: %v", err)
	}
	want := "module example.com/premod\n\ngo " + synthesisedGoDirective + "\n"
	if string(body) != want {
		t.Errorf("synthesised go.mod =\n%q\nwant\n%q", body, want)
	}
}

// TestSynthesiseGoMod_IncompatibleVersionAddsNoMajorSuffix pins the rule that a
// +incompatible coordinate keeps its published path. Deriving "/v2" from the
// version would produce a module path nothing resolves to, and a graph whose
// every node ID names it would build cleanly and join nothing.
func TestSynthesiseGoMod_IncompatibleVersionAddsNoMajorSuffix(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	synth, err := synthesiseGoMod(dir, mustCoord(t, "github.com/example/sprigalike", "v2.22.0+incompatible"), domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("synthesiseGoMod: %v", err)
	}
	if synth.ModulePath != "github.com/example/sprigalike" {
		t.Errorf("ModulePath = %q, want the path with no major-version suffix", synth.ModulePath)
	}
	body, err := os.ReadFile(filepath.Join(dir, "go.mod")) /* #nosec G304 -- dir is this test's own t.TempDir() */
	if err != nil {
		t.Fatalf("reading synthesised go.mod: %v", err)
	}
	if got := string(body); got != "module github.com/example/sprigalike\n\ngo "+synthesisedGoDirective+"\n" {
		t.Errorf("synthesised go.mod = %q, want no /v2 in the module path", got)
	}
}

// TestSynthesiseGoMod_RefusesWhenModuleShipsOne is the guard that keeps this
// change from masking failures it does not explain: a module that publishes a
// go.mod and fails to load is failing for its own reasons, and overwriting the
// published file would replace that diagnosis with a fabricated tree.
func TestSynthesiseGoMod_RefusesWhenModuleShipsOne(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	published := "module example.com/published\n\ngo 1.19\n\nrequire example.com/dep v1.2.3\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(published), 0o600); err != nil {
		t.Fatalf("seeding published go.mod: %v", err)
	}

	synth, err := synthesiseGoMod(dir, mustCoord(t, "example.com/other", "v1.0.0"), domain.AnalysisInputs{})
	if err == nil {
		t.Fatal("synthesiseGoMod succeeded on a module that ships its own go.mod")
	}
	if !synth.IsZero() {
		t.Errorf("SynthesisedGoMod = %+v, want the zero value when nothing was written", synth)
	}
	body, err := os.ReadFile(filepath.Join(dir, "go.mod")) /* #nosec G304 -- dir is this test's own t.TempDir() */
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	if string(body) != published {
		t.Errorf("published go.mod was modified:\n%q", body)
	}
}

// TestSynthesiseGoMod_RefusesWhenDependenciesMustBeResolved keeps the change
// inside the half it can deliver honestly. A synthesised go.mod carries no
// require list, so a module that imports third-party code would be analysed
// against versions nobody chose — producing edges that join nothing else in the
// ledger. Such a module keeps failing, and the refusal names why.
func TestSynthesiseGoMod_RefusesWhenDependenciesMustBeResolved(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := "package premod\n\nimport \"github.com/example/dep\"\n\n// F uses a dependency.\nfunc F() { dep.G() }\n"
	if err := os.WriteFile(filepath.Join(dir, "premod.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("writing source: %v", err)
	}

	synth, err := synthesiseGoMod(dir, mustCoord(t, "example.com/premod", "v1.0.0"), domain.AnalysisInputs{})
	if !errors.Is(err, errNeedsDependencyResolution) {
		t.Fatalf("err = %v, want errNeedsDependencyResolution", err)
	}
	if !strings.Contains(err.Error(), "github.com/example/dep") {
		t.Errorf("refusal %q does not name the import that caused it", err)
	}
	if !synth.IsZero() {
		t.Errorf("SynthesisedGoMod = %+v, want the zero value", synth)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Error("a go.mod was written for a module whose dependencies cannot be resolved")
	}
}

// TestSynthesiseGoMod_TestOnlyDependencyDoesNotBlock: a third-party import that
// appears only in _test.go declarations costs the test axis, which the load
// records on its own terms. It is not a reason to leave the module with no graph
// at all.
func TestSynthesiseGoMod_TestOnlyDependencyDoesNotBlock(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	files := map[string]string{
		"premod.go":      "package premod\n\nimport \"strings\"\n\n// F is exported.\nfunc F(s string) string { return strings.ToUpper(s) }\n",
		"premod_test.go": "package premod\n\nimport (\n\t\"testing\"\n\n\t\"github.com/stretchr/testify/assert\"\n)\n\nfunc TestF(t *testing.T) { assert.Equal(t, \"A\", F(\"a\")) }\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	if _, err := synthesiseGoMod(dir, mustCoord(t, "example.com/premod", "v1.0.0"), domain.AnalysisInputs{}); err != nil {
		t.Fatalf("synthesiseGoMod refused a module whose only external import is in a test file: %v", err)
	}
}

// TestSynthesiseGoMod_IgnoresNonPackageDirectories: vendored copies, testdata
// and nested modules are not this module's packages, so their imports must not
// decide whether it can be synthesised for.
func TestSynthesiseGoMod_IgnoresNonPackageDirectories(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	files := map[string]string{
		"premod.go":                      "package premod\n\n// F is exported.\nfunc F() {}\n",
		"vendor/example.com/dep/dep.go":  "package dep\n\nimport \"github.com/example/other\"\n\n// G is vendored.\nfunc G() { other.H() }\n",
		"testdata/sample.go":             "package sample\n\nimport \"github.com/example/fixture\"\n\n// H is fixture data.\nfunc H() { fixture.I() }\n",
		"nested/go.mod":                  "module example.com/nested\n\ngo 1.21\n",
		"nested/nested.go":               "package nested\n\nimport \"github.com/example/nesteddep\"\n\n// J is another module's.\nfunc J() { nesteddep.K() }\n",
		"_ignored/ignored.go":            "package ignored\n\nimport \"github.com/example/ignoreddep\"\n\n// L is ignored by the toolchain.\nfunc L() { ignoreddep.M() }\n",
		"premod_windows_amd64_extra.txt": "not go source\n",
	}
	for name, body := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("creating %s: %v", name, err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	synth, err := synthesiseGoMod(dir, mustCoord(t, "example.com/premod", "v1.0.0"), domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("synthesiseGoMod refused on imports outside the module's own packages: %v", err)
	}
	if !synth.VendorTreePresent {
		t.Error("VendorTreePresent = false for a tree that ships vendor/")
	}
}

// TestSynthesiseGoMod_DetectsVendorTree records the hazard rather than leaving
// it to the toolchain: a go.mod beside a vendor directory auto-selects
// -mod=vendor, at which point the graph would describe vendored copies.
func TestSynthesiseGoMod_DetectsVendorTree(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "vendor"), 0o750); err != nil {
		t.Fatalf("creating vendor tree: %v", err)
	}

	synth, err := synthesiseGoMod(dir, mustCoord(t, "example.com/vendored", "v1.0.0"), domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("synthesiseGoMod: %v", err)
	}
	if !synth.VendorTreePresent {
		t.Error("VendorTreePresent = false for a tree that ships vendor/")
	}
}

// TestAnalysisEnv_PinsModuleModeOnEveryLoad holds the two things -mod=mod is
// doing. It overrides an inherited vendor selection, which a synthesised go.mod
// beside a vendor tree would otherwise auto-select; and it lifts the main-module
// go.sum obligation off an artefact that never took it on, which is why it is on
// every load rather than only the synthesised ones. It must be LAST, because
// os/exec keeps the final occurrence of a duplicate key.
func TestAnalysisEnv_PinsModuleModeOnEveryLoad(t *testing.T) {
	t.Parallel()

	plain := analysisEnv()
	if idx := slices.Index(plain, "GOFLAGS=-mod=mod"); idx != len(plain)-1 {
		t.Errorf("GOFLAGS at position %d of %d on a load that synthesised nothing: "+
			"a published zip carrying no go.sum for its own module graph fails the load without it",
			idx, len(plain))
	}

	vendored := analysisEnv()
	if !slices.Contains(vendored, "GOFLAGS=-mod=mod") {
		t.Error("analysisEnv left vendor mode selectable beside a synthesised go.mod")
	}
	if idx := slices.Index(vendored, "GOFLAGS=-mod=mod"); idx != len(vendored)-1 {
		t.Errorf("GOFLAGS at position %d of %d: it must be last so it wins the os/exec dedupe", idx, len(vendored))
	}
	if !slices.Contains(vendored, "GOWORK=off") {
		t.Error("analysisEnv dropped the workspace isolation it inherits from isolatedModuleEnv")
	}
}

// TestSynthesiseGoMod_PinsRequiresFromTheOfferedBuildList is the half the
// refusal above was holding open. The versions come from a build that already
// resolved them, so the file names coordinates the rest of the ledger holds and
// the load never has to ask a proxy what "latest" means today.
func TestSynthesiseGoMod_PinsRequiresFromTheOfferedBuildList(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := "package premod\n\nimport \"github.com/example/dep/sub\"\n\n// F uses a dependency.\nfunc F() { sub.G() }\n"
	if err := os.WriteFile(filepath.Join(dir, "premod.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("writing source: %v", err)
	}

	dep := mustCoord(t, "github.com/example/dep", "v1.4.2")
	synth, err := synthesiseGoMod(dir, mustCoord(t, "example.com/premod", "v1.0.0"), domain.AnalysisInputs{
		BuildList: map[coordinate.ModuleCoordinate]struct{}{dep: {}},
		Source:    "01WALKAAAAAAAAAAAAAAAAAAAA",
	})
	if err != nil {
		t.Fatalf("synthesiseGoMod: %v", err)
	}
	if len(synth.Requires) != 1 || synth.Requires[0].Path != dep.Path() || synth.Requires[0].Version != dep.Version() {
		t.Fatalf("Requires = %+v, want the one coordinate the build list resolved", synth.Requires)
	}

	body, err := os.ReadFile(filepath.Join(dir, "go.mod")) /* #nosec G304 -- dir is this test's own t.TempDir() */
	if err != nil {
		t.Fatalf("reading synthesised go.mod: %v", err)
	}
	want := "module example.com/premod\n\ngo " + synthesisedGoDirective + "\n\nrequire (\n\tgithub.com/example/dep v1.4.2\n)\n"
	if string(body) != want {
		t.Errorf("synthesised go.mod =\n%q\nwant\n%q", body, want)
	}
}

// TestSynthesiseGoMod_RefusesWhenTheBuildListMissesOneImport keeps the
// all-or-nothing rule at the level that writes the file. A go.mod naming one of
// two dependencies still sends the loader hunting for the other.
func TestSynthesiseGoMod_RefusesWhenTheBuildListMissesOneImport(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := "package premod\n\nimport (\n\t\"github.com/example/dep\"\n\t\"github.com/example/absent\"\n)\n\n" +
		"// F uses two dependencies.\nfunc F() { dep.G(); absent.H() }\n"
	if err := os.WriteFile(filepath.Join(dir, "premod.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("writing source: %v", err)
	}

	dep := mustCoord(t, "github.com/example/dep", "v1.4.2")
	synth, err := synthesiseGoMod(dir, mustCoord(t, "example.com/premod", "v1.0.0"), domain.AnalysisInputs{
		BuildList: map[coordinate.ModuleCoordinate]struct{}{dep: {}},
		Source:    "01WALKAAAAAAAAAAAAAAAAAAAA",
	})
	if !errors.Is(err, errNeedsDependencyResolution) {
		t.Fatalf("err = %v, want errNeedsDependencyResolution", err)
	}
	if !strings.Contains(err.Error(), "github.com/example/absent") {
		t.Errorf("refusal %q does not name the import the build list could not pin", err)
	}
	if !strings.Contains(err.Error(), "01WALKAAAAAAAAAAAAAAAAAAAA") {
		t.Errorf("refusal %q does not name the build list that was consulted", err)
	}
	if !synth.IsZero() {
		t.Errorf("SynthesisedGoMod = %+v, want the zero value", synth)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Error("a partially-pinned go.mod was written")
	}
}

// TestAnalysisEnv_LoadsOffline pins the posture every analysis rests on: the
// versions are already chosen — by the walk for a fetched module, by the tree's
// own go.mod and go.sum for a working tree, by the synthesis for a module with
// no usable go.mod — so the only legitimate source for them is the local module
// cache, and a load that could reach a proxy could substitute something nobody
// selected. It was once conditional on a synthesised require list, which left
// the two commonest paths reaching the proxy for names that cannot resolve
// there.
func TestAnalysisEnv_LoadsOffline(t *testing.T) {
	t.Parallel()
	env := analysisEnv()
	for _, want := range []string{"GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=mod"} {
		if !slices.Contains(env, want) {
			t.Errorf("analysisEnv does not set %s: a load that can reach a proxy can substitute "+
				"a version nobody chose, and pays a round trip per unresolvable name", want)
		}
	}
	// The control that must hold: GOFLAGS stays last, so os/exec's keep-the-last
	// dedupe cannot have the offline pins displace it.
	if idx := slices.Index(env, "GOFLAGS=-mod=mod"); idx != len(env)-1 {
		t.Errorf("GOFLAGS at position %d of %d", idx, len(env))
	}
}

// coldCacheDep is a module this host has already fetched, so a fixture can carry
// a real go.sum and still resolve nothing from an empty cache.
const coldCacheDepPath, coldCacheDepVersion = "gopkg.in/yaml.v3", "v3.0.1"

// seedGoSum writes the go.sum the tree's own toolchain would have written, from
// this host's warm cache and with no network.
//
// The analysis posture is read-only, so a fixture that omits go.sum now tests a
// missing checksum rather than the cold cache it means to test — these fixtures
// were relying on the analysis to supply it.
func seedGoSum(t *testing.T, dir string) {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", "./...") // #nosec G204 -- fixed binary, literal arguments
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GOFLAGS=-mod=mod", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot seed go.sum for %s@%s from this host's module cache: %v\n%s",
			coldCacheDepPath, coldCacheDepVersion, err, out)
	}
}

// modOnlyCache is a module cache holding the dependency's .mod but not its zip:
// version selection reads the .mod and succeeds, and the package load that needs
// the source meets the offline posture.
func modOnlyCache(t *testing.T) string {
	t.Helper()
	cache := t.TempDir()
	depDir := filepath.Join(cache, "cache", "download", filepath.FromSlash(coldCacheDepPath), "@v")
	if err := os.MkdirAll(depDir, 0o750); err != nil {
		t.Fatalf("module cache: %v", err)
	}
	out, err := exec.Command("go", "env", "GOMODCACHE").Output() // #nosec G204 -- fixed binary, literal arguments
	if err != nil {
		t.Skipf("cannot locate this host's module cache: %v", err)
	}
	src := filepath.Join(strings.TrimSpace(string(out)), "cache", "download",
		filepath.FromSlash(coldCacheDepPath), "@v")
	for _, name := range []string{coldCacheDepVersion + ".mod", coldCacheDepVersion + ".info"} {
		data, rerr := os.ReadFile(filepath.Join(src, name)) // #nosec G304 -- this host's own module cache
		if rerr != nil {
			t.Skipf("%s is not in this host's module cache: %v", name, rerr)
		}
		// #nosec G703 -- both segments are package constants joined into t.TempDir()
		if werr := os.WriteFile(filepath.Join(depDir, name), data, 0o600); werr != nil {
			t.Fatalf("writing %s: %v", name, werr)
		}
	}
	return cache
}

// TestAnalyseDir_AbsentDependencyNamesTheColdCache is the behaviour change the
// offline default owes an account of. A working tree used to be loaded with
// whatever GOPROXY the environment offered, so a dependency missing from the
// module cache was fetched; it is now loaded offline and the packages importing
// it do not type-check.
//
// What the user then sees must not be a bare loader error. The type errors that
// reach the record name the import — "could not import x" — and never the
// reason, because the reason is the go command's sentence about its own offline
// posture and that is reported by the metadata load. Without it a cold cache
// reads as unexplained breakage in the module, and the remedy — warm the cache —
// is nowhere on the record.
func TestAnalyseDir_AbsentDependencyNamesTheColdCache(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	write("go.mod", "module example.com/needsdep\n\ngo 1.21\n\nrequire "+
		coldCacheDepPath+" "+coldCacheDepVersion+"\n")
	write("a.go", "package needsdep\n\nimport _ \""+coldCacheDepPath+"\"\n\nfunc F() {}\n")
	seedGoSum(t, dir)
	// An empty module cache, so the requirement above cannot be satisfied locally
	// however warm this host's real cache is.
	t.Setenv("GOMODCACHE", filepath.Join(t.TempDir(), "cold"))

	coord, err := coordinate.NewModuleCoordinate("example.com/needsdep", coordinate.LocalVersion)
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	rec, err := quietAnalyser().AnalyseDir(context.Background(), dir, coord)
	if err != nil {
		t.Fatalf("AnalyseDir: %v", err)
	}
	if rec.OverallStatus == domain.CallGraphStatusExtracted {
		t.Fatalf("a tree whose dependency is not in the cache was recorded as fully extracted")
	}
	if !isOfflineCacheMiss(rec.FailureDetail) {
		t.Errorf("the record does not say the module cache was cold, so the remedy is not on it: %q",
			rec.FailureDetail)
	}
}

// TestOfflineCacheMissIsNotTheModulesFault. The offline posture a pinned
// synthesis imposes belongs to this host, so a dependency absent from the local
// module cache must never be recorded as a property of the published bytes: a
// module fault is CACHEABLE, and caching a cold cache makes a warm one
// irrelevant forever.
//
// Measured on the reference store: sprig@v2.22.0+incompatible pinned all seven
// of its requires from the corteza build list and then failed minimal version
// selection because the transitive go.mod graph was not in GOMODCACHE.
func TestOfflineCacheMissIsNotTheModulesFault(t *testing.T) {
	t.Parallel()
	const detail = "meta load: err: exit status 1: stderr: go: golang.org/x/crypto@v0.31.0 requires\n" +
		"\tgolang.org/x/text@v0.21.0 requires\n" +
		"\tgolang.org/x/net@v0.25.0: module lookup disabled by GOPROXY=off"
	if !isOfflineCacheMiss(detail) {
		t.Error("a load that failed because the module cache is cold was not recognised as such; " +
			"the record would file this host's missing file as the module's permanent fault")
	}
	// The control that must be false: a genuine module fault stays the module's.
	for _, real := range []string{
		"no packages successfully loaded",
		"err: exit status 1: stderr: premod.go:3:8: undefined: nope",
		"",
	} {
		if isOfflineCacheMiss(real) {
			t.Errorf("a genuine module failure was reclassified as environmental: %q", real)
		}
	}
}

// TestAnalyseDir_ColdCachePartialStatesTheEnvironmentCause is the other half of
// naming the cold cache: the reason has to reach the axis that decides whether
// the record may be served back, not only the prose a reader sees.
//
// A tree whose module cache holds a dependency's go.mod but not its source loads
// far enough to produce a graph — every package that does not import it
// typechecks — so the record is Partial rather than failed. Left unattributed,
// that record is cacheable, and the run made after the cache was warmed is
// served it: the analysis that would finally have measured the whole tree never
// happens, and the remedy the tool prints reads as tried and failed.
func TestAnalyseDir_ColdCachePartialStatesTheEnvironmentCause(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o750); err != nil {
			t.Fatalf("mkdir for %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	write("go.mod", "module example.com/needsdep\n\ngo 1.21\n\nrequire "+
		coldCacheDepPath+" "+coldCacheDepVersion+"\n")
	write("a.go", "package needsdep\n\nimport _ \""+coldCacheDepPath+"\"\n\nfunc A() {}\n")
	// The package that carries the graph: nothing about it is missing, so the
	// analysis produces something and the outcome is an incompleteness.
	write("b/b.go", "package b\n\nfunc B() {}\n")
	seedGoSum(t, dir)
	t.Setenv("GOMODCACHE", modOnlyCache(t))

	coord, err := coordinate.NewModuleCoordinate("example.com/needsdep", coordinate.LocalVersion)
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	rec, err := quietAnalyser().AnalyseDir(context.Background(), dir, coord)
	if err != nil {
		t.Fatalf("AnalyseDir: %v", err)
	}
	if rec.OverallStatus != domain.CallGraphStatusPartial {
		t.Fatalf("status = %s, want Partial (detail: %q)", rec.OverallStatus, rec.FailureDetail)
	}
	if rec.FailureCause != domain.FailureCauseEnvironment {
		t.Errorf("cause = %q, want %q: the cold cache reached the prose and not the axis, so this "+
			"record is served back to the run made after the cache was warmed (detail: %q)",
			rec.FailureCause, domain.FailureCauseEnvironment, rec.FailureDetail)
	}
	if domain.RecordIsCacheable(rec) {
		t.Error("a graph this host's cold cache cut short is servable as a cache hit")
	}
}

// TestAnalyseDir_PartialFromTheModulesOwnSourcesStaysCacheable is the control the
// change above must not break. A package that does not typecheck on its own
// terms is a stable finding about the module, and re-deriving it on every run
// would pay a full analysis to rediscover it.
func TestAnalyseDir_PartialFromTheModulesOwnSourcesStaysCacheable(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o750); err != nil {
			t.Fatalf("mkdir for %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	write("go.mod", "module example.com/broken\n\ngo 1.21\n")
	write("a/a.go", "package a\n\nfunc A() { undefinedHelper() }\n")
	write("b/b.go", "package b\n\nfunc B() {}\n")

	coord, err := coordinate.NewModuleCoordinate("example.com/broken", coordinate.LocalVersion)
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	rec, err := quietAnalyser().AnalyseDir(context.Background(), dir, coord)
	if err != nil {
		t.Fatalf("AnalyseDir: %v", err)
	}
	if rec.OverallStatus != domain.CallGraphStatusPartial {
		t.Fatalf("status = %s, want Partial (detail: %q)", rec.OverallStatus, rec.FailureDetail)
	}
	if rec.FailureCause != domain.FailureCauseModule {
		t.Errorf("cause = %q, want %q", rec.FailureCause, domain.FailureCauseModule)
	}
	if !domain.RecordIsCacheable(rec) {
		t.Error("a module's own compile error is re-derived on every run rather than served")
	}
}

// TestAnalysisEnv_PinsTheLocalToolchain is the control on the offline posture
// being internally consistent: a switch left enabled alongside GOPROXY=off and
// GOSUMDB=off can only fail, and it failed naming the checksum database.
func TestAnalysisEnv_PinsTheLocalToolchain(t *testing.T) {
	t.Parallel()
	env := analysisEnv()
	if !slices.Contains(env, "GOTOOLCHAIN=local") {
		t.Error("analysisEnv leaves the toolchain switch enabled alongside GOPROXY=off and GOSUMDB=off: " +
			"the switch cannot complete, and the load fails naming the checksum database instead of the version gap")
	}
	// The control that must still hold: GOFLAGS keeps the last position, so
	// os/exec's keep-the-last dedupe cannot have the new pin displace it.
	if idx := slices.Index(env, "GOFLAGS=-mod=mod"); idx != len(env)-1 {
		t.Errorf("GOFLAGS at position %d of %d", idx, len(env))
	}
}

// TestAnalysisEnv_OverridesInheritedToolchainSetting guards the direction of the
// override: an ambient GOTOOLCHAIN=auto is the default every shell carries, and
// it would otherwise win the duplicate-key dedupe.
func TestAnalysisEnv_OverridesInheritedToolchainSetting(t *testing.T) {
	t.Setenv("GOTOOLCHAIN", "auto")

	env := analysisEnv()

	last := ""
	for _, kv := range env {
		if strings.HasPrefix(kv, "GOTOOLCHAIN=") {
			last = kv
		}
	}
	if last != "GOTOOLCHAIN=local" {
		t.Errorf("effective GOTOOLCHAIN = %q, want GOTOOLCHAIN=local to win over the inherited setting", last)
	}
}

// TestAnalysisEnv_StaysOffline is the guarantee the pin must not loosen: the
// point is to stop the child attempting a fetch, never to permit one.
func TestAnalysisEnv_StaysOffline(t *testing.T) {
	t.Parallel()
	env := analysisEnv()
	for _, want := range []string{"GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOWORK=off"} {
		if !slices.Contains(env, want) {
			t.Errorf("analysisEnv does not set %s", want)
		}
	}
}

// TestAnalyseDir_MissingChecksumEntryNamesTheGapNotTheSource is the failure path
// of the read-only posture. The tree is no longer edited to close a go.sum gap,
// so the gap has to be reported instead — and the type errors that reach the
// record name the import and never the reason, exactly as they do for a cold
// cache. The go command said both the condition and its own remedy, one layer
// down, and the SSA layer above replaced it with "invalid package name".
func TestAnalyseDir_MissingChecksumEntryNamesTheGapNotTheSource(t *testing.T) {
	dir := t.TempDir()
	// Nothing here needs a real module or this host's cache: the go command
	// refuses on the checksum before it looks anything up.
	t.Setenv("GOMODCACHE", filepath.Join(t.TempDir(), "empty"))
	for name, content := range map[string]string{
		"go.mod": "module example.com/needsdep\n\ngo 1.21\n\nrequire example.com/dep v1.0.0\n",
		"a.go":   "package needsdep\n\nimport _ \"example.com/dep\"\n\nfunc F() {}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	coord := mustCoord(t, "example.com/needsdep", coordinate.LocalVersion)
	rec, err := quietAnalyser().AnalyseDir(context.Background(), dir, coord)
	if err != nil {
		t.Fatalf("AnalyseDir: %v", err)
	}

	if !domain.IsMissingChecksumEntry(rec.FailureDetail) {
		t.Errorf("the record does not name the checksum gap, so the reader is sent after a fault in "+
			"source that compiles: %q", rec.FailureDetail)
	}
	// The gap is in the tree, not on this host, and the tree's digest moves when
	// the developer closes it. The axis must not move with the message.
	if rec.FailureCause != domain.FailureCauseModule {
		t.Errorf("cause = %q, want %q: a checksum the tree does not carry is not this host's",
			rec.FailureCause, domain.FailureCauseModule)
	}
	if !domain.RecordIsIncomplete(rec) {
		t.Fatalf("the record is not incomplete, so no remedy is printed at all (status %s)", rec.OverallStatus)
	}
	remedy := domain.IncompleteGraphRemedy(coord, rec.FailureCause, rec.FailureDetail, dir)
	if strings.Contains(remedy, "Fix the package so it compiles") {
		t.Errorf("the reader is told to edit source that is fine:\n%s", remedy)
	}
	if !strings.Contains(remedy, domain.MissingChecksumRemedy) {
		t.Errorf("the remedy names nothing that closes the checksum gap:\n%s", remedy)
	}
}
