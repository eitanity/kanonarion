package staticcha

import (
	"errors"
	"io/fs"
	"os"
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

// TestAnalysisEnv_DisablesVendorModeOnlyWhenVendored checks the decision the
// vendor flag drives. Vendor mode is left alone for every other analysis: a
// module that ships both a go.mod and a vendor tree is entitled to be read the
// way its own configuration says.
func TestAnalysisEnv_DisablesVendorModeOnlyWhenVendored(t *testing.T) {
	t.Parallel()

	plain := analysisEnv(domain.SynthesisedGoMod{})
	if slices.Contains(plain, "GOFLAGS=-mod=mod") {
		t.Error("analysisEnv disabled vendor mode for an analysis that synthesised nothing")
	}

	vendored := analysisEnv(domain.SynthesisedGoMod{
		ModulePath:        "example.com/vendored",
		GoDirective:       synthesisedGoDirective,
		VendorTreePresent: true,
	})
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
	want := "module example.com/premod\n\ngo 1.16\n\nrequire (\n\tgithub.com/example/dep v1.4.2\n)\n"
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

// TestAnalysisEnv_PinnedRequiresLoadOffline pins the posture the pinning rests
// on: the versions are already chosen, so the only legitimate source for them is
// the local module cache, and a load that could reach a proxy could substitute
// something the walk never selected.
func TestAnalysisEnv_PinnedRequiresLoadOffline(t *testing.T) {
	t.Parallel()
	pinned := analysisEnv(domain.SynthesisedGoMod{
		ModulePath:  "example.com/premod",
		GoDirective: "1.16",
		Requires:    []domain.SynthesisedRequire{{Path: "github.com/example/dep", Version: "v1.4.2"}},
	})
	for _, want := range []string{"GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=mod"} {
		if !slices.Contains(pinned, want) {
			t.Errorf("analysisEnv for a pinned synthesis does not set %s", want)
		}
	}
	// The control that must be absent: an analysis that pinned nothing keeps the
	// ambient posture it always had, so this change adds no offline constraint to
	// any path that did not gain a require list.
	plain := analysisEnv(domain.SynthesisedGoMod{ModulePath: "example.com/premod", GoDirective: "1.16"})
	if slices.Contains(plain, "GOPROXY=off") {
		t.Error("an unpinned analysis was forced offline; that is a behaviour change on a path " +
			"this feature does not touch")
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
