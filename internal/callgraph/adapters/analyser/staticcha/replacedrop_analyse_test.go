package staticcha_test

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	"code.eitanity.com/kanonarion/internal/callgraph/domain"
)

// TestAnalyse_MonorepoReplaceIsDroppedAndTheModuleLoads is the regression this
// change exists for.
//
// A module published from a monorepo carries replace directives naming sibling
// directories. No consumer's build applies them — a replace is ignored outside
// the main module — but the analysis makes the extracted module the main module,
// and the siblings are not in the zip, so the requirement dangles and every
// package importing it fails to type-check. Measured on
// github.com/aws/aws-sdk-go-v2/config@v1.32.25: fifteen packages of the
// dependency closure in error, and a record of 86 nodes with ZERO exported-API
// nodes because the module's own root package was one of them.
//
// The dependency here is golang.org/x/mod at the version this repository itself
// requires, so it is in the module cache of any host that built these tests. That
// is what lets the assertion be "the module loads completely" rather than "it
// fails differently".
func TestAnalyse_MonorepoReplaceIsDroppedAndTheModuleLoads(t *testing.T) {
	xmod := builtXModVersion(t)
	coord := mustTestCoord(t, "example.com/premod", "v1.0.0")
	files := map[string]string{
		"go.mod": "module example.com/premod\n\ngo 1.17\n\n" +
			"require golang.org/x/mod " + xmod + "\n\n" +
			"replace golang.org/x/mod => ../mod/\n",
		"premod.go": "package premod\n\nimport \"golang.org/x/mod/semver\"\n\n" +
			"// Canonical is the module's exported entry point.\nfunc Canonical(v string) string { return semver.Canonical(v) }\n",
	}

	a := staticcha.New("0.1.0", "", slog.Default())
	rec, err := a.Analyse(context.Background(), writeZipToTemp(t, makeZip(t, coord, files)), coord, domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("Analyse returned error: %v", err)
	}

	if rec.OverallStatus != domain.CallGraphStatusExtracted {
		t.Fatalf("OverallStatus = %s (%s), want Extracted: the dangling replace should be gone",
			rec.OverallStatus, rec.FailureDetail)
	}
	if strings.Contains(rec.FailureDetail, "replacement directory") {
		t.Errorf("the load still reports a replacement directory: %s", rec.FailureDetail)
	}

	// The consumer-visible cost of the bug was an empty public API: the module's
	// own root package failed, so nothing it exports reached the graph.
	var exported int
	for _, n := range rec.Nodes {
		if n.IsExportedAPI {
			exported++
		}
	}
	if exported == 0 {
		t.Errorf("record carries %d node(s) and no exported-API node: the module's own package did not reach the graph", len(rec.Nodes))
	}

	// The record has to say the analysed tree is not the published tree.
	if len(rec.DroppedReplaces) != 1 {
		t.Fatalf("DroppedReplaces = %v, want the one directive that was removed", rec.DroppedReplaces)
	}
	if got, want := rec.DroppedReplaces[0].String(), "golang.org/x/mod => ../mod/"; got != want {
		t.Errorf("DroppedReplaces[0] = %q, want %q", got, want)
	}
	if summary := domain.DroppedReplacesSummary(rec.DroppedReplaces); !strings.Contains(summary, "../mod/") {
		t.Errorf("the summary a reader sees does not name the directive: %q", summary)
	}
}

// TestAnalyse_VersionToVersionReplaceIsLeftAlone holds the other half of the
// rule. A replace naming a module VERSION resolves with no filesystem involved,
// so the extraction does not break it and removing it would change what the
// module's own build selects.
func TestAnalyse_VersionToVersionReplaceIsLeftAlone(t *testing.T) {
	xmod := builtXModVersion(t)
	if xmod == "v0.39.0" {
		t.Fatal("this build links golang.org/x/mod v0.39.0, the version the fixture replaces away: pick another")
	}
	coord := mustTestCoord(t, "example.com/premod", "v1.0.0")
	files := map[string]string{
		"go.mod": "module example.com/premod\n\ngo 1.17\n\n" +
			"require golang.org/x/mod v0.39.0\n\n" +
			"replace golang.org/x/mod v0.39.0 => golang.org/x/mod " + xmod + "\n",
		"premod.go": "package premod\n\nimport \"golang.org/x/mod/semver\"\n\n" +
			"// Canonical is the module's exported entry point.\nfunc Canonical(v string) string { return semver.Canonical(v) }\n",
	}

	a := staticcha.New("0.1.0", "", slog.Default())
	rec, err := a.Analyse(context.Background(), writeZipToTemp(t, makeZip(t, coord, files)), coord, domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("Analyse returned error: %v", err)
	}
	if len(rec.DroppedReplaces) != 0 {
		t.Errorf("DroppedReplaces = %v: a version-to-version replace was dropped", rec.DroppedReplaces)
	}
	// It resolved THROUGH the replacement, which is the proof the directive was
	// still in force: v0.39.0 is not in this repository's own build.
	if rec.OverallStatus != domain.CallGraphStatusExtracted {
		t.Errorf("OverallStatus = %s (%s), want Extracted", rec.OverallStatus, rec.FailureDetail)
	}
}

// TestAnalyse_UnobtainableRequirementIsTheEnvironment is cause two.
//
// A module whose own go.mod requires something this host does not hold cannot be
// analysed here, and the loader says so — on the DEPENDENCY it failed to obtain,
// not on the module's own package, which gets only the type-checker's
// consequence: `could not import X (invalid package name: "")`. Reading only the
// module's own packages filed a cold cache as the module's source failing to
// compile, which is CACHEABLE, so no later run on a host that had the dependency
// could ever correct it.
func TestAnalyse_UnobtainableRequirementIsTheEnvironment(t *testing.T) {
	coord := mustTestCoord(t, "example.com/premod", "v1.0.0")
	files := map[string]string{
		"go.mod": "module example.com/premod\n\ngo 1.17\n\n" +
			"require example.com/nosuchdep v1.2.3\n",
		"premod.go": "package premod\n\nimport \"example.com/nosuchdep\"\n\n" +
			"// F is the module's exported entry point.\nfunc F() { nosuchdep.G() }\n",
	}

	a := staticcha.New("0.1.0", "", slog.Default())
	rec, err := a.Analyse(context.Background(), writeZipToTemp(t, makeZip(t, coord, files)), coord, domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("Analyse returned error: %v", err)
	}

	if rec.FailureCause != domain.FailureCauseEnvironment {
		t.Errorf("FailureCause = %q, want %q: this host could not supply the requirement, which is not a property of the module",
			rec.FailureCause, domain.FailureCauseEnvironment)
	}
	// Naming the module and version is what a reader can act on. The import path
	// alone does not say which module to go and get.
	if !strings.Contains(rec.FailureDetail, "example.com/nosuchdep v1.2.3") {
		t.Errorf("FailureDetail does not name the module and version that could not be obtained: %s", rec.FailureDetail)
	}
	// And it must never be served back: a host that later holds the module has to
	// get its chance to measure.
	if domain.RecordIsCacheable(rec) {
		t.Error("the record is cacheable: a repaired environment would never re-measure it")
	}
}

// TestAnalyse_TestOnlyRequirementIsAlsoTheEnvironment is the same fault one step
// over, and it is the one the metadata load cannot see.
//
// The metadata load runs with tests off, so a dependency imported only from
// _test.go files never appears in its graph and its "module lookup disabled"
// sentence reaches no error set the record was classified from. Every module
// whose only absent requirement was a test framework was therefore filed against
// the module. Measured on the maintainer's store: nine coordinates, all of them
// short of a testing library.
func TestAnalyse_TestOnlyRequirementIsAlsoTheEnvironment(t *testing.T) {
	coord := mustTestCoord(t, "example.com/premod", "v1.0.0")
	files := map[string]string{
		"go.mod": "module example.com/premod\n\ngo 1.17\n\n" +
			"require example.com/nosuchtestdep v1.3.4\n",
		"premod.go": "package premod\n\n// F is the module's exported entry point.\nfunc F() int { return 1 }\n",
		"premod_test.go": "package premod\n\nimport (\n\t\"testing\"\n\n\t\"example.com/nosuchtestdep\"\n)\n\n" +
			"func TestF(t *testing.T) { nosuchtestdep.Assert(t, F() == 1) }\n",
	}

	a := staticcha.New("0.1.0", "", slog.Default())
	rec, err := a.Analyse(context.Background(), writeZipToTemp(t, makeZip(t, coord, files)), coord, domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("Analyse returned error: %v", err)
	}
	if rec.FailureCause != domain.FailureCauseEnvironment {
		t.Errorf("FailureCause = %q, want %q (status %s, detail %q)",
			rec.FailureCause, domain.FailureCauseEnvironment, rec.OverallStatus, rec.FailureDetail)
	}
	if !strings.Contains(rec.FailureDetail, "example.com/nosuchtestdep v1.3.4") {
		t.Errorf("FailureDetail does not name the test-only module that could not be obtained: %s", rec.FailureDetail)
	}
	if domain.RecordIsCacheable(rec) {
		t.Error("the record is cacheable: a repaired environment would never re-measure it")
	}
}

// TestAnalyse_ModuleWithNoReplaceIsUntouched is the control. The overwhelming
// majority of records must not move, and a rewrite that reformatted every go.mod
// would change the analysed tree of modules this fix has no business touching.
func TestAnalyse_ModuleWithNoReplaceIsUntouched(t *testing.T) {
	a := staticcha.New("0.1.0", "", slog.Default())
	rec, err := a.Analyse(context.Background(), writeZipToTemp(t, makeZip(t, testCoord, testModuleFiles)), testCoord, domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("Analyse returned error: %v", err)
	}
	if rec.OverallStatus != domain.CallGraphStatusExtracted {
		t.Fatalf("OverallStatus = %s (%s), want Extracted", rec.OverallStatus, rec.FailureDetail)
	}
	if len(rec.DroppedReplaces) != 0 {
		t.Errorf("DroppedReplaces = %v on a module that publishes none", rec.DroppedReplaces)
	}
	if rec.FailureCause != domain.FailureCauseUnrecorded {
		t.Errorf("FailureCause = %q on a complete extraction", rec.FailureCause)
	}
}

// builtXModVersion is the golang.org/x/mod version this repository's own build
// selects. The loader runs offline, so a fixture can only require a version the
// host's module cache is certain to hold, and the only such version is the one
// this build resolved. A literal is stranded by the next dependency bump on any
// host whose cache does not still hold the old one.
func builtXModVersion(t *testing.T) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "go", "list", "-m", "-f", "{{.Version}}", "golang.org/x/mod").Output()
	if err != nil {
		t.Fatalf("reading the golang.org/x/mod version this build selects: %v", err)
	}
	version := strings.TrimSpace(string(out))
	if version == "" {
		t.Fatal("go list named no version for golang.org/x/mod")
	}
	return version
}

// TestAnalyse_NestedModuleReplaceIsDroppedAndTheModuleLoads is the otel shape
// end to end: the module replaces its own nested module with "./mod", the zip
// format leaves "./mod" out, and the nested module is published separately. The
// module path golang.org/x makes golang.org/x/mod nested in it, and the host's
// module cache holds that requirement.
func TestAnalyse_NestedModuleReplaceIsDroppedAndTheModuleLoads(t *testing.T) {
	xmod := builtXModVersion(t)
	coord := mustTestCoord(t, "golang.org/x", "v1.0.0")
	files := map[string]string{
		"go.mod": "module golang.org/x\n\ngo 1.17\n\n" +
			"require golang.org/x/mod " + xmod + "\n\n" +
			"replace golang.org/x/mod => ./mod\n",
		"x.go": "package x\n\nimport \"golang.org/x/mod/semver\"\n\n" +
			"// Canonical is the module's exported entry point.\nfunc Canonical(v string) string { return semver.Canonical(v) }\n",
	}

	a := staticcha.New("0.1.0", "", slog.Default())
	rec, err := a.Analyse(context.Background(), writeZipToTemp(t, makeZip(t, coord, files)), coord, domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("Analyse returned error: %v", err)
	}
	if rec.OverallStatus != domain.CallGraphStatusExtracted {
		t.Fatalf("OverallStatus = %s (%s), want Extracted: the nested-module replace should be gone",
			rec.OverallStatus, rec.FailureDetail)
	}
	if len(rec.DroppedReplaces) != 1 {
		t.Fatalf("DroppedReplaces = %v, want the one directive that was removed", rec.DroppedReplaces)
	}
	if got, want := rec.DroppedReplaces[0].String(), "golang.org/x/mod => ./mod"; got != want {
		t.Errorf("DroppedReplaces[0] = %q, want %q", got, want)
	}
}

// TestAnalyse_AbsentInTreeReplaceOfAnotherModuleKeepsGosMessage is the control:
// an absent in-tree target for a module that is not nested in this one is a
// fault in the published bytes, and the go command's own message is the record.
func TestAnalyse_AbsentInTreeReplaceOfAnotherModuleKeepsGosMessage(t *testing.T) {
	coord := mustTestCoord(t, "example.com/premod", "v1.0.0")
	files := map[string]string{
		"go.mod": "module example.com/premod\n\ngo 1.17\n\n" +
			"require example.com/other v1.0.0\n\n" +
			"replace example.com/other => ./other\n",
		"premod.go": "package premod\n\nimport \"example.com/other\"\n\n" +
			"// Value is the module's exported entry point.\nfunc Value() int { return other.V }\n",
	}

	a := staticcha.New("0.1.0", "", slog.Default())
	rec, err := a.Analyse(context.Background(), writeZipToTemp(t, makeZip(t, coord, files)), coord, domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("Analyse returned error: %v", err)
	}
	if len(rec.DroppedReplaces) != 0 {
		t.Errorf("DroppedReplaces = %v: a replace of a module that is not nested was dropped", rec.DroppedReplaces)
	}
	if rec.OverallStatus != domain.CallGraphStatusPartial {
		t.Fatalf("OverallStatus = %s (%s), want Partial", rec.OverallStatus, rec.FailureDetail)
	}
	// go attaches its sentence to the dependency; the importing package gets only
	// "could not import". The record leads with go's own words.
	const gosMessage = "the loader reported: premod.go:3:8: example.com/other@v1.0.0: replacement directory ./other does not exist"
	if !strings.HasPrefix(rec.FailureDetail, gosMessage) {
		t.Errorf("FailureDetail does not lead with go's message about the replace:\n%s", rec.FailureDetail)
	}
	if rec.FailureCause != domain.FailureCauseModule {
		t.Errorf("FailureCause = %q, want module", rec.FailureCause)
	}
}

// TestAnalyse_DependencyErrorNamesNoHostPath holds the dependency error to the
// rule positions follow: a path under the module cache is written relative to
// it. Two analyses reading the same module from two differently named caches
// state one detail, with no "-: " position prefix.
func TestAnalyse_DependencyErrorNamesNoHostPath(t *testing.T) {
	xsys := builtModuleVersion(t, "golang.org/x/sys")
	coord := mustTestCoord(t, "example.com/premod", "v1.0.0")
	files := map[string]string{
		"go.mod": "module example.com/premod\n\ngo 1.17\n\nrequire golang.org/x/sys " + xsys + "\n",
		// golang.org/x/sys/windows builds on windows only, so on any other host
		// go reports "build constraints exclude all Go files in <cache>/…".
		"premod.go": "//go:build !windows\n\npackage premod\n\nimport \"golang.org/x/sys/windows\"\n\n" +
			"// Value is the module's exported entry point.\nfunc Value() uint32 { return windows.INFINITE }\n",
	}
	if runtime.GOOS == "windows" {
		t.Skip("golang.org/x/sys/windows builds here")
	}

	var details []string
	for range 2 {
		cache := copiedModuleCache(t, "golang.org/x/sys", xsys)
		a := staticcha.New("0.1.0", "", slog.Default()).WithRealModcache(cache)
		rec, err := a.Analyse(context.Background(), writeZipToTemp(t, makeZip(t, coord, files)), coord, domain.AnalysisInputs{})
		if err != nil {
			t.Fatalf("Analyse returned error: %v", err)
		}
		if strings.Contains(rec.FailureDetail, cache) {
			t.Errorf("FailureDetail names the module cache %s:\n%s", cache, rec.FailureDetail)
		}
		details = append(details, rec.FailureDetail)
	}
	const lead = "the loader reported: build constraints exclude all Go files in golang.org/x/sys@"
	if !strings.HasPrefix(details[0], lead) {
		t.Errorf("FailureDetail does not lead with the dependency's error, module-cache relative:\n%s", details[0])
	}
	t.Logf("detail: %s", details[0])
	if details[0] != details[1] {
		t.Errorf("two caches, two details:\n%s\n%s", details[0], details[1])
	}
}

// builtModuleVersion is the version of path this repository's own build
// selects; see builtXModVersion.
func builtModuleVersion(t *testing.T, path string) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "go", "list", "-m", "-f", "{{.Version}}", path).Output()
	if err != nil {
		t.Fatalf("reading the %s version this build selects: %v", path, err)
	}
	return strings.TrimSpace(string(out))
}

// copiedModuleCache builds a module cache under a fresh temp directory holding
// one module, copied from the host's cache: the extracted tree and its download
// entries.
func copiedModuleCache(t *testing.T, path, version string) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Fatalf("go env GOMODCACHE: %v", err)
	}
	host := strings.TrimSpace(string(out))
	cache := t.TempDir()
	tree := path + "@" + version
	if err := os.CopyFS(filepath.Join(cache, tree), os.DirFS(filepath.Join(host, tree))); err != nil {
		t.Fatalf("copying %s: %v", tree, err)
	}
	dl := filepath.Join("cache", "download", path, "@v")
	if err := os.MkdirAll(filepath.Join(cache, dl), 0o750); err != nil {
		t.Fatal(err)
	}
	for _, ext := range []string{".info", ".mod", ".zip", ".ziphash"} {
		name := filepath.Join(dl, version+ext)
		data, err := os.ReadFile(filepath.Join(host, name)) //nolint:gosec // a host module-cache file this test copies
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cache, name), data, 0o600); err != nil { /* #nosec G703 -- cache is this test's own temp dir */
			t.Fatal(err)
		}
	}
	return cache
}
