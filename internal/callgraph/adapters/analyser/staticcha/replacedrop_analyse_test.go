package staticcha_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
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
	coord := mustTestCoord(t, "example.com/premod", "v1.0.0")
	files := map[string]string{
		"go.mod": "module example.com/premod\n\ngo 1.17\n\n" +
			"require golang.org/x/mod v0.40.0\n\n" +
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
	coord := mustTestCoord(t, "example.com/premod", "v1.0.0")
	files := map[string]string{
		"go.mod": "module example.com/premod\n\ngo 1.17\n\n" +
			"require golang.org/x/mod v0.39.0\n\n" +
			"replace golang.org/x/mod v0.39.0 => golang.org/x/mod v0.40.0\n",
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
