package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	dirxmod "github.com/eitanity/kanonarion/internal/directive/adapters/parser/xmod"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	sbomdomain "github.com/eitanity/kanonarion/internal/sbom/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// These are the three fixes a missing licence record can have. They are spelled
// here so a test that asserts one is named can also assert the OTHERS are not:
// a message that always named the same one would pass every "does it name a
// remedy" check while sending most of its readers to a command that cannot
// produce their record.
const (
	analyseRootRemedy  = "--analyse-root"
	analyseLocalRemedy = "--analyse-local"
	analyseDepRemedy   = "kanonarion license "
)

// localReplaceProject writes a project whose go.mod replaces one requirement
// with a directory and another with a fork, and returns its go.mod path. The
// two replaces are the pair the branch has to tell apart: only the filesystem
// one names a module 'fetch' can never reach.
func localReplaceProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	goMod := filepath.Join(dir, "go.mod")
	const src = `module example.com/app

go 1.24

require (
	example.com/dep v1.0.0
	example.com/forked v1.2.0
	example.com/local v0.0.0-00010101000000-000000000000
)

replace example.com/local => ./internal/local

replace example.com/forked => example.com/fork v1.2.0
`
	if err := os.WriteFile(goMod, []byte(src), 0o600); err != nil {
		t.Fatalf("writing fixture go.mod: %v", err)
	}
	return goMod
}

// sbomRefusalFor runs the incomplete-licence refusal over a document and
// returns the message the operator is given.
func sbomRefusalFor(t *testing.T, doc string) string {
	t.Helper()
	return sbomRefusalIn(t, &Container{}, doc, "")
}

// sbomRefusalIn is sbomRefusalFor over a caller-built container, so a test can
// give the command a walk to read the build from. The document is still what
// the refusal is composed from.
func sbomRefusalIn(t *testing.T, ctr *Container, doc, walkID string) string {
	t.Helper()
	ctr.GenerateSBOM = &testfakes.FakeGenerateSBOM{
		Result: sbomdomain.SBOMRecord{ID: "S1", WalkID: walkID, Content: []byte(doc), LicensesIncomplete: true},
	}
	var stdout bytes.Buffer
	err := sbomGenerateWith(context.Background(), ctr, "W1",
		sbomFlags{format: "cyclonedx-json", operator: "tester"}, time.Time{}, &stdout, io.Discard)
	assertIncompleteLicenceExit(t, err)
	// The gate is unchanged: the document is still written whole to stdout and
	// the refusal travels on the error, never on the SBOM bytes.
	if stdout.String() != doc {
		t.Errorf("the document must still be written whole to stdout, got: %q", stdout.String())
	}
	return err.Error()
}

// The walk root's own licence is not fetchable, so naming 'kanonarion license'
// for it would send the operator to a command that cannot produce the record.
// The remedy is the walk re-run with --analyse-root.
func TestSBOMUndeterminedRoot_NamesTheAnalyseRootRemedy(t *testing.T) {
	msg := sbomRefusalFor(t, `{"metadata":{"component":{"name":"example.com/app","version":"local"}},"components":[]}`)

	if !strings.Contains(msg, "example.com/app@local (the document's subject)") {
		t.Errorf("the component must still be named: %s", msg)
	}
	if !strings.Contains(msg, analyseRootRemedy) {
		t.Errorf("a missing root licence must name the --analyse-root remedy: %s", msg)
	}
	if strings.Contains(msg, analyseDepRemedy) {
		t.Errorf("the root must not be sent to the per-coordinate analysis, which cannot produce its record: %s", msg)
	}
}

// A dependency's licence IS fetchable and is analysed by coordinate, so it gets
// the other remedy — named with the coordinate the operator has to type.
func TestSBOMUndeterminedDependency_NamesItsOwnAnalysis(t *testing.T) {
	msg := sbomRefusalFor(t, `{"metadata":{"component":{"name":"example.com/app","version":"local",`+
		`"licenses":[{"license":{"id":"MIT"}}]}},`+
		`"components":[{"name":"example.com/dep","version":"v1.0.0"}]}`)

	if !strings.Contains(msg, "example.com/dep@v1.0.0") {
		t.Errorf("the component must still be named: %s", msg)
	}
	if !strings.Contains(msg, "run 'kanonarion license example.com/dep@v1.0.0'") {
		t.Errorf("a missing dependency licence must name its own analysis: %s", msg)
	}
	if strings.Contains(msg, analyseRootRemedy) {
		t.Errorf("a dependency must not be sent to --analyse-root, which analyses the project's own licence: %s", msg)
	}
}

// Both kinds in one document get both remedies, and the dependencies that share
// a remedy are counted rather than restated — they are already named.
func TestSBOMUndeterminedRootAndDependencies_NameBothRemedies(t *testing.T) {
	msg := sbomRefusalFor(t, `{"metadata":{"component":{"name":"example.com/app","version":"local"}},`+
		`"components":[{"name":"example.com/dep","version":"v1.0.0"},`+
		`{"name":"example.com/other","version":"v2.3.4"}]}`)

	for _, want := range []string{
		"3 component(s) with no licence identity",
		analyseRootRemedy,
		"run 'kanonarion license example.com/dep@v1.0.0'",
		"and the same for the other 1 component(s) named",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in: %s", want, msg)
		}
	}
}

// A component whose coordinate the rules refuse is still named; only the remedy
// is withheld, because there is no coordinate to run anything against.
func TestSBOMUndeterminedUnparseableCoordinate_IsStillNamed(t *testing.T) {
	msg := sbomRefusalFor(t, `{"components":[{"name":"example.com/dep","version":""}]}`)

	if !strings.Contains(msg, "example.com/dep@") {
		t.Errorf("the component must still be named: %s", msg)
	}
	if strings.Contains(msg, analyseDepRemedy) || strings.Contains(msg, analyseRootRemedy) {
		t.Errorf("no remedy can be stated for a coordinate nothing can be run against: %s", msg)
	}
}

// One missing record, one fix: 'sbom' and 'license-compat' meet the same gap
// from opposite ends and must not phrase it differently. The assertion is that
// the sentence license-compat prints is the sentence sbom prints, both taken
// from the running commands rather than from a copy of the wording.
func TestMissingLicenceRecordStatesOneFixOnBothSurfaces(t *testing.T) {
	root := coordinatetest.MustNew("example.com/app", "local")

	ctr := containerWithWalk(root, licdomain.ClosureCompatibilityReport{}, licapp.ErrRootLicenceNotAnalysed)
	var out bytes.Buffer
	err := licenseCompatWith(context.Background(), ctr, root, "", "", &out, io.Discard)
	requireExit(t, err, ExitNotFound)

	shared := missingLicenceRecordRemedy(root, licenceRemedyBuild{})
	if !strings.Contains(err.Error(), shared) {
		t.Fatalf("license-compat no longer states the shared remedy %q: %s", shared, err.Error())
	}
	msg := sbomRefusalFor(t, `{"metadata":{"component":{"name":"example.com/app","version":"local"}},"components":[]}`)
	if !strings.Contains(msg, shared) {
		t.Errorf("sbom states a different fix for the same missing record: %s", msg)
	}
}

// The three branches, over one build. The remedy is chosen by where the
// component's source is — the project's own tree, a directory this build
// replaces a module with, or the module proxy — because that is what decides
// which command can produce the record. Naming 'kanonarion license' for a
// locally replaced module is the case that cannot terminate: it sends the
// reader to 'fetch', and there is nothing published for fetch to get.
func TestMissingLicenceRecordRemedy_NamesTheCommandTheComponentCanFollow(t *testing.T) {
	goMod := localReplaceProject(t)
	build := licenceRemedyBuildFor(dirxmod.New(), goMod)

	localTarget := coordinatetest.MustNew("example.com/local", "v0.0.0-00010101000000-000000000000")

	for _, tc := range []struct {
		name   string
		coord  coordinate.ModuleCoordinate
		build  licenceRemedyBuild
		want   string
		absent []string
	}{
		{
			name:   "the walk root is analysed from the project's own tree",
			coord:  coordinatetest.MustNew("example.com/app", "local"),
			build:  build,
			want:   "run 'kanonarion walk --gomod ./go.mod --analyse-root'",
			absent: []string{analyseLocalRemedy, analyseDepRemedy},
		},
		{
			name:   "a locally replaced module is ingested from the path replacing it",
			coord:  localTarget,
			build:  build,
			want:   "run 'kanonarion walk --gomod " + goMod + " --analyse-local'",
			absent: []string{analyseRootRemedy, analyseDepRemedy},
		},
		{
			name:   "a published dependency is analysed by coordinate",
			coord:  coordinatetest.MustNew("example.com/dep", "v1.0.0"),
			build:  build,
			want:   "run 'kanonarion license example.com/dep@v1.0.0'",
			absent: []string{analyseRootRemedy, analyseLocalRemedy},
		},
		{
			// A fork replace resolves to another published module, so the fetch
			// 'license' starts with reaches it. Only local_path marks the target
			// that has no published source.
			name:   "a module replaced by a fork is still fetchable",
			coord:  coordinatetest.MustNew("example.com/forked", "v1.2.0"),
			build:  build,
			want:   "run 'kanonarion license example.com/forked@v1.2.0'",
			absent: []string{analyseRootRemedy, analyseLocalRemedy},
		},
		{
			// The same coordinate, asked without a build. Nothing has been
			// measured, so nothing is inferred: a wrong --analyse-local is the
			// same defect as a wrong 'license', pointed the other way.
			name:   "an unknown build never guesses a local replace",
			coord:  localTarget,
			build:  licenceRemedyBuild{},
			want:   "run 'kanonarion license example.com/local@v0.0.0-00010101000000-000000000000'",
			absent: []string{analyseRootRemedy, analyseLocalRemedy},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := missingLicenceRecordRemedy(tc.coord, tc.build)
			if !strings.Contains(got, tc.want) {
				t.Errorf("remedy for %s must name %q, got: %s", tc.coord, tc.want, got)
			}
			for _, no := range tc.absent {
				if strings.Contains(got, no) {
					t.Errorf("remedy for %s must not name %q, got: %s", tc.coord, no, got)
				}
			}
		})
	}
}

// A go.mod replace a go.work overrides does not shape the build, so its target
// resolves the ordinary way and keeps the ordinary remedy. The applied flag is
// the directive context's answer to that; this asserts the remedy reads it.
func TestMissingLicenceRecordRemedy_IgnoresAnUnappliedLocalReplace(t *testing.T) {
	goMod := localReplaceProject(t)
	const work = `go 1.24

use .

replace example.com/local => example.com/fork v3.0.0
`
	if err := os.WriteFile(filepath.Join(filepath.Dir(goMod), "go.work"), []byte(work), 0o600); err != nil {
		t.Fatalf("writing fixture go.work: %v", err)
	}
	build := licenceRemedyBuildFor(dirxmod.New(), goMod)

	coord := coordinatetest.MustNew("example.com/local", "v0.0.0-00010101000000-000000000000")
	got := missingLicenceRecordRemedy(coord, build)
	if strings.Contains(got, analyseLocalRemedy) {
		t.Errorf("a go.work-overridden local replace does not shape this build: %s", got)
	}
	if !strings.Contains(got, "run 'kanonarion license example.com/local@") {
		t.Errorf("the overridden target keeps the dependency remedy: %s", got)
	}
}

// All three kinds in one document get all three sentences, and the components
// that share a remedy are counted rather than restated. The locally replaced
// ones are covered by the run already named: one --analyse-local walk ingests
// every local-replace target the build has.
func TestMissingLicenceRecordRemedies_StatesEachKindOnce(t *testing.T) {
	goMod := localReplaceProject(t)
	build := licenceRemedyBuildFor(dirxmod.New(), goMod)

	got := missingLicenceRecordRemedies([]coordinate.ModuleCoordinate{
		coordinatetest.MustNew("example.com/app", "local"),
		coordinatetest.MustNew("example.com/local", "v0.0.0-00010101000000-000000000000"),
		coordinatetest.MustNew("example.com/dep", "v1.0.0"),
		coordinatetest.MustNew("example.com/other", "v2.3.4"),
	}, build)

	for _, want := range []string{
		"--analyse-root",
		"--gomod " + goMod + " --analyse-local",
		"run 'kanonarion license example.com/dep@v1.0.0'",
		"and the same for the other 1 component(s) named",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in: %s", want, got)
		}
	}
}

// The branch has to reach the printed message, not just the function: 'sbom'
// reads the build from the walk the document was generated from, so a
// local-replace target in that walk is told to run --analyse-local.
func TestSBOMUndeterminedLocalReplaceTarget_NamesTheAnalyseLocalRemedy(t *testing.T) {
	goMod := localReplaceProject(t)
	walks := testfakes.NewFakeQueryWalks()
	walks.AddWalk(walkdomain.WalkRecord{ID: "W9", ProjectDir: filepath.Dir(goMod)})
	ctr := &Container{QueryWalks: walks, DirectiveParser: dirxmod.New()}

	msg := sbomRefusalIn(t, ctr, `{"metadata":{"component":{"name":"example.com/app","version":"local",`+
		`"licenses":[{"license":{"id":"MIT"}}]}},`+
		`"components":[{"name":"example.com/local","version":"v0.0.0-00010101000000-000000000000"}]}`, "W9")

	if !strings.Contains(msg, "--gomod "+goMod+" --analyse-local") {
		t.Errorf("a local-replace target must be sent to --analyse-local: %s", msg)
	}
	if strings.Contains(msg, analyseDepRemedy) {
		t.Errorf("a local-replace target must not be sent to 'license', which fetches a module that was never published: %s", msg)
	}
}

// The same document over a walk with no project directory. Provenance is not an
// oracle: without a tree to read there is no build, and the message falls back
// to the dependency remedy rather than naming a go.mod nobody measured.
func TestSBOMUndeterminedWithoutAProjectDir_KeepsTheDependencyRemedy(t *testing.T) {
	walks := testfakes.NewFakeQueryWalks()
	walks.AddWalk(walkdomain.WalkRecord{ID: "W9"})
	ctr := &Container{QueryWalks: walks, DirectiveParser: dirxmod.New()}

	msg := sbomRefusalIn(t, ctr, `{"metadata":{"component":{"name":"example.com/app","version":"local",`+
		`"licenses":[{"license":{"id":"MIT"}}]}},`+
		`"components":[{"name":"example.com/local","version":"v0.0.0-00010101000000-000000000000"}]}`, "W9")

	if strings.Contains(msg, analyseLocalRemedy) {
		t.Errorf("a walk with no project directory measured no local replace: %s", msg)
	}
	if !strings.Contains(msg, "run 'kanonarion license example.com/local@") {
		t.Errorf("the unknown build keeps the dependency remedy: %s", msg)
	}
}
