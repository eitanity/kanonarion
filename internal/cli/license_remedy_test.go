package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	sbomdomain "github.com/eitanity/kanonarion/internal/sbom/domain"
)

// analyseRootRemedy and its dependency counterpart are the two fixes a missing
// licence record can have. They are spelled here so a test that asserts one is
// named can also assert the OTHER is not: a message that always named the same
// one would pass every "does it name a remedy" check while sending half its
// readers to a command that cannot produce their record.
const (
	analyseRootRemedy = "--analyse-root"
	analyseDepRemedy  = "kanonarion license "
)

// sbomRefusalFor runs the incomplete-licence refusal over a document and
// returns the message the operator is given.
func sbomRefusalFor(t *testing.T, doc string) string {
	t.Helper()
	ctr := &Container{GenerateSBOM: &testfakes.FakeGenerateSBOM{
		Result: sbomdomain.SBOMRecord{ID: "S1", Content: []byte(doc), LicensesIncomplete: true},
	}}
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

	shared := missingLicenceRecordRemedy(root)
	if !strings.Contains(err.Error(), shared) {
		t.Fatalf("license-compat no longer states the shared remedy %q: %s", shared, err.Error())
	}
	msg := sbomRefusalFor(t, `{"metadata":{"component":{"name":"example.com/app","version":"local"}},"components":[]}`)
	if !strings.Contains(msg, shared) {
		t.Errorf("sbom states a different fix for the same missing record: %s", msg)
	}
}
