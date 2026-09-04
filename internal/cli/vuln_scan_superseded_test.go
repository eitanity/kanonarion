package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
)

// vuln-scan-show showed a run whose records this build does not read as a
// verdict with nothing behind it: "Status: Affected", no module section, the
// word "pipeline" nowhere, and exit 0. A caller branching on the exit status
// alone read that as clean.
//
// Worse than uninformative, the one line it did print was untrue. "No scan
// record ... no record backs it" was printed for coordinates whose records are
// in the store, named by content hash in the run itself, and declined only
// because this build reads a newer generation.
//
// The condition is permanent, not transient. A run stores the record identities
// it was built from, so re-scanning writes new records beside the old ones and
// leaves the run pointing where it pointed. Measured on the development store:
// 51 of 72 runs read this way and always will.

// supersededRunFixture is a run recorded at runPipeline naming one module, with
// no record served at this build's generation. held seeds what the store holds
// for that module, generation by generation.
func supersededRunFixture(t *testing.T, runPipeline string, held []vulnports.VulnerabilityRecordGeneration) (
	*testfakes.FakeQueryScanRuns, *testfakes.FakeQueryVuln, coordinate.ModuleCoordinate,
) {
	t.Helper()
	run, _ := fixtureRunAndRec(t)
	run.PipelineVersion = runPipeline

	ucRuns := testfakes.NewFakeQueryScanRuns()
	ucRuns.AddRun(run)

	// No AddRecord: nothing is served at the generation this build reads, which
	// is the whole condition.
	ucVuln := testfakes.NewFakeQueryVuln()
	app := mustVulnCoord(t, "example.com/app", "v1.0.0")
	if held != nil {
		ucVuln.SetRecordGenerations(app, held)
	}
	return ucRuns, ucVuln, app
}

func showRun(t *testing.T, ucRuns *testfakes.FakeQueryScanRuns, ucVuln *testfakes.FakeQueryVuln, jsonOut bool) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	err := runScanShow(context.Background(), fixtureScanID, jsonOut, ucRuns, ucVuln, nil, nil, &buf, io.Discard)
	return buf.String(), err
}

// The first of the two states the acceptance names: the records are present at
// the generation the run ran under, and this build declines them.
func TestScanShow_SupersededRunNamesBothGenerations(t *testing.T) {
	ucRuns, ucVuln, _ := supersededRunFixture(t, "v22", []vulnports.VulnerabilityRecordGeneration{
		{PipelineVersion: "v22", Records: 3, Findings: 2},
		{PipelineVersion: vulnPipelineVersion, Records: 1, Findings: 0},
	})

	out, err := showRun(t, ucRuns, ucVuln, false)

	// The section, headed by its own name — not "Findings", which no state of
	// this command prints, and against which an acceptance would pass unfixed.
	if !strings.Contains(out, "Superseded scan records (1)") {
		t.Errorf("no superseded section:\n%s", out)
	}
	// Both generations, which is the fact the reader has no other way to reach.
	if !strings.Contains(out, "pipeline v22") {
		t.Errorf("the generation the run recorded is not named:\n%s", out)
	}
	if !strings.Contains(out, "pipeline "+vulnPipelineVersion) {
		t.Errorf("the generation this build reads is not named:\n%s", out)
	}
	// What is behind the gap, counted.
	if !strings.Contains(out, "3 record(s), 2 finding(s)") {
		t.Errorf("the size of the gap is not counted:\n%s", out)
	}
	// The distinction, in as many words, and the fact that makes a run different
	// from a coordinate. The notice wraps, so the sentences are read with the
	// line breaks collapsed — asserting on the unwrapped text pins the column the
	// wrap happens to fall at, which is not the behaviour being tested.
	flat := flattenNote(out)
	if !strings.Contains(flat, "stale cache, not a coverage gap") {
		t.Errorf("a stale cache is not distinguished from a coverage gap:\n%s", out)
	}
	if !strings.Contains(flat, "Re-scanning does not repair this run") {
		t.Errorf("the run's permanence is not stated:\n%s", out)
	}
	if !strings.Contains(flat, "kanonarion vuln-scan "+fixtureWalkID) {
		t.Errorf("no remedy command:\n%s", out)
	}
	// The untrue statement is gone: something does back these modules.
	if strings.Contains(out, "No scan record") {
		t.Errorf("a held-and-declined record is still reported as absent:\n%s", out)
	}
	// And it is not a success.
	code, ok := ExitCodeFromError(err)
	if !ok || code != ExitNotFound {
		t.Fatalf("exit code = %d (carried %v, err %v), want %d", code, ok, err, ExitNotFound)
	}
}

// The second state: the run is at an old generation and the store no longer
// holds the coordinate there either. Nothing backs the verdict, the old wording
// is the true one, and it stays.
func TestScanShow_AbsentRecordKeepsTheCoverageGapWording(t *testing.T) {
	ucRuns, ucVuln, _ := supersededRunFixture(t, "v22", []vulnports.VulnerabilityRecordGeneration{
		{PipelineVersion: "v19", Records: 1, Findings: 0},
	})

	out, err := showRun(t, ucRuns, ucVuln, false)

	if !strings.Contains(out, "No scan record (1)") {
		t.Errorf("the coverage gap lost its section:\n%s", out)
	}
	if strings.Contains(out, "Superseded scan records") {
		t.Errorf("a coordinate the store does not hold at the run's generation is not a superseded record:\n%s", out)
	}
	if code, ok := ExitCodeFromError(err); !ok || code != ExitNotFound {
		t.Fatalf("exit code = %d (carried %v, err %v), want %d", code, ok, err, ExitNotFound)
	}
}

// The control the acceptance names, and the one that must be able to fail: a run
// at this build's own generation, every module served, is untouched and exits 0.
func TestScanShow_CurrentRunUnchanged(t *testing.T) {
	run, rec := fixtureRunAndRec(t)
	run.PipelineVersion = vulnPipelineVersion
	ucRuns := testfakes.NewFakeQueryScanRuns()
	ucRuns.AddRun(run)
	ucVuln := testfakes.NewFakeQueryVuln()
	ucVuln.AddRecord(mustVulnCoord(t, "example.com/app", "v1.0.0"), rec)

	out, err := showRun(t, ucRuns, ucVuln, false)
	if err != nil {
		t.Fatalf("runScanShow() = %v, want nil for a run this build serves in full", err)
	}
	if strings.Contains(out, "Superseded") || strings.Contains(out, "No scan record") {
		t.Errorf("a fully served run gained a caveat:\n%s", out)
	}
	// The control has to be able to fail: the section it must not contain is only
	// meaningful if the section it must contain is there.
	if !strings.Contains(out, "Affected modules (1)") {
		t.Errorf("the control lost its findings section, so its silence proves nothing:\n%s", out)
	}
}

// A run can be at a superseded generation and still render in full, when the
// coordinates it names have since been re-scanned against the same snapshot.
// Nothing is declined, so nothing is caveated and the exit code stays 0 — the
// gate is on what could not be served, never on the run's age.
func TestScanShow_SupersededRunThatStillRendersExitsZero(t *testing.T) {
	run, rec := fixtureRunAndRec(t)
	run.PipelineVersion = "v19"
	ucRuns := testfakes.NewFakeQueryScanRuns()
	ucRuns.AddRun(run)
	ucVuln := testfakes.NewFakeQueryVuln()
	ucVuln.AddRecord(mustVulnCoord(t, "example.com/app", "v1.0.0"), rec)

	out, err := showRun(t, ucRuns, ucVuln, false)
	if err != nil {
		t.Fatalf("runScanShow() = %v, want nil when every module the run names is served", err)
	}
	if strings.Contains(out, "Superseded scan records") {
		t.Errorf("a run that rendered in full was caveated anyway:\n%s", out)
	}
}

// --json owes the same facts as fields. An agent branching on the exit status
// cannot read the prose, and the prose is where all of this lived.
func TestScanShow_JSONCarriesTheGenerationsAsFields(t *testing.T) {
	ucRuns, ucVuln, _ := supersededRunFixture(t, "v22", []vulnports.VulnerabilityRecordGeneration{
		{PipelineVersion: "v22", Records: 3, Findings: 2},
	})

	out, err := showRun(t, ucRuns, ucVuln, true)
	if code, ok := ExitCodeFromError(err); !ok || code != ExitNotFound {
		t.Fatalf("--json exit code = %d (carried %v, err %v), want %d — the two surfaces answer one question",
			code, ok, err, ExitNotFound)
	}

	var got scanShowJSON
	if derr := json.Unmarshal([]byte(out), &got); derr != nil {
		t.Fatalf("decoding --json: %v\n%s", derr, out)
	}
	if !got.Superseded {
		t.Errorf("superseded = false, want true for a run recorded at v22")
	}
	if got.PipelineVersion != "v22" {
		t.Errorf("pipeline_version = %q, want the run's own v22", got.PipelineVersion)
	}
	if got.ReadsPipelineVersion != vulnPipelineVersion {
		t.Errorf("reads_pipeline_version = %q, want %q", got.ReadsPipelineVersion, vulnPipelineVersion)
	}
	if len(got.SupersededRecords) != 1 {
		t.Fatalf("superseded_records = %+v, want one entry", got.SupersededRecords)
	}
	rec := got.SupersededRecords[0]
	if rec.Coordinate != "example.com/app@v1.0.0" || rec.PipelineVersion != "v22" || rec.Records != 3 || rec.Findings != 2 {
		t.Errorf("superseded_records[0] = %+v, want the coordinate with its held counts", rec)
	}
	if len(got.MissingRecords) != 0 {
		t.Errorf("missing_records = %v, want empty — a held record is not an absent one", got.MissingRecords)
	}
}

// The derived field is emitted on every run, false included: absent is
// indistinguishable from a producer that does not derive it.
func TestScanShow_JSONEmitsSupersededFalse(t *testing.T) {
	run, rec := fixtureRunAndRec(t)
	run.PipelineVersion = vulnPipelineVersion
	ucRuns := testfakes.NewFakeQueryScanRuns()
	ucRuns.AddRun(run)
	ucVuln := testfakes.NewFakeQueryVuln()
	ucVuln.AddRecord(mustVulnCoord(t, "example.com/app", "v1.0.0"), rec)

	out, err := showRun(t, ucRuns, ucVuln, true)
	if err != nil {
		t.Fatalf("runScanShow(--json) = %v, want nil", err)
	}
	if !strings.Contains(out, `"superseded": false`) {
		t.Errorf("superseded is not emitted false:\n%s", out)
	}
	if !strings.Contains(out, `"reads_pipeline_version": "`+vulnPipelineVersion+`"`) {
		t.Errorf("reads_pipeline_version is not emitted:\n%s", out)
	}
}

// One condition, one description. vuln-show's coordinate refusal and this run's
// notice are the same fact about the same store, and two renderers that can
// drift apart is the defect, not the wording.
func TestSupersededCause_SharedBetweenTheCoordinateAndTheRun(t *testing.T) {
	coord := mustVulnCoord(t, "example.com/app", "v1.0.0")
	gens := []vulnports.VulnerabilityRecordGeneration{{PipelineVersion: "v22", Records: 3, Findings: 2}}

	coordLine := supersededVulnLine(coord, gens, remedyRescanSuperseded("Re-scan it", coord, true, nil))
	runNote := supersededRunNote(
		[]supersededRunRecord{{Coordinate: coord.String(), PipelineVersion: "v22", Records: 3, Findings: 2}},
		1, "v22", fixtureWalkID)

	// The shared clause, taken from the one function both compose from rather
	// than retyped here, so this test cannot pass a copy that has drifted.
	shared := "A superseded record is not served, so this answer is empty for want of a scan at this generation"
	if !strings.Contains(supersededVulnCause("x", "they have"), shared) {
		t.Fatalf("the shared clause is not in supersededVulnCause; this test is checking the wrong thing")
	}
	if !strings.Contains(coordLine, shared) {
		t.Errorf("the coordinate refusal no longer carries the shared cause:\n%s", coordLine)
	}
	// The run's note wraps, so the clause is compared with its line breaks and
	// indentation collapsed.
	if !strings.Contains(flattenNote(runNote), shared) {
		t.Errorf("the run notice no longer carries the shared cause:\n%s", runNote)
	}
}

// flattenNote collapses a wrapped notice onto one line so a sentence spanning
// two of them can be compared as the sentence it is.
func flattenNote(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// A run whose walk is gone gets the statement without a command naming an id
// that resolves to nothing.
func TestScanShow_SupersededNoteOmitsTheCommandWhenTheWalkIsGone(t *testing.T) {
	note := supersededRunNote(
		[]supersededRunRecord{{Coordinate: "example.com/app@v1.0.0", PipelineVersion: "v22", Records: 1, Findings: 0}},
		1, "v22", "")
	if strings.Contains(note, "kanonarion vuln-scan") {
		t.Errorf("a remedy was offered against a walk the store no longer holds:\n%s", note)
	}
	if !strings.Contains(flattenNote(note), "stale cache, not a coverage gap") {
		t.Errorf("the explanation was dropped along with the command:\n%s", note)
	}
}

// The sections the acceptance says must not move.
func TestScanShow_WithdrawnSectionAndModuleCountSurvive(t *testing.T) {
	run, rec := fixtureRunAndRec(t)
	run.PipelineVersion = "v22"
	app := mustVulnCoord(t, "example.com/app", "v1.0.0")
	other := mustVulnCoord(t, "example.com/other", "v2.0.0")
	run.PerModuleResults[other] = "sha256:other"

	withdrawn := rec
	withdrawn.Coordinate = other
	// The hash the run pins for this module, because that is what the report reads.
	withdrawn.ContentHash = "sha256:other"
	withdrawn.OverallStatus = vuldomain.StatusAffected
	f := withdrawn.Findings[0]
	f.WithdrawnAt = f.PublishedAt
	withdrawn.Findings = []vuldomain.VulnerabilityFinding{f}

	ucRuns := testfakes.NewFakeQueryScanRuns()
	ucRuns.AddRun(run)
	ucVuln := testfakes.NewFakeQueryVuln()
	ucVuln.AddRecord(other, withdrawn)
	ucVuln.SetRecordGenerations(app, []vulnports.VulnerabilityRecordGeneration{
		{PipelineVersion: "v22", Records: 1, Findings: 0},
	})

	out, _ := showRun(t, ucRuns, ucVuln, false)
	if !strings.Contains(out, "Modules:     2") {
		t.Errorf("the module count moved:\n%s", out)
	}
	if !strings.Contains(out, "Withdrawn advisories, not counted as findings (1)") {
		t.Errorf("the withdrawn section moved:\n%s", out)
	}
	if !strings.Contains(out, "Superseded scan records (1)") {
		t.Errorf("the superseded section is missing beside them:\n%s", out)
	}
}
