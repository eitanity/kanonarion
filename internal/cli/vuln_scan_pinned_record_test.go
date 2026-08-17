package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
)

// A scan run is a historical record, so its body must be the records it names.
//
// vuln-scan-show re-resolved each coordinate at this build's pipeline and the
// run's snapshot and rendered whatever the composition ladder ranked first,
// never consulting the content hash the run pinned. Measured on the development
// store: 136 of 4,765 run module rows were served a record their run never
// named, 92 of them measured in another project's target-rooted frame, and 11
// turned a recorded ScanFailed or Unscannable into Clean — a failure the run
// recorded, displayed as nothing wrong, from a measurement of a different
// build, with nothing in the output saying so.

// pinnedFrameFixture is one coordinate measured twice at the generation this
// build serves: once in another project's frame, once in the run's own. The
// other frame's record is seeded FIRST, which is what the fake's
// coordinate-keyed read returns — the substitution this reads against.
func pinnedFrameFixture(t *testing.T, ours, theirs vuldomain.VulnerabilityRecord) (
	*testfakes.FakeQueryScanRuns, *testfakes.FakeQueryVuln,
) {
	t.Helper()
	run, _ := fixtureRunAndRec(t)
	run.PipelineVersion = vulnPipelineVersion
	run.PerModuleResults = map[coordinate.ModuleCoordinate]string{ours.Coordinate: ours.ContentHash}

	ucRuns := testfakes.NewFakeQueryScanRuns()
	ucRuns.AddRun(run)
	ucVuln := testfakes.NewFakeQueryVuln()
	ucVuln.AddRecords(ours.Coordinate, theirs, ours)
	return ucRuns, ucVuln
}

// otherFrameRecord is the same coordinate as ours, measured in another
// project's build and carrying its own advisory, so which record was rendered
// is visible in the output rather than inferred.
func otherFrameRecord(t *testing.T, coord coordinate.ModuleCoordinate) vuldomain.VulnerabilityRecord {
	t.Helper()
	return vuldomain.VulnerabilityRecord{
		Coordinate:       coord,
		Rooting:          vuldomain.TargetRootedAt(mustVulnCoord(t, "example.com/other-project", "v1.0.0")),
		OverallStatus:    vuldomain.StatusAffected,
		CoverageStatus:   vuldomain.CoverageAnalysed,
		FindingsStatus:   vuldomain.FindingsRecordAffected,
		DatabaseSnapshot: fixtureSnap,
		Findings:         []vuldomain.VulnerabilityFinding{{ID: "GO-OTHER-FRAME"}},
		PipelineVersion:  vulnPipelineVersion,
		ContentHash:      "sha256:other-frame",
	}
}

// The frame is part of what the run recorded, so a record measured in another
// project's build is not this run's record at all — with or without a notice
// attached.
func TestScanShow_CrossFrameRecordIsNotSubstituted(t *testing.T) {
	app := mustVulnCoord(t, "example.com/app", "v1.0.0")
	ours := vuldomain.VulnerabilityRecord{
		Coordinate:       app,
		Rooting:          vuldomain.TargetRootedAt(mustVulnCoord(t, "example.com/ours", "v1.0.0")),
		OverallStatus:    vuldomain.StatusAffected,
		CoverageStatus:   vuldomain.CoverageAnalysed,
		FindingsStatus:   vuldomain.FindingsRecordAffected,
		DatabaseSnapshot: fixtureSnap,
		Findings:         []vuldomain.VulnerabilityFinding{{ID: "GO-OUR-FRAME"}},
		PipelineVersion:  vulnPipelineVersion,
		ContentHash:      "sha256:our-frame",
	}
	ucRuns, ucVuln := pinnedFrameFixture(t, ours, otherFrameRecord(t, app))

	out, err := showRun(t, ucRuns, ucVuln, false)
	if err != nil {
		t.Fatalf("the run's own record is served, so nothing is short: %v", err)
	}
	if !strings.Contains(out, "GO-OUR-FRAME") {
		t.Errorf("the record the run pinned was not rendered:\n%s", out)
	}
	if strings.Contains(out, "GO-OTHER-FRAME") {
		t.Errorf("a record measured in another frame was served for this run:\n%s", out)
	}
}

// The same guarantee on the JSON surface, which owes what the text surface owes.
func TestScanShowJSON_CrossFrameRecordIsNotSubstituted(t *testing.T) {
	app := mustVulnCoord(t, "example.com/app", "v1.0.0")
	ours := vuldomain.VulnerabilityRecord{
		Coordinate:       app,
		Rooting:          vuldomain.TargetRootedAt(mustVulnCoord(t, "example.com/ours", "v1.0.0")),
		OverallStatus:    vuldomain.StatusAffected,
		CoverageStatus:   vuldomain.CoverageAnalysed,
		FindingsStatus:   vuldomain.FindingsRecordAffected,
		DatabaseSnapshot: fixtureSnap,
		Findings:         []vuldomain.VulnerabilityFinding{{ID: "GO-OUR-FRAME"}},
		PipelineVersion:  vulnPipelineVersion,
		ContentHash:      "sha256:our-frame",
	}
	ucRuns, ucVuln := pinnedFrameFixture(t, ours, otherFrameRecord(t, app))

	out, err := showRun(t, ucRuns, ucVuln, true)
	if err != nil {
		t.Fatalf("the run's own record is served, so nothing is short: %v", err)
	}
	var got scanShowJSON
	if uerr := json.Unmarshal([]byte(out), &got); uerr != nil {
		t.Fatalf("decoding scan run JSON: %v\n%s", uerr, out)
	}
	if len(got.AffectedModules) != 1 || len(got.AffectedModules[0].Findings) != 1 {
		t.Fatalf("affected modules = %+v, want the pinned record's single finding", got.AffectedModules)
	}
	if id := got.AffectedModules[0].Findings[0].ID; id != "GO-OUR-FRAME" {
		t.Errorf("finding = %q, want the record the run pinned", id)
	}
}

// The direction that must never happen silently: a failure the run recorded,
// displayed as a clean module because a later scan in another frame answered
// the coordinate.
func TestBuildScanAffectedModules_RecordedFailureIsNotRenderedClean(t *testing.T) {
	app := mustVulnCoord(t, "example.com/app", "v1.0.0")
	ours := vuldomain.VulnerabilityRecord{
		Coordinate:       app,
		Rooting:          vuldomain.TargetRootedAt(mustVulnCoord(t, "example.com/ours", "v1.0.0")),
		OverallStatus:    vuldomain.StatusScanFailed,
		CoverageStatus:   vuldomain.CoverageFailedScan,
		FindingsStatus:   vuldomain.FindingsRecordClean,
		DatabaseSnapshot: fixtureSnap,
		ErrorDetail:      "govulncheck exited 1",
		PipelineVersion:  vulnPipelineVersion,
		ContentHash:      "sha256:our-failure",
	}
	clean := otherFrameRecord(t, app)
	clean.OverallStatus = vuldomain.StatusClean
	clean.FindingsStatus = vuldomain.FindingsRecordClean
	clean.Findings = nil

	ucRuns, ucVuln := pinnedFrameFixture(t, ours, clean)
	run, _, err := ucRuns.GetRun(t.Context(), fixtureScanID)
	if err != nil {
		t.Fatalf("reading the fixture run: %v", err)
	}

	summary := buildScanAffectedModules(t.Context(), run, ucVuln, nil)

	if len(summary.affected) != 0 {
		t.Errorf("affected = %+v, want empty: the run recorded a failed scan", summary.affected)
	}
	if len(summary.missing) != 0 || len(summary.superseded) != 0 {
		t.Errorf("the run's own record is held at this generation, so it is neither absent nor superseded: %+v %+v",
			summary.missing, summary.superseded)
	}
	if len(summary.scanFailed) != 1 || summary.scanFailed[0].Coordinate != app.String() {
		t.Fatalf("scan failures = %+v, want the recorded failure named", summary.scanFailed)
	}
	if summary.scanFailed[0].Error != ours.ErrorDetail {
		t.Errorf("error detail = %q, want the run's own record's", summary.scanFailed[0].Error)
	}
}

// Where the pinned record cannot be served, the existing superseded path takes
// it. A record is servable for the coordinate — it is simply not the run's —
// and that is not a licence to render it.
func TestScanShow_PinnedRecordNotServedRoutesToSuperseded(t *testing.T) {
	app := mustVulnCoord(t, "example.com/app", "v1.0.0")
	run, _ := fixtureRunAndRec(t)
	run.PipelineVersion = "v22"
	run.PerModuleResults = map[coordinate.ModuleCoordinate]string{app: "sha256:pinned-at-v22"}

	ucRuns := testfakes.NewFakeQueryScanRuns()
	ucRuns.AddRun(run)
	ucVuln := testfakes.NewFakeQueryVuln()
	// Held and servable at this build's generation, and not the record the run
	// named — the state that used to render as an ordinary verdict.
	ucVuln.AddRecords(app, otherFrameRecord(t, app))
	ucVuln.SetRecordGenerations(app, []vulnports.VulnerabilityRecordGeneration{
		{PipelineVersion: "v22", Records: 1, Findings: 0},
		{PipelineVersion: vulnPipelineVersion, Records: 1, Findings: 1},
	})

	out, err := showRun(t, ucRuns, ucVuln, false)
	if !strings.Contains(out, "Superseded scan records (1)") {
		t.Errorf("the module the run named is not reported through the superseded path:\n%s", out)
	}
	if strings.Contains(out, "GO-OTHER-FRAME") {
		t.Errorf("a record the run never named was rendered as its verdict:\n%s", out)
	}
	code, ok := ExitCodeFromError(err)
	if !ok || code != ExitNotFound {
		t.Fatalf("exit code = %d (carried %v, err %v), want %d", code, ok, err, ExitNotFound)
	}

	// The JSON surface answers with the same body and the same exit code.
	outJSON, errJSON := showRun(t, ucRuns, ucVuln, true)
	var got scanShowJSON
	if uerr := json.Unmarshal([]byte(outJSON), &got); uerr != nil {
		t.Fatalf("decoding scan run JSON: %v\n%s", uerr, outJSON)
	}
	if len(got.SupersededRecords) != 1 || got.SupersededRecords[0].Coordinate != app.String() {
		t.Errorf("superseded records = %+v, want the module the run named", got.SupersededRecords)
	}
	if len(got.AffectedModules) != 0 {
		t.Errorf("affected modules = %+v, want none: no record this run named is served", got.AffectedModules)
	}
	codeJSON, okJSON := ExitCodeFromError(errJSON)
	if !okJSON || codeJSON != code {
		t.Fatalf("json exit code = %d (carried %v), want the text surface's %d", codeJSON, okJSON, code)
	}
}
