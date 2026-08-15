package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
)

// A pipeline bump leaves records the reads cannot see, and every empty answer
// they produce used to be reported as "never scanned". These exercise the three
// coordinates a store holds after a bump — dark, current, and genuinely absent —
// against each reader, because the failure is not that a message is wrong: it is
// that one message was serving three conditions.

const supersededVulnPipeline = "0.0.1-superseded"

// darkCoord is a coordinate the store holds only at a superseded generation: the
// keyed reads return nothing, the census says why, and the rows themselves are
// still there for the one read that spans generations. The three are seeded
// together because they are one condition — a fixture where the census counts
// rows the store does not hold would let a history listing pass by reporting an
// absence.
func darkCoord(t *testing.T, uc *testfakes.FakeQueryVuln, records, findings int) coordinate.ModuleCoordinate {
	t.Helper()
	coord := coordinatetest.MustNew("example.com/dark", "v1.0.0")
	uc.SetRecordGenerations(coord, []vulnports.VulnerabilityRecordGeneration{
		{PipelineVersion: supersededVulnPipeline, Records: records, Findings: findings},
	})
	uc.AddSupersededRecords(coord, darkRecords(coord, records, findings)...)
	return coord
}

// darkRecords builds the rows the census counts, newest first, spreading the
// findings across them.
func darkRecords(coord coordinate.ModuleCoordinate, records, findings int) []vuldomain.VulnerabilityRecord {
	out := make([]vuldomain.VulnerabilityRecord, 0, records)
	scannedAt := time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC)
	for i := range records {
		n := findings / records
		if i < findings%records {
			n++
		}
		fs := make([]vuldomain.VulnerabilityFinding, 0, n)
		for j := range n {
			fs = append(fs, vuldomain.VulnerabilityFinding{
				ID:          fmt.Sprintf("GO-2026-%04d", i*100+j),
				Summary:     "example vulnerability",
				PublishedAt: scannedAt,
				ModifiedAt:  scannedAt,
			})
		}
		status := vuldomain.StatusClean
		if n > 0 {
			status = vuldomain.StatusAffected
		}
		out = append(out, vuldomain.VulnerabilityRecord{
			Ecosystem:        fetchdomain.EcosystemGo,
			Coordinate:       coord,
			OverallStatus:    status,
			DatabaseSnapshot: fixtureSnap,
			ScannedAt:        scannedAt.Add(-time.Duration(i) * time.Hour),
			PipelineVersion:  supersededVulnPipeline,
			Findings:         fs,
		})
	}
	return out
}

// currentRecord is a coordinate answered normally, at the version this build
// serves. It is the control: a fix that made every answer look superseded would
// fail here and nowhere else.
func currentRecord(t *testing.T, uc *testfakes.FakeQueryVuln) coordinate.ModuleCoordinate {
	t.Helper()
	coord := coordinatetest.MustNew("example.com/current", "v2.0.0")
	scannedAt := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	rec := vuldomain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord,
		OverallStatus:    vuldomain.StatusAffected,
		DatabaseSnapshot: fixtureSnap,
		ScannedAt:        scannedAt,
		PipelineVersion:  vulnPipelineVersion,
		Findings: []vuldomain.VulnerabilityFinding{
			{ID: "GO-2026-0001", Summary: "example vulnerability", PublishedAt: scannedAt, ModifiedAt: scannedAt},
		},
	}
	uc.AddRecord(coord, rec)
	uc.SetRecordGenerations(coord, []vulnports.VulnerabilityRecordGeneration{
		{PipelineVersion: vulnPipelineVersion, Records: 1, Findings: 1},
	})
	return coord
}

func TestVulnShow_SupersededGenerationIsNamedNotReportedAbsent(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()
	coord := darkCoord(t, uc, 16, 252)

	err := runVulnShow(context.Background(), coord.String(), "", "", false, false, false,
		uc, testfakes.NewFakeQueryScanRuns(), testfakes.NewFakeQueryWalks(), nil, io.Discard)
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	msg := err.Error()
	for _, want := range []string{supersededVulnPipeline, "16 record(s)", "252 finding(s)", vulnPipelineVersion, "not a coverage gap"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message does not name %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, "run: kanonarion vuln-scan <walk-id>") {
		t.Errorf("still reporting the bare miss for a coordinate the store holds: %s", msg)
	}
}

// A history is what the store has ever recorded, so a pipeline bump may not
// empty it. Every other read on this coordinate refuses, and refusing is right
// for them: they answer "what holds now". This one answers "what was recorded",
// and the bump that superseded the rows is the moment its reader most needs
// them.
func TestVulnShowHistory_SupersededGenerationIsListedNotRefused(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()
	coord := darkCoord(t, uc, 16, 252)

	var buf bytes.Buffer
	if err := runVulnShowHistory(context.Background(), coord, false, uc, nil, &buf); err != nil {
		t.Fatalf("history refused a coordinate the store holds 16 records for: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "16 scan record(s)") {
		t.Errorf("history did not list the 16 records the census counts:\n%s", out)
	}
	if got := strings.Count(out, "[superseded]"); got != 16 {
		t.Errorf("marked %d of 16 rows superseded:\n%s", got, out)
	}
	if !strings.Contains(out, "pipeline="+supersededVulnPipeline) {
		t.Errorf("history does not name the generation it is standing on:\n%s", out)
	}
	if !strings.Contains(out, "16 of 16 record(s) were produced by superseded scan logic") {
		t.Errorf("no notice sizing the superseded part of the listing:\n%s", out)
	}
}

// The same listing as JSON goes through the same read, so it spans generations
// too — and a machine cannot read the prose marking, so the state is a field.
func TestVulnShowHistoryJSON_MarksSupersededRecords(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()
	coord := darkCoord(t, uc, 3, 3)

	var buf bytes.Buffer
	if err := runVulnShowHistory(context.Background(), coord, true, uc, nil, &buf); err != nil {
		t.Fatalf("history --json refused a coordinate the store holds records for: %v", err)
	}
	var got []struct {
		PipelineVersion string `json:"pipeline_version"`
		Superseded      bool   `json:"superseded"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decoding history JSON: %v\n%s", err, buf.String())
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 records, got %d:\n%s", len(got), buf.String())
	}
	for i, r := range got {
		if r.PipelineVersion != supersededVulnPipeline {
			t.Errorf("record %d: pipeline_version %q", i, r.PipelineVersion)
		}
		if !r.Superseded {
			t.Errorf("record %d: superseded field is false for a superseded record:\n%s", i, buf.String())
		}
	}
}

// A coordinate nobody has scanned still reads as one: nothing at any generation,
// and no supersession to report.
func TestVulnShowHistory_NeverScannedStillReadsAsAbsent(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()
	coord := coordinatetest.MustNew("example.com/never-scanned", "v1.0.0")

	err := runVulnShowHistory(context.Background(), coord, false, uc, nil, io.Discard)
	if err == nil {
		t.Fatal("expected a refusal for a coordinate the store holds nothing for")
	}
	if !strings.Contains(err.Error(), "no vulnerability records") {
		t.Errorf("absence does not read as absence: %v", err)
	}
	if strings.Contains(err.Error(), "superseded") {
		t.Errorf("reports supersession for a coordinate with no records at all: %v", err)
	}
}

func TestReachability_SupersededGenerationIsNotUnscanned(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()
	coord := darkCoord(t, uc, 16, 252)

	err := runVulnReachability(context.Background(), coord.String(), "GO-2024-3321", "", "", false, false,
		uc, testfakes.NewFakeQueryWalks(), nil, io.Discard)
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	msg := err.Error()
	if strings.Contains(msg, "the module has not been vuln-scanned") {
		t.Errorf("claims the module was never scanned when the store holds 16 records: %s", msg)
	}
	if !strings.Contains(msg, supersededVulnPipeline) {
		t.Errorf("message does not name the generation held: %s", msg)
	}
}

// The control: a coordinate with a record at this generation still answers, and
// answers without a word about supersession.
func TestVulnShow_CurrentGenerationAnswersUnchanged(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()
	coord := currentRecord(t, uc)

	var buf bytes.Buffer
	if err := runVulnShow(context.Background(), coord.String(), "", "", false, false, false,
		uc, testfakes.NewFakeQueryScanRuns(), testfakes.NewFakeQueryWalks(), nil, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, coord.String()) || !strings.Contains(out, "Affected") {
		t.Errorf("expected the ordinary record output, got: %q", out)
	}
	if strings.Contains(out, "superseded") {
		t.Errorf("a served record was described as superseded: %q", out)
	}
}

// The other control: a coordinate the store has nothing for, at any generation,
// still says so — plainly, and with the command that fixes it.
func TestVulnShow_GenuineAbsenceStillReportsAbsence(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()
	coord := coordinatetest.MustNew("example.com/never", "v0.1.0")

	err := runVulnShow(context.Background(), coord.String(), "", "", false, false, false,
		uc, testfakes.NewFakeQueryScanRuns(), testfakes.NewFakeQueryWalks(), nil, io.Discard)
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "no vulnerability record for "+coord.String()) {
		t.Errorf("absence is no longer reported plainly: %s", msg)
	}
	if strings.Contains(msg, "superseded") {
		t.Errorf("named a supersession for a coordinate the store holds nothing for: %s", msg)
	}
}

func TestReachability_GenuineAbsenceStillReportsUnscanned(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()
	coord := coordinatetest.MustNew("example.com/never", "v0.1.0")

	err := runVulnReachability(context.Background(), coord.String(), "GO-2024-3321", "", "", false, false,
		uc, testfakes.NewFakeQueryWalks(), nil, io.Discard)
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	if !strings.Contains(err.Error(), "has not been vuln-scanned") {
		t.Errorf("a genuinely unscanned module must still be reported as one: %s", err)
	}
}

// vuln-by-id keeps serving superseded rows — they are the newest evidence the
// store holds — and marks them, so a reader can tell one from a current answer.
func TestVulnByID_MarksSupersededRows(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()
	scannedAt := time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC)
	old := coordinatetest.MustNew("example.com/old", "v1.0.0")
	current := coordinatetest.MustNew("example.com/new", "v1.1.0")
	mk := func(coord coordinate.ModuleCoordinate, pipeline string) vuldomain.VulnerabilityRecord {
		return vuldomain.VulnerabilityRecord{
			Ecosystem:        fetchdomain.EcosystemGo,
			Coordinate:       coord,
			OverallStatus:    vuldomain.StatusAffected,
			DatabaseSnapshot: fixtureSnap,
			ScannedAt:        scannedAt,
			PipelineVersion:  pipeline,
			Findings: []vuldomain.VulnerabilityFinding{
				{ID: "GO-2025-3553", PublishedAt: scannedAt, ModifiedAt: scannedAt},
			},
		}
	}
	uc.SetByID([]vuldomain.VulnerabilityRecord{
		mk(old, supersededVulnPipeline),
		mk(current, vulnPipelineVersion),
	})

	var buf bytes.Buffer
	if err := runVulnByID(context.Background(), "GO-2025-3553", "", false, uc, nil, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, old.String()) || !strings.Contains(out, current.String()) {
		t.Errorf("a row was dropped; both must still be served: %q", out)
	}
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.Contains(line, old.String()):
			if !strings.Contains(line, "pipeline="+supersededVulnPipeline) || !strings.Contains(line, "[superseded]") {
				t.Errorf("superseded row is not marked: %q", line)
			}
		case strings.Contains(line, current.String()):
			if strings.Contains(line, "[superseded]") {
				t.Errorf("current row marked superseded: %q", line)
			}
		}
	}
	if !strings.Contains(out, "1 of 2 row(s) were produced by superseded scan logic") {
		t.Errorf("listing does not state how much of it is superseded: %q", out)
	}
}

func TestVulnByID_AllCurrentRowsCarryNoNotice(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()
	scannedAt := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	coord := coordinatetest.MustNew("example.com/new", "v1.1.0")
	uc.SetByID([]vuldomain.VulnerabilityRecord{{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord,
		OverallStatus:    vuldomain.StatusAffected,
		DatabaseSnapshot: fixtureSnap,
		ScannedAt:        scannedAt,
		PipelineVersion:  vulnPipelineVersion,
		Findings: []vuldomain.VulnerabilityFinding{
			{ID: "GO-2025-3553", PublishedAt: scannedAt, ModifiedAt: scannedAt},
		},
	}})

	var buf bytes.Buffer
	if err := runVulnByID(context.Background(), "GO-2025-3553", "", false, uc, nil, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(buf.String(), "superseded") {
		t.Errorf("a listing of current rows carries a superseded notice: %q", buf.String())
	}
}

func TestBuildVulnerabilities_SupersededIsNotNotRun(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()
	coord := darkCoord(t, uc, 16, 252)

	v := buildVulnerabilitiesFromBatch(context.Background(), coord, uc, &vulnBatchCtx{})

	if v.Status != sectionStatusSuperseded {
		t.Errorf("Status = %q, want %q", v.Status, sectionStatusSuperseded)
	}
	if !strings.Contains(v.Error, supersededVulnPipeline) {
		t.Errorf("section does not name the generation held: %q", v.Error)
	}
}
