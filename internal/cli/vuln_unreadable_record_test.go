package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
)

// One stored record this build cannot verify used to take out the whole answer:
// `vuln-by-id` over an advisory touching four modules reported none of them, and
// a coordinate's history vanished for the one row that had drifted. These tests
// pin all three parts of the replacement — the readable records are served, the
// unreadable one is named in place, and the command exits 0 — plus the
// fail-closed direction for the read that composes a single verdict.

// driftedRecords is the error a record listing returns for a row sealed by a
// generation this build no longer produces. The identity is bare and the
// generation rides beside it, which is the shape the store hands over.
func driftedRecords(coord string) error {
	return &vulnports.UnreadableRows{Rows: []vulnports.UnreadableRow{{
		Kind: vulnports.RowKindRecord,
		ID:   coord,
		Generation: vulnports.RowGeneration{
			PipelineVersion: "v25",
			SnapshotSource:  "govulndb",
			SnapshotVersion: "v2026-01-01",
		},
		Reason: fmt.Errorf("%w: content hash mismatch: stored %q, computed %q",
			recordseal.ErrGenerationDrift, "00c9783d", "0498eace"),
	}}}
}

func unreadableTestRecord(t *testing.T, path, version string) vuldomain.VulnerabilityRecord {
	t.Helper()
	scannedAt := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	return vuldomain.VulnerabilityRecord{
		Coordinate:       mustVulnCoord(t, path, version),
		WalkID:           fixtureWalkID,
		OverallStatus:    vuldomain.StatusAffected,
		DatabaseSnapshot: fixtureSnap,
		Findings: []vuldomain.VulnerabilityFinding{
			{ID: "GO-2025-0001", Summary: "example vulnerability", PublishedAt: scannedAt, ModifiedAt: scannedAt},
		},
		ScannedAt:       scannedAt,
		PipelineVersion: vulnPipelineVersion,
	}
}

func TestRunVulnByID_ServesReadableRecordsAndNamesTheUnreadable(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()
	uc.SetByID([]vuldomain.VulnerabilityRecord{
		unreadableTestRecord(t, "example.com/alpha", "v1.0.0"),
		unreadableTestRecord(t, "example.com/charlie", "v3.0.0"),
	})
	uc.PartialErr = driftedRecords("example.com/bravo@v2.0.0")

	var out bytes.Buffer
	if err := runVulnByID(context.Background(), "GO-2025-0001", "", false, uc, nil, &out); err != nil {
		t.Fatalf("runVulnByID() = %v, want nil — a survey reports the fault and exits 0", err)
	}

	got := out.String()
	// The records that verify are still served. Losing them is the defect.
	for _, coord := range []string{"example.com/alpha@v1.0.0", "example.com/charlie@v3.0.0"} {
		if !strings.Contains(got, coord) {
			t.Errorf("output does not list %s; one bad row must not withhold the good ones:\n%s", coord, got)
		}
	}
	// The bad row is named. Omitting it silently is the other wrong answer. In
	// text the generation is composed into the label, which is what tells one row
	// of a coordinate's history from another when prose is all there is.
	if !strings.Contains(got, "example.com/bravo@v2.0.0 (pipeline v25, vuln-db v2026-01-01)") {
		t.Errorf("output does not name the unreadable record and its generation:\n%s", got)
	}
	if !strings.Contains(got, statusUnreadable) {
		t.Errorf("output does not mark the row unreadable:\n%s", got)
	}
	// Drift is not tampering, and the wording must not let a reader conclude it was.
	if !strings.Contains(got, "sealed by an earlier record generation; re-scan to reseal") {
		t.Errorf("output does not report the row as generation drift:\n%s", got)
	}
}

// The JSON surface is where a partial answer is most dangerous: nothing there
// tells a consumer to look, so the unreadable row joins the same array the
// records are in, carrying the status key a filter already reads.
func TestRunVulnByID_JSONCarriesTheUnreadableRecord(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()
	uc.SetByID([]vuldomain.VulnerabilityRecord{unreadableTestRecord(t, "example.com/alpha", "v1.0.0")})
	uc.PartialErr = driftedRecords("example.com/bravo@v2.0.0")

	var out bytes.Buffer
	if err := runVulnByID(context.Background(), "GO-2025-0001", "", true, uc, nil, &out); err != nil {
		t.Fatalf("runVulnByID(--json) = %v, want nil", err)
	}

	var rows []map[string]any
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("decoding %q: %v", out.String(), err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want the record and the unreadable row", len(rows))
	}
	last := rows[len(rows)-1]
	if last["overall_status"] != statusUnreadable {
		t.Errorf("overall_status = %v, want %q — a consumer filtering on status must see the row",
			last["overall_status"], statusUnreadable)
	}
	// The identity is a FIELD, under the key its readable siblings use. A
	// consumer must not have to regex a coordinate out of a display string, and
	// the key it reaches for must not be absent.
	if last["coordinate"] != "example.com/bravo@v2.0.0" {
		t.Errorf("coordinate = %v, want the bare coordinate under the sibling key", last["coordinate"])
	}
	if last["pipeline_version"] != "v25" {
		t.Errorf("pipeline_version = %v, want the generation beside the coordinate", last["pipeline_version"])
	}
	snapshot, _ := last["database_snapshot"].(map[string]any)
	if snapshot["version"] != "v2026-01-01" || snapshot["source"] != "govulndb" {
		t.Errorf("database_snapshot = %v, want the snapshot the head named", last["database_snapshot"])
	}
	if reason, _ := last["reason"].(string); reason == "" {
		t.Error("the unreadable row carries no reason; a consumer cannot act on a bare flag")
	}

	// Every key on the row is one a readable record also states, or the reason.
	// A key of its own would be a second vocabulary for a coordinate.
	readable := rows[0]
	for k := range last {
		if k == "reason" {
			continue
		}
		if _, shared := readable[k]; !shared {
			t.Errorf("the unreadable row carries %q, which no readable record states", k)
		}
	}
}

// Bytes that will not say which module they are get no coordinate rather than a
// guessed one — and are still reported.
func TestRunVulnByID_JSONReportsARowThatNamesNoCoordinate(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()
	uc.PartialErr = &vulnports.UnreadableRows{Rows: []vulnports.UnreadableRow{{
		Kind:   vulnports.RowKindRecord,
		Reason: errors.New("unmarshalling vulnerability record: unexpected end of JSON input"),
	}}}

	var out bytes.Buffer
	if err := runVulnByID(context.Background(), "GO-2025-0001", "", true, uc, nil, &out); err != nil {
		t.Fatalf("runVulnByID(--json) = %v, want nil", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("decoding %q: %v", out.String(), err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want the unidentified row reported rather than dropped", len(rows))
	}
	if _, present := rows[0]["coordinate"]; present {
		t.Errorf("a row that named no coordinate carries one anyway: %v", rows[0])
	}
	if rows[0]["overall_status"] != statusUnreadable {
		t.Errorf("overall_status = %v, want %q", rows[0]["overall_status"], statusUnreadable)
	}

	// The text surface still says there is a row, in prose, with a stand-in.
	var text bytes.Buffer
	if err := runVulnByID(context.Background(), "GO-2025-0001", "", false, uc, nil, &text); err != nil {
		t.Fatalf("runVulnByID() = %v, want nil", err)
	}
	if !strings.Contains(text.String(), "(unidentified record)") {
		t.Errorf("the text listing does not report the unidentified row:\n%s", text.String())
	}
}

// An advisory whose every record is unreadable must not print the all-clear.
// "No modules affected" over a store that could not be wholly read is an
// absence asserted over a population that was never enumerated.
func TestRunVulnByID_WithholdsTheAllClearWhenNothingCouldBeRead(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()
	uc.PartialErr = driftedRecords("example.com/bravo@v2.0.0")

	var out bytes.Buffer
	if err := runVulnByID(context.Background(), "GO-2025-0001", "", false, uc, nil, &out); err != nil {
		t.Fatalf("runVulnByID() = %v, want nil", err)
	}
	if strings.Contains(out.String(), "no modules affected") {
		t.Errorf("an all-clear was printed over a store that could not be read:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "example.com/bravo@v2.0.0") {
		t.Errorf("the unreadable record was not named:\n%s", out.String())
	}
}

func TestRunVulnShowHistory_ListsReadableRowsAndNamesTheUnreadable(t *testing.T) {
	coord := mustVulnCoord(t, "example.com/bravo", "v2.0.0")
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecord(coord, unreadableTestRecord(t, "example.com/bravo", "v2.0.0"))
	uc.PartialErr = driftedRecords("example.com/bravo@v2.0.0")

	var out bytes.Buffer
	if err := runVulnShowHistory(context.Background(), coord, false, uc, nil, nil, &out); err != nil {
		t.Fatalf("runVulnShowHistory() = %v, want nil — this is the command an operator diagnoses with", err)
	}
	got := out.String()
	if !strings.Contains(got, statusUnreadable) {
		t.Errorf("the history does not mark the unreadable row:\n%s", got)
	}
	// The header counts what it could read AND what it could not, so a reader
	// does not take the count for the coordinate's whole history.
	if !strings.Contains(got, "1 this build cannot verify") {
		t.Errorf("the header does not say how much could not be read:\n%s", got)
	}
}

func TestRunVulnShowHistory_JSONCarriesTheUnreadableRow(t *testing.T) {
	coord := mustVulnCoord(t, "example.com/bravo", "v2.0.0")
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecord(coord, unreadableTestRecord(t, "example.com/bravo", "v2.0.0"))
	uc.PartialErr = driftedRecords("example.com/bravo@v2.0.0")

	var out bytes.Buffer
	if err := runVulnShowHistory(context.Background(), coord, true, uc, nil, nil, &out); err != nil {
		t.Fatalf("runVulnShowHistory(--json) = %v, want nil", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("decoding %q: %v", out.String(), err)
	}
	if len(rows) != 2 || rows[len(rows)-1]["overall_status"] != statusUnreadable {
		t.Fatalf("rows = %v, want the record and the unreadable row", rows)
	}
	// The history's unreadable row is structured exactly as vuln-by-id's: both
	// surfaces go through one projection, so neither can drift from the other.
	last := rows[len(rows)-1]
	if last["coordinate"] != "example.com/bravo@v2.0.0" || last["pipeline_version"] != "v25" {
		t.Errorf("the history's unreadable row is not structured like its siblings: %v", last)
	}
}

// The other half of the contract: a command that serves ONE verdict keeps
// failing closed, because a verdict selected from a set with a row missing can
// be a Clean standing where a finding was. What it gains is the survey that
// does list the row.
func TestRunVulnShow_FailsClosedAndNamesTheHistory(t *testing.T) {
	coord := mustVulnCoord(t, "example.com/bravo", "v2.0.0")
	uc := testfakes.NewFakeQueryVuln()
	uc.PartialErr = driftedRecords("example.com/bravo@v2.0.0")

	err := runVulnShow(context.Background(), coord.String(), "", "", buildTargetFlags{}, false, false, false,
		uc, nil, nil, nil, nil, io.Discard)
	if err == nil {
		t.Fatal("runVulnShow() = nil; a single-verdict read over a partly unreadable ledger must refuse")
	}
	if !errors.Is(err, vulnports.ErrVulnIntegrity) {
		t.Errorf("errors.Is(err, ErrVulnIntegrity) = false for %v; the exit code would stop being 10", err)
	}
	if !strings.Contains(err.Error(), "--history") {
		t.Errorf("the refusal names no next command:\n%v", err)
	}
}

// A clean store is untouched by any of this: the same records, no extra rows,
// and no error.
func TestRecordSurveys_CleanStoreIsUnchanged(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()
	uc.SetByID([]vuldomain.VulnerabilityRecord{unreadableTestRecord(t, "example.com/alpha", "v1.0.0")})

	var out bytes.Buffer
	if err := runVulnByID(context.Background(), "GO-2025-0001", "", true, uc, nil, &out); err != nil {
		t.Fatalf("runVulnByID(--json) = %v, want nil", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("decoding %q: %v", out.String(), err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want only the one record", len(rows))
	}
	if _, present := rows[0]["reason"]; present {
		t.Error("a clean store's record carries an unreadable-row key")
	}
}
