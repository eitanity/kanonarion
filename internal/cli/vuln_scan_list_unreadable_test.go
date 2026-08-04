package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// vuln-scan-list is the command an operator reaches for to find a bad row, so a
// bad row must not be what stops it running. These tests pin all three parts of
// that: the readable runs are listed, the unreadable one is named in place, and
// the command exits 0 — a clean list that quietly omitted the row would pass a
// weaker assertion while telling the reader something untrue about the store.

func listableRun(id, walkID string) vulndomain.WalkScanRun {
	return vulndomain.WalkScanRun{
		ID:            id,
		WalkID:        walkID,
		OverallStatus: vulndomain.WalkStatusAllClean,
		Snapshot:      vulntest.MustNewAt("govulndb", "v2024-01-01", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
		CompletedAt:   time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
	}
}

// driftedRuns is the error the store returns for a row sealed by a generation
// this build no longer produces.
func driftedRuns(id string) error {
	return &vulnports.UnreadableRuns{Runs: []vulnports.UnreadableRun{{
		ID: id,
		Reason: fmt.Errorf("%w: content hash mismatch: stored %q, computed %q",
			recordseal.ErrGenerationDrift, "e4bb5481", "aa1aeac1"),
	}}}
}

func TestRunScanList_ListsReadableRunsAndNamesTheUnreadable(t *testing.T) {
	fake := testfakes.NewFakeQueryScanRuns()
	fake.AddRun(listableRun("vscan-good-1", "walk-1"))
	fake.AddRun(listableRun("vscan-good-2", "walk-1"))
	fake.ListErr = driftedRuns("vscan-bad")

	var out bytes.Buffer
	if err := runScanList(t.Context(), "", 0, fake, &out, io.Discard); err != nil {
		t.Fatalf("runScanList() = %v, want nil — a survey command reports the fault and exits 0", err)
	}

	got := out.String()
	// Every readable row is still listed. Losing them is the defect.
	for _, id := range []string{"vscan-good-1", "vscan-good-2"} {
		if !strings.Contains(got, id) {
			t.Errorf("output does not list %s; one bad row must not withhold the good ones:\n%s", id, got)
		}
	}
	// The bad row is named. Omitting it silently is the other wrong answer.
	if !strings.Contains(got, "vscan-bad") {
		t.Errorf("output does not name the unreadable run:\n%s", got)
	}
	if !strings.Contains(got, scanRunStatusUnreadable) {
		t.Errorf("output does not mark the row unreadable:\n%s", got)
	}
	// Drift is not tampering, and the wording must not let a reader conclude it
	// was.
	if !strings.Contains(got, "sealed by an earlier record generation; re-scan to reseal") {
		t.Errorf("output does not report the row as generation drift:\n%s", got)
	}
}

func TestRunScanList_JSONCarriesTheUnreadableRow(t *testing.T) {
	fake := testfakes.NewFakeQueryScanRuns()
	fake.AddRun(listableRun("vscan-good-1", "walk-1"))
	fake.ListErr = driftedRuns("vscan-bad")

	prev := jsonOut
	jsonOut = true
	t.Cleanup(func() { jsonOut = prev })

	var out bytes.Buffer
	if err := runScanList(t.Context(), "", 0, fake, &out, io.Discard); err != nil {
		t.Fatalf("runScanList(--json) = %v, want nil", err)
	}

	var entries []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(out.Bytes(), &entries); err != nil {
		t.Fatalf("decoding JSON output: %v\n%s", err, out.String())
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %+v, want the readable run and the unreadable one", entries)
	}
	last := entries[1]
	if last.ID != "vscan-bad" || last.Status != scanRunStatusUnreadable || last.Reason == "" {
		t.Errorf("unreadable entry = %+v, want it named, marked unreadable and given a reason", last)
	}
}

// TestRunScanList_NeutralWordingWhenDriftCannotBeShown pins the judgement the
// ticket leaves open: where the read site cannot establish that a row is merely
// old, it says the row could not be verified and claims nothing about how it
// got that way.
func TestRunScanList_NeutralWordingWhenDriftCannotBeShown(t *testing.T) {
	fake := testfakes.NewFakeQueryScanRuns()
	fake.AddRun(listableRun("vscan-good-1", "walk-1"))
	fake.ListErr = &vulnports.UnreadableRuns{Runs: []vulnports.UnreadableRun{{
		ID:     "vscan-bad",
		Reason: errors.New(`content hash mismatch: stored "e4bb5481", computed "aa1aeac1"`),
	}}}

	var out bytes.Buffer
	if err := runScanList(t.Context(), "", 0, fake, &out, io.Discard); err != nil {
		t.Fatalf("runScanList() = %v, want nil", err)
	}
	got := out.String()
	if !strings.Contains(got, "could not be verified") {
		t.Errorf("output does not use the neutral wording:\n%s", got)
	}
	if strings.Contains(got, "sealed by an earlier record generation") {
		t.Errorf("output claims generation drift it cannot show:\n%s", got)
	}
}

// TestRunScanList_CleanStoreIsUnchanged is the negative direction: with no
// faults the command prints exactly what it always printed.
func TestRunScanList_CleanStoreIsUnchanged(t *testing.T) {
	fake := testfakes.NewFakeQueryScanRuns()
	fake.AddRun(listableRun("vscan-good-1", "walk-1"))

	var out bytes.Buffer
	if err := runScanList(t.Context(), "", 0, fake, &out, io.Discard); err != nil {
		t.Fatalf("runScanList() = %v, want nil", err)
	}
	got := out.String()
	if strings.Contains(got, scanRunStatusUnreadable) {
		t.Errorf("a clean store reported an unreadable row:\n%s", got)
	}
	if lines := strings.Count(strings.TrimSpace(got), "\n") + 1; lines != 1 {
		t.Errorf("output has %d lines, want just the one run:\n%s", lines, got)
	}
}

// TestRunScanList_OtherErrorsStillAbort keeps the softening narrow. A listing
// that failed for any other reason knows nothing about what it skipped, so
// there is no honest partial answer and the command must still fail.
func TestRunScanList_OtherErrorsStillAbort(t *testing.T) {
	fake := testfakes.NewFakeQueryScanRuns()
	fake.AddRun(listableRun("vscan-good-1", "walk-1"))
	fake.ListErr = errors.New("database is locked")

	var out bytes.Buffer
	if err := runScanList(t.Context(), "", 0, fake, &out, io.Discard); err == nil {
		t.Fatalf("runScanList() = nil, want the database failure to abort the listing:\n%s", out.String())
	}
}

// TestRunScanHistory_ReportsUnreadableRows covers the other survey on the same
// store seam, so a fix that reached one listing and not the other would fail
// here.
func TestRunScanHistory_ReportsUnreadableRows(t *testing.T) {
	fake := testfakes.NewFakeQueryScanRuns()
	fake.AddRun(listableRun("vscan-good-1", "walk-1"))
	fake.ListErr = driftedRuns("vscan-bad")

	var out bytes.Buffer
	if err := runScanHistory(t.Context(), "walk-1", false, fake, &out); err != nil {
		t.Fatalf("runScanHistory() = %v, want nil", err)
	}
	got := out.String()
	if !strings.Contains(got, "vscan-good-1") || !strings.Contains(got, "vscan-bad") {
		t.Errorf("history did not report both the readable and the unreadable run:\n%s", got)
	}
}

// TestRunScanShow_ReportsTheUnreadableRunItWasAskedFor closes the loop the
// listing opens. vuln-scan-list names a row it could not verify; this is the
// command an operator runs next against that name, and it must discuss the row
// rather than refuse it.
func TestRunScanShow_ReportsTheUnreadableRunItWasAskedFor(t *testing.T) {
	fake := testfakes.NewFakeQueryScanRuns()
	fake.GetErr = driftedRuns("vscan-bad")

	var out bytes.Buffer
	if err := runScanShow(t.Context(), "vscan-bad", false, fake, nil, &out); err != nil {
		t.Fatalf("runScanShow() = %v, want nil — an inspection command names the fault and exits 0", err)
	}
	got := out.String()
	if !strings.Contains(got, "vscan-bad") {
		t.Errorf("output does not name the run asked for:\n%s", got)
	}
	if !strings.Contains(got, scanRunStatusUnreadable) {
		t.Errorf("output does not mark the run unreadable:\n%s", got)
	}
	if !strings.Contains(got, "sealed by an earlier record generation; re-scan to reseal") {
		t.Errorf("output does not give the reason:\n%s", got)
	}
}

// TestRunScanShow_JSONNamesTheRun covers the machine channel on the same path.
func TestRunScanShow_JSONNamesTheRun(t *testing.T) {
	fake := testfakes.NewFakeQueryScanRuns()
	fake.GetErr = driftedRuns("")

	var out bytes.Buffer
	if err := runScanShow(t.Context(), "vscan-bad", true, fake, nil, &out); err != nil {
		t.Fatalf("runScanShow(--json) = %v, want nil", err)
	}
	var got struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decoding JSON: %v\n%s", err, out.String())
	}
	// The stored bytes named no run; the id the caller typed is still reported,
	// because it is the only identity in the exchange.
	if got.ID != "vscan-bad" || got.Status != scanRunStatusUnreadable || got.Reason == "" {
		t.Errorf("got %+v, want the asked-for id marked unreadable with a reason", got)
	}
}

// TestRunScanShow_OtherFailuresStillAbort keeps the softening narrow: only the
// unreadable-row failure is answerable, and absence is still absence.
func TestRunScanShow_OtherFailuresStillAbort(t *testing.T) {
	t.Run("read failure", func(t *testing.T) {
		fake := testfakes.NewFakeQueryScanRuns()
		fake.GetErr = errors.New("database is locked")
		var out bytes.Buffer
		if err := runScanShow(t.Context(), "vscan-x", false, fake, nil, &out); err == nil {
			t.Errorf("runScanShow() = nil, want the database failure to abort")
		}
	})
	t.Run("not found", func(t *testing.T) {
		fake := testfakes.NewFakeQueryScanRuns()
		var out bytes.Buffer
		if err := runScanShow(t.Context(), "vscan-absent", false, fake, nil, &out); err == nil {
			t.Errorf("runScanShow() = nil, want a missing run to still be reported missing")
		}
	})
}

// TestUnreadableRunsFailsConsumersClosed pins the half of the contract this
// change must not move: a consuming command classifies the same failure exactly
// as it did before.
func TestUnreadableRunsFailsConsumersClosed(t *testing.T) {
	err := driftedRuns("vscan-bad")
	if !errors.Is(err, vulnports.ErrVulnIntegrity) {
		t.Fatalf("errors.Is(err, ErrVulnIntegrity) = false; consuming commands would stop failing closed")
	}
	if !strings.Contains(err.Error(), "vscan-bad") {
		t.Errorf("error text does not name the row: %v", err)
	}
}
