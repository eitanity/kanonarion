package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// A scan run whose walk has been purged is half-preserved evidence: the findings
// survive, the statement of what was scanned does not. It must still be listed —
// it is the only record those scans happened — but it must never render a walk
// id that reads as a live reference. These tests pin that at every surface that
// serves a run, and pin that a run whose walk is present is unchanged.

const unresolvableMarker = "inputs unresolvable"

func TestRunScanList_NamesTheRunWhoseWalkIsGone(t *testing.T) {
	fake := testfakes.NewFakeQueryScanRuns()
	fake.AddRun(listableRun("vscan-dangling", "walk-purged"))
	fake.AddRun(listableRun("vscan-healthy", "walk-held"))
	fake.MarkWalkAbsent("walk-purged")

	var out bytes.Buffer
	if err := runScanList(t.Context(), "", 0, 0, fake, &out, io.Discard); err != nil {
		t.Fatalf("runScanList() = %v, want nil", err)
	}
	got := out.String()

	var dangling, healthy string
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		switch {
		case strings.Contains(line, "vscan-dangling"):
			dangling = line
		case strings.Contains(line, "vscan-healthy"):
			healthy = line
		}
	}
	if dangling == "" || healthy == "" {
		t.Fatalf("both runs must be listed; a run whose walk is gone is still evidence:\n%s", got)
	}
	if !strings.Contains(dangling, unresolvableMarker) {
		t.Errorf("the dangling run renders as an ordinary run:\n%s", dangling)
	}
	if !strings.Contains(dangling, "walk absent from this store") {
		t.Errorf("the statement does not say what is unresolvable:\n%s", dangling)
	}
	if strings.Contains(healthy, unresolvableMarker) {
		t.Errorf("a run whose walk resolves gained the statement:\n%s", healthy)
	}
}

func TestRunScanList_JSONStatesUnresolvableInputs(t *testing.T) {
	fake := testfakes.NewFakeQueryScanRuns()
	fake.AddRun(listableRun("vscan-dangling", "walk-purged"))
	fake.AddRun(listableRun("vscan-healthy", "walk-held"))
	fake.MarkWalkAbsent("walk-purged")

	prev := jsonOut
	jsonOut = true
	t.Cleanup(func() { jsonOut = prev })

	var out bytes.Buffer
	if err := runScanList(t.Context(), "", 0, 0, fake, &out, io.Discard); err != nil {
		t.Fatalf("runScanList(--json) = %v, want nil", err)
	}

	var entries []map[string]any
	if err := json.Unmarshal(out.Bytes(), &entries); err != nil {
		t.Fatalf("decoding JSON: %v\n%s", err, out.String())
	}
	byID := make(map[string]map[string]any, len(entries))
	for _, e := range entries {
		id, _ := e["id"].(string)
		byID[id] = e
	}
	note, ok := byID["vscan-dangling"]["inputs_unresolvable"].(string)
	if !ok || !strings.Contains(note, "walk-purged") {
		t.Errorf("dangling entry does not state unresolvable inputs: %v", byID["vscan-dangling"])
	}
	// Absent, not false or empty: an existing consumer of this listing sees no
	// change on a healthy store.
	if _, present := byID["vscan-healthy"]["inputs_unresolvable"]; present {
		t.Errorf("healthy entry carries the statement: %v", byID["vscan-healthy"])
	}
}

func TestRunScanList_RefusesToGuessWhenPresenceCannotBeChecked(t *testing.T) {
	probeErr := errors.New("database is locked")
	fake := testfakes.NewFakeQueryScanRuns()
	fake.AddRun(listableRun("vscan-1", "walk-1"))
	fake.PresenceErr = probeErr

	var out bytes.Buffer
	err := runScanList(t.Context(), "", 0, 0, fake, &out, io.Discard)
	if !errors.Is(err, probeErr) {
		t.Fatalf("runScanList() = %v, want the probe failure; a reader that cannot check must not answer", err)
	}
}

func TestRunScanShow_StatesUnresolvableInputsOnTheWalkLine(t *testing.T) {
	fake := testfakes.NewFakeQueryScanRuns()
	run := listableRun("vscan-dangling", "walk-purged")
	fake.AddRun(run)
	fake.MarkWalkAbsent("walk-purged")

	var out bytes.Buffer
	if err := runScanShow(t.Context(), "vscan-dangling", false, fake, testfakes.NewFakeQueryVuln(), nil, nil, &out, io.Discard); err != nil {
		t.Fatalf("runScanShow() = %v, want nil", err)
	}
	got := out.String()
	var walkLine string
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "Walk ID:") {
			walkLine = line
		}
	}
	if walkLine == "" {
		t.Fatalf("no Walk ID line:\n%s", got)
	}
	if !strings.Contains(walkLine, unresolvableMarker) {
		t.Errorf("the walk reference renders as though it resolves:\n%s", walkLine)
	}
}

func TestRunScanShow_HealthyRunIsUnchanged(t *testing.T) {
	fake := testfakes.NewFakeQueryScanRuns()
	run := listableRun("vscan-healthy", "walk-held")
	fake.AddRun(run)

	var out bytes.Buffer
	if err := runScanShow(t.Context(), "vscan-healthy", false, fake, testfakes.NewFakeQueryVuln(), nil, nil, &out, io.Discard); err != nil {
		t.Fatalf("runScanShow() = %v, want nil", err)
	}
	got := out.String()
	if !strings.Contains(got, "Walk ID:     walk-held\n") {
		t.Errorf("the walk line changed for a run whose walk resolves:\n%s", got)
	}
	if strings.Contains(got, unresolvableMarker) {
		t.Errorf("a healthy run gained the statement:\n%s", got)
	}
}

func TestRunScanHistory_StatesUnresolvableInputsForThePurgedWalk(t *testing.T) {
	fake := testfakes.NewFakeQueryScanRuns()
	fake.AddRun(listableRun("vscan-dangling", "walk-purged"))
	fake.MarkWalkAbsent("walk-purged")

	var out bytes.Buffer
	if err := runScanHistory(t.Context(), "walk-purged", false, fake, &out); err != nil {
		t.Fatalf("runScanHistory() = %v, want nil", err)
	}
	got := out.String()
	if !strings.Contains(got, unresolvableMarker) || !strings.Contains(got, "walk-purged") {
		t.Errorf("history renders the purged walk's runs as ordinary:\n%s", got)
	}
	if !strings.Contains(got, "vscan-dangling") {
		t.Errorf("history dropped the run; it is still evidence the scan happened:\n%s", got)
	}
}

// A purged walk owes the statement even with no run left to hang it on: the
// history command is told the walk id directly.
func TestRunScanHistory_StatesUnresolvableInputsWithNoRuns(t *testing.T) {
	fake := testfakes.NewFakeQueryScanRuns()
	fake.MarkWalkAbsent("walk-purged")

	var out bytes.Buffer
	if err := runScanHistory(t.Context(), "walk-purged", false, fake, &out); err != nil {
		t.Fatalf("runScanHistory() = %v, want nil", err)
	}
	if !strings.Contains(out.String(), unresolvableMarker) {
		t.Errorf("an absent walk reports only 'no scan runs found':\n%s", out.String())
	}
}

func TestRunScanHistory_JSONShapeUnchangedForAHeldWalk(t *testing.T) {
	fake := testfakes.NewFakeQueryScanRuns()
	fake.AddRun(listableRun("vscan-healthy", "walk-held"))

	var out bytes.Buffer
	if err := runScanHistory(t.Context(), "walk-held", true, fake, &out); err != nil {
		t.Fatalf("runScanHistory() = %v, want nil", err)
	}
	var runs []vulndomain.WalkScanRun
	if err := json.Unmarshal(out.Bytes(), &runs); err != nil {
		t.Fatalf("a healthy walk must still encode as a bare run array: %v\n%s", err, out.String())
	}
	if len(runs) != 1 {
		t.Errorf("got %d runs, want 1", len(runs))
	}
}

func TestRunScanHistory_JSONStatesUnresolvableInputs(t *testing.T) {
	fake := testfakes.NewFakeQueryScanRuns()
	fake.AddRun(listableRun("vscan-dangling", "walk-purged"))
	fake.MarkWalkAbsent("walk-purged")

	var out bytes.Buffer
	if err := runScanHistory(t.Context(), "walk-purged", true, fake, &out); err != nil {
		t.Fatalf("runScanHistory() = %v, want nil", err)
	}
	var payload struct {
		Runs               []vulndomain.WalkScanRun `json:"runs"`
		InputsUnresolvable string                   `json:"inputs_unresolvable"`
	}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decoding JSON: %v\n%s", err, out.String())
	}
	if !strings.Contains(payload.InputsUnresolvable, "walk-purged") {
		t.Errorf("JSON does not state the unresolvable inputs: %s", out.String())
	}
	if len(payload.Runs) != 1 {
		t.Errorf("got %d runs, want the dangling run still reported", len(payload.Runs))
	}
}
