package cli

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// The context report loads scan runs for the newest few walks only. That window
// is deliberate — the alternative is reading every walk's runs on every
// invocation — and unlike the containment search it cannot report a false
// absence, because a module's verdict is read from the vulnerability ledger and
// not from this set.
//
// What it does bound is the RUN CONTEXT attached to a verdict: status word,
// coverage caveat, affected peers. A section missing all three because the
// record's walk fell outside the window looks exactly like one where the scan
// had nothing to say. So the window keeps its cap and states its basis, and
// states it only when it actually bit.

func windowWalks(t *testing.T, count int) *testfakes.FakeQueryWalks {
	t.Helper()
	uc := testfakes.NewFakeQueryWalks()
	summaries := make([]walkports.WalkSummary, 0, count)
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	for i := range count {
		id := fmt.Sprintf("walk-%03d", i)
		root := mustCoord(t, fmt.Sprintf("example.com/proj%d", i), "v1.0.0")
		uc.AddWalk(walkdomain.WalkRecord{ID: id, Target: root, Graph: walkdomain.Graph{Target: root}})
		summaries = append(summaries, walkports.WalkSummary{
			ID: id, Target: root, StartedAt: base.Add(-time.Duration(i) * time.Minute),
		})
	}
	uc.SetSummaries(summaries)
	return uc
}

func loadWindow(t *testing.T, walkCount int) *vulnBatchCtx {
	t.Helper()
	runs := testfakes.NewFakeQueryScanRuns()
	runs.AddSnapshot(vulntest.MustNew("osv", "2026-08-01T00:00:00Z"))
	batch, err := loadVulnBatchCtx(context.Background(), runs, windowWalks(t, walkCount))
	if err != nil {
		t.Fatalf("loadVulnBatchCtx: %v", err)
	}
	return batch
}

// A store larger than the window: the window is capped at its constant, and a
// verdict read from a walk outside it says why it carries no run context.
func TestVulnContextWindow_StatesItsBoundWhenItBit(t *testing.T) {
	batch := loadWindow(t, vulnContextWalkWindow+5)
	if got := len(batch.window); got != vulnContextWalkWindow {
		t.Fatalf("window holds %d walks, want %d", got, vulnContextWalkWindow)
	}
	if !batch.windowCapped {
		t.Fatal("the window covered fewer walks than the store holds and did not record it")
	}
	var result contextVulnerabilities
	batch.nameWindowBound(&result, "walk-042")
	if result.WalkWindowNote == "" {
		t.Fatal("a verdict from a walk outside the window carries no statement of the window")
	}
	if !strings.Contains(result.WalkWindowNote, fmt.Sprintf("%d most recent", vulnContextWalkWindow)) {
		t.Errorf("the note does not name the window: %q", result.WalkWindowNote)
	}
}

// The zero-paired control. On a store the window covers entirely there is no
// bound to disclose, and a note printed anyway would be boilerplate a reader
// learns to skip — including on the store this was filed against, which holds
// fewer walks than the window.
func TestVulnContextWindow_SaysNothingWhenItCoveredTheStore(t *testing.T) {
	batch := loadWindow(t, vulnContextWalkWindow-5)
	if batch.windowCapped {
		t.Fatal("a window covering every walk in the store reported itself as capped")
	}
	var result contextVulnerabilities
	// Even a walk id the batch never saw draws no note here: the window is not
	// what kept it out, and saying otherwise would name the wrong cause.
	batch.nameWindowBound(&result, "walk-999")
	if result.WalkWindowNote != "" {
		t.Errorf("an unbounded window hedged anyway: %q", result.WalkWindowNote)
	}
}

// A walk inside the window has its run context read, so there is nothing to
// disclose about it either.
func TestVulnContextWindow_SaysNothingForAWalkInsideIt(t *testing.T) {
	batch := loadWindow(t, vulnContextWalkWindow+5)
	var result contextVulnerabilities
	batch.nameWindowBound(&result, batch.window[0])
	if result.WalkWindowNote != "" {
		t.Errorf("a walk inside the window drew a window note: %q", result.WalkWindowNote)
	}
}

// The note a reader actually sees. It carries its own label, because the walk
// the answer came from is a different fact from the report's read of it, and
// one record must show one "Walk basis" line.
func TestVulnContextWindow_RendersTheNoteUnderItsOwnLabel(t *testing.T) {
	batch := loadWindow(t, vulnContextWalkWindow+5)
	var v contextVulnerabilities
	v.Status = "Clean"
	v.WalkBasisID = "walk-042"
	v.WalkBasisFrame = "target-rooted:example.com/app@v1.0.0"
	batch.nameWindowBound(&v, "walk-042")

	var buf bytes.Buffer
	w := &errWriter{w: &buf}
	printVulnerabilitiesSummary(w, contextOutput{Vulnerabilities: v})
	if w.err != nil {
		t.Fatalf("rendering the summary: %v", w.err)
	}
	got := buf.String()

	want := "  Run context:     this record was measured in a walk outside the 10 most recent walks this report loaded, so there is no run context to show\n"
	if !strings.Contains(got, want) {
		t.Errorf("rendered summary =\n%s\nwant a line %q", got, want)
	}
	if n := strings.Count(got, "Walk basis:"); n != 1 {
		t.Errorf("the record shows %d walk-basis lines, want 1:\n%s", n, got)
	}
	if strings.Contains(got, "Walk basis:      this record was measured") {
		t.Errorf("the note is still printed under the walk-basis label:\n%s", got)
	}
}
