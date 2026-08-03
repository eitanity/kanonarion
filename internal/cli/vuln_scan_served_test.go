package cli

import (
	"bytes"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// servedRunFixture is the smallest container that can serve a stored run: the
// scan use case that witnesses the serving, and the query side that rebuilds the
// report from the records that run wrote.
func servedRunFixture(t *testing.T) (*Container, *testfakes.FakeScanWalk, vulndomain.WalkScanRun) {
	t.Helper()
	run := vulndomain.WalkScanRun{
		ID:              "vscan-served",
		WalkID:          "walk-served",
		Snapshot:        vulntest.MustNew("vuln.go.dev", "2026-07-27T16:28:49Z"),
		StartedAt:       time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC),
		CompletedAt:     time.Date(2026, 8, 1, 9, 4, 0, 0, time.UTC),
		CoverageStatus:  vulndomain.CoverageComplete,
		FindingsStatus:  vulndomain.FindingsClean,
		PipelineVersion: vulnapp.PipelineVersion,
	}
	scan := &testfakes.FakeScanWalk{}
	qv := testfakes.NewFakeQueryVuln()
	qv.SetRunRecords(run.ID, nil)
	return &Container{ScanWalk: scan, QueryVuln: qv}, scan, run
}

// TestServeStoredScanRun_WitnessesTheServing is the headline. Serving a reused
// run used to append NOTHING: the scan was answered from stored rows, and the
// only trace in the store was the derivation timestamp of a run that might be
// weeks old. "When did we last check" was then unrecoverable — an unchanged
// store answers from the same rows indefinitely.
//
// Run against the code before the fix, this fails with zero servings recorded.
func TestServeStoredScanRun_WitnessesTheServing(t *testing.T) {
	ctr, scan, run := servedRunFixture(t)
	var stdout, stderr bytes.Buffer

	if err := serveStoredScanRun(t.Context(), run, ctr, false, false, vulnapp.ServeSurfaceVulnScan, &stdout, &stderr); err != nil {
		t.Fatalf("serveStoredScanRun: %v", err)
	}

	if len(scan.ServedRuns) != 1 {
		t.Fatalf("serving a stored run witnessed %d serving(s), want exactly 1", len(scan.ServedRuns))
	}
	got := scan.ServedRuns[0]
	if got.RunID != run.ID {
		t.Errorf("witnessed run %q, want %q", got.RunID, run.ID)
	}
	if got.WalkID != run.WalkID {
		t.Errorf("witnessed walk %q, want %q", got.WalkID, run.WalkID)
	}
	if got.Surface != vulnapp.ServeSurfaceVulnScan {
		t.Errorf("witnessed surface %q, want %q", got.Surface, vulnapp.ServeSurfaceVulnScan)
	}
	// Control: a served run measures nothing, so the witnessing must not have
	// come at the cost of a scan.
	if scan.ScanCalls != 0 {
		t.Errorf("serving a stored run re-measured %d time(s)", scan.ScanCalls)
	}
}

// The surface travels from the command that asked. `audit` and `inspect` drive
// the same scan function as `vuln-scan`, and a log that attributed all three to
// one name would answer "who asked" with the wrong caller.
func TestServeStoredScanRun_AttributesTheAskingSurface(t *testing.T) {
	for _, surface := range []string{vulnapp.ServeSurfaceVulnScan, vulnapp.ServeSurfaceAudit, vulnapp.ServeSurfaceInspect} {
		t.Run(surface, func(t *testing.T) {
			ctr, scan, run := servedRunFixture(t)
			var stdout, stderr bytes.Buffer
			if err := serveStoredScanRun(t.Context(), run, ctr, false, false, surface, &stdout, &stderr); err != nil {
				t.Fatalf("serveStoredScanRun: %v", err)
			}
			if len(scan.ServedRuns) != 1 || scan.ServedRuns[0].Surface != surface {
				t.Fatalf("witnessed %+v, want one serving attributed to %q", scan.ServedRuns, surface)
			}
		})
	}
}

// A serving that could not be witnessed fails rather than handing back an
// untraced answer, and it fails BEFORE the report is written: a report on stdout
// with no ledger line is exactly the silence this closes.
func TestServeStoredScanRun_FailsWhenTheServingCannotBeWitnessed(t *testing.T) {
	ctr, scan, run := servedRunFixture(t)
	scan.ServeReusableRunErr = errServedTest
	var stdout, stderr bytes.Buffer

	err := serveStoredScanRun(t.Context(), run, ctr, false, false, vulnapp.ServeSurfaceVulnScan, &stdout, &stderr)
	if err == nil {
		t.Fatal("an unwitnessable serving reported success")
	}
	if stdout.Len() != 0 {
		t.Errorf("the report was written despite the failed witness: %q", stdout.String())
	}
}

type servedTestError struct{}

func (servedTestError) Error() string { return "ledger unavailable" }

var errServedTest = servedTestError{}
