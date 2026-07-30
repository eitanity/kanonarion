package application_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	application "github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// A refused write used to be logged and stepped over: the derived record was
// handed back to the caller, the tally counted it, the run was persisted and the
// summary described the module as measured. Every write leg of the stage now
// raises instead, and these are the regressions for each of them.
//
// The assertion is deliberately in two parts at every leg. That the scan returns
// an error is the smaller half; that NO WalkScanRun reached the store is the
// claim the defect was about, because the run record is what the summary, the
// coverage counts and every later query are read from. A leg that returned an
// error but still persisted a run would leave the false claim in place.
func assertScanRefusedAndClaimedNothing(t *testing.T, store *fakeVulnStore, run domain.WalkScanRun, err error, wantInMessage ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("scan succeeded although the store refused a record write: a verdict the store did not accept is not a verdict the run may claim")
	}
	if !errors.Is(err, errStore) {
		t.Errorf("the store's own error must survive wrapping so an operator sees why the write failed, got: %v", err)
	}
	for _, want := range wantInMessage {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error message missing %q, so it does not identify the failure: %v", want, err)
		}
	}
	if run.ID != "" {
		t.Errorf("a refused scan must return no run, got %q with status %q", run.ID, run.OverallStatus)
	}
	if n := store.walkScanRunCount(); n != 0 {
		t.Errorf("%d walk scan run(s) persisted after a refused record write; the run record is what the summary and every later query read, so none may be kept", n)
	}
}

// The project-rooted leg: one govulncheck run over the live working tree derives
// a verdict per in-build module, and each is written individually.
func TestScanWalk_ProjectRooted_ARefusedWriteFailsTheScan(t *testing.T) {
	ctx := t.Context()
	f := newProjectScanFixture(t, &fakeScanner{})
	f.vulnStore.errOnPutRecordFor = f.depB

	run, err := f.walkUC.Scan(ctx, application.ScanWalkParams{
		WalkID: f.walkID, Operator: "tester", ProjectDir: "/fake/project",
	})
	assertScanRefusedAndClaimedNothing(t, f.vulnStore, run, err, f.depB.Path())
}

// The target-rooted leg is the sibling of the project-rooted one for a
// coordinate-keyed walk. It must NOT fall back to isolated per-module scanning
// here: the fallback exists for a target that cannot be analysed, and repeating
// the analysis would only meet the same refusal one write later.
func TestScanWalk_TargetRooted_ARefusedWriteFailsTheScanWithoutFallingBack(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{targetRooted: true}
	f := newTargetScanFixture(t, scanner)
	f.vulnStore.errOnPutRecordFor = f.depB

	run, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester"})
	assertScanRefusedAndClaimedNothing(t, f.vulnStore, run, err, f.depB.Path())

	if scanner.scanCalls != 0 {
		t.Errorf("%d isolated per-module scans ran after a write was refused; a store that refuses one write refuses them all, so the fallback buys no coverage", scanner.scanCalls)
	}
}

// The ScanFailed leg. A worker that failed before reaching a verdict is recorded
// as such, and that record is as much a measurement of the run as a clean one:
// without it the module is neither analysed nor accounted for as failed, and the
// coverage buckets stop partitioning the module total.
//
// The refusal is scoped to depA, whose isolated scan therefore fails on its own
// write first — which is what produces the worker error this leg then tries to
// record.
func TestScanWalk_ARefusedScanFailedRecordFailsTheScan(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{}
	f := newTargetScanFixture(t, scanner)
	// Every node carries a known advisory so the metadata pre-filter cannot
	// short-circuit the heavy scan and skip the write leg under test.
	f.markAllVulnerable()
	f.vulnStore.errOnPutRecordFor = f.depA

	run, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester"})
	assertScanRefusedAndClaimedNothing(t, f.vulnStore, run, err, f.depA.Path(), "ScanFailed")
}

// The local-replace leg. Its record is written after every module verdict, so a
// coordinate-scoped refusal is the only way to reach it — and reaching it is the
// point: this node's whole contribution to the run is the Unscannable row saying
// a working tree cannot be analysed, so a refused write turns the run's
// unscannable count into a claim about a row that is not there.
func TestScanWalk_ARefusedLocalReplaceRecordFailsTheScan(t *testing.T) {
	ctx := t.Context()

	target := coordinatetest.MustNew("github.com/example/proj", coordinate.LocalVersion)
	localDep := coordinatetest.MustNew("example.com/dep", "v1.0.0")

	f := newProjectScanFixtureFor(t, &fakeScanner{}, walkdomain.WalkRecord{
		ID:     "walk-localreplace-refused",
		Target: target,
		Graph: walkdomain.Graph{
			Target: target,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: target, ResolutionSource: walkdomain.ResolutionLocalMainModule},
				{Coordinate: localDep, ResolutionSource: walkdomain.ResolutionLocalReplace, LocalPath: "../local/dep"},
			},
		},
	}, target)
	f.vulnStore.errOnPutRecordFor = localDep

	run, err := f.walkUC.Scan(ctx, application.ScanWalkParams{
		WalkID: f.walkID, Operator: "tester", ProjectDir: "/fake/project",
	})
	assertScanRefusedAndClaimedNothing(t, f.vulnStore, run, err, localDep.Path(), "local-replace Unscannable")
}
