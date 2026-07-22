package application_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	application "github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// errFakeDatabase stands in for an unreadable pinned advisory database.
var errFakeDatabase = errors.New("advisory database unavailable")

// TestScanWalk_ProjectRooted_MatchesAdvisoriesByCoordinate is the regression
// guard for a false AllClean on the path a project walk treats as authoritative.
//
// Every per-module verdict used to be derived solely from the grouped output of
// one project-rooted govulncheck run: a module the grouping attributed nothing
// to became Clean. That made Clean mean "nothing was attributed here", which is
// indistinguishable from "the parse dropped it" — one attribution failure
// converts an affected module into a clean one and the run reports AllClean.
//
// Here the project-rooted analysis attributes nothing at all while the pinned
// snapshot holds an advisory for depA. The verdict must be Affected: advisories
// are matched by coordinate on every module in the walk, and the analysis
// contributes reachability rather than deciding what is looked for.
func TestScanWalk_ProjectRooted_MatchesAdvisoriesByCoordinate(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{}
	f := newProjectScanFixture(t, scanner)

	// The project-rooted analysis reports nothing — the attribution gap.
	scanner.projectFindings = nil
	f.db.findings = map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{
		f.depA: {{ID: "GO-2026-5970", Summary: "Infinite loop on invalid input", FixedIn: "v0.39.0"}},
	}

	run, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester", ProjectDir: "/fake/project"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if run.OverallStatus != domain.WalkStatusAffected {
		t.Errorf("overall status = %s, want Affected: an advisory in the pinned snapshot must not read as AllClean", run.OverallStatus)
	}
	assertModuleStatus(t, ctx, f.vulnStore, f.walkID, f.depA, domain.StatusAffected)
	// A module with no advisory in the snapshot stays Clean, and that Clean now
	// means "advisories were matched and none applied".
	assertModuleStatus(t, ctx, f.vulnStore, f.walkID, f.depB, domain.StatusClean)

	rec, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(ctx, f.depA, "v1", f.walkID)
	if err != nil || !ok {
		t.Fatalf("record for depA: ok=%v err=%v", ok, err)
	}
	if len(rec.Findings) != 1 || rec.Findings[0].ID != "GO-2026-5970" {
		t.Fatalf("depA findings = %+v, want GO-2026-5970", rec.Findings)
	}
	// The whole-build analysis examined the real import graph and did not reach
	// the symbol, so its silence is recorded as an answer, not as an absence.
	if r := rec.Findings[0].Reachable; r == nil || r.IsReachable {
		t.Errorf("coordinate-matched finding reachability = %+v, want not-reachable rather than unknown", r)
	}
}

// TestScanWalk_ProjectRooted_ReportedFindingKeepsItsReachability asserts the
// merge does not overwrite what the project-rooted analysis established: a
// finding the analysis reached carries its call-graph answer, and the coordinate
// match adds to the set rather than replacing it.
func TestScanWalk_ProjectRooted_ReportedFindingKeepsItsReachability(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{}
	f := newProjectScanFixture(t, scanner)

	scanner.projectFindings = map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{
		f.depA: {{ID: "GO-2026-0001", Reachable: &domain.ReachabilityResult{IsReachable: true, Confidence: domain.ConfidenceHigh}}},
	}
	f.db.findings = map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{
		f.depA: {
			{ID: "GO-2026-0001"}, // same advisory, without reachability
			{ID: "GO-2026-0002"}, // only the snapshot knows about this one
		},
	}

	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester", ProjectDir: "/fake/project"}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	rec, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(ctx, f.depA, "v1", f.walkID)
	if err != nil || !ok {
		t.Fatalf("record for depA: ok=%v err=%v", ok, err)
	}
	if len(rec.Findings) != 2 {
		t.Fatalf("depA findings = %+v, want both the reached and the coordinate-matched advisory", rec.Findings)
	}
	byID := map[string]domain.VulnerabilityFinding{}
	for _, fi := range rec.Findings {
		byID[fi.ID] = fi
	}
	if r := byID["GO-2026-0001"].Reachable; r == nil || !r.IsReachable {
		t.Errorf("the analysis-reported finding lost its reachability: %+v", r)
	}
	if r := byID["GO-2026-0002"].Reachable; r == nil || r.IsReachable {
		t.Errorf("the coordinate-matched finding = %+v, want not-reachable", r)
	}
}

// TestScanWalk_ProjectRooted_AdvisoryLookupFailureIsNotClean asserts a module
// whose advisory set could not be read is reported as a fault, never as clean:
// an unchecked module and a checked-and-clean one must not be the same verdict.
func TestScanWalk_ProjectRooted_AdvisoryLookupFailureIsNotClean(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{}
	f := newProjectScanFixture(t, scanner)
	f.db.errOnLookup = errFakeDatabase

	run, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester", ProjectDir: "/fake/project"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if run.OverallStatus == domain.WalkStatusAllClean {
		t.Fatal("a walk whose advisory lookups all failed reported AllClean")
	}
	assertModuleStatus(t, ctx, f.vulnStore, f.walkID, f.depA, domain.StatusScanFailed)
}

// TestScanWalk_EveryScannedCoordinateHasAPersistedRecord is the regression guard
// for the second half of the same defect: the run reported a progress line for
// every module in the graph but persistence was best-effort, so a module could
// be counted in the run and leave nothing in the store — discoverable only by
// querying the store afterwards. A gap must fail the run.
func TestScanWalk_EveryScannedCoordinateHasAPersistedRecord(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{}
	f := newProjectScanFixture(t, scanner)
	// depB's verdict is claimed by the run and silently not stored.
	f.vulnStore.dropRecordFor = f.depB

	_, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester", ProjectDir: "/fake/project"})
	if err == nil {
		t.Fatal("Scan returned nil error although one scanned coordinate has no persisted record")
	}
	if !strings.Contains(err.Error(), f.depB.Path) {
		t.Errorf("error must name the module whose verdict was lost; got: %v", err)
	}
}
