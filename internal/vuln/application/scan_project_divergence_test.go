package application_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	application "github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// writeProjectGoMod writes a manifest into the directory a walk was taken from,
// requiring exactly the modules given. It is the only fact the agreement check
// reads off the tree.
func writeProjectGoMod(t *testing.T, dir string, requires map[string]string) {
	t.Helper()
	paths := make([]string, 0, len(requires))
	for p := range requires {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var b strings.Builder
	b.WriteString("module github.com/example/proj\n\ngo 1.24\n\nrequire (\n")
	for _, p := range paths {
		fmt.Fprintf(&b, "\t%s %s\n", p, requires[p])
	}
	b.WriteString(")\n")
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(b.String()), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
}

// recordFor reads back the record this run stored for coord.
func recordFor(t *testing.T, f projectScanFixture, coord coordinate.ModuleCoordinate) domain.VulnerabilityRecord {
	t.Helper()
	rec, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(t.Context(), coord, "v1", f.walkID)
	if err != nil || !ok {
		t.Fatalf("record for %s: ok=%v err=%v", coord, ok, err)
	}
	return rec
}

// TestScanWalk_ProjectDirStillBuildsTheWalk_AnalysisIsAttributed pins the
// unchanged case: the directory still requires the versions the walk resolved,
// so the project-rooted analysis runs and its reachability answer is recorded
// exactly as before.
func TestScanWalk_ProjectDirStillBuildsTheWalk_AnalysisIsAttributed(t *testing.T) {
	ctx := t.Context()
	f, _, dir := recordedProjectFixture(t)
	writeProjectGoMod(t, dir, map[string]string{
		f.depA.Path(): f.depA.Version(),
		f.depB.Path(): f.depB.Version(),
	})
	f.scanner.projectFindings = map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{
		f.depA: {{ID: "GO-2025-3553", Reachable: &domain.ReachabilityResult{IsReachable: true, Confidence: domain.ConfidenceHigh}}},
	}

	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester"}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if f.scanner.projectCalls != 1 {
		t.Fatalf("project-rooted scans = %d, want 1: an agreeing directory must still be analysed", f.scanner.projectCalls)
	}
	rec := recordFor(t, f, f.depA)
	if rec.OverallStatus != domain.StatusAffected {
		t.Errorf("depA status = %s, want Affected", rec.OverallStatus)
	}
	if len(rec.Findings) != 1 || rec.Findings[0].Reachable == nil || !rec.Findings[0].Reachable.IsReachable {
		t.Errorf("depA findings = %+v, want the analysis's reachable verdict", rec.Findings)
	}
}

// TestScanWalk_ProjectDirAddedAnUnrelatedDependency_StillMatches pins what
// "matches" means. A tree that requires a module the walk never carried has not
// moved away from the walk on anything the walk pinned, so the analysis is still
// evidence about this build and is still attributed.
func TestScanWalk_ProjectDirAddedAnUnrelatedDependency_StillMatches(t *testing.T) {
	ctx := t.Context()
	f, _, dir := recordedProjectFixture(t)
	writeProjectGoMod(t, dir, map[string]string{
		f.depA.Path():              f.depA.Version(),
		f.depB.Path():              f.depB.Version(),
		"github.com/newly/adopted": "v1.2.3",
	})

	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester"}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if f.scanner.projectCalls != 1 {
		t.Fatalf("project-rooted scans = %d, want 1: an added dependency is not a divergence", f.scanner.projectCalls)
	}
	if rec := recordFor(t, f, f.depA); rec.UnscanReason != "" {
		t.Errorf("depA unscan reason = %q, want none", rec.UnscanReason)
	}
}

// TestScanWalk_ProjectDirUpgradedAwayFromTheWalk_RecordsNoReachability is the
// regression for the false negative this fix exists to close.
//
// The walk pins a vulnerable version. The directory has since been upgraded to
// the fixed one, so govulncheck run over that directory correctly reports
// nothing — and that silence used to be filed against the walk's version as
// "not reachable" at high confidence. It must now be filed as no reachability
// answer at all, while the coordinate match against the version the walk pinned
// survives: the operator does not lose the "you are pinned to a vulnerable
// version" signal because a directory moved.
func TestScanWalk_ProjectDirUpgradedAwayFromTheWalk_RecordsNoReachability(t *testing.T) {
	ctx := t.Context()
	f, _, dir := recordedProjectFixture(t)
	// The walk pinned gopkg.in/yaml.v3 v3.0.1; the tree now requires v3.0.2.
	writeProjectGoMod(t, dir, map[string]string{
		f.depA.Path(): "v3.0.2",
		f.depB.Path(): f.depB.Version(),
	})
	// The pinned snapshot still knows the advisory against the walk's version.
	f.db.findings = map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{
		f.depA: {{ID: "GO-2025-3553", Summary: "excessive memory allocation"}},
	}
	// govulncheck over the upgraded tree finds nothing, exactly as it should.
	f.scanner.projectFindings = nil

	run, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester"})
	if err != nil {
		t.Fatalf("a walk whose directory moved on must still scan, got: %v", err)
	}

	if f.scanner.projectCalls != 0 {
		t.Errorf("project-rooted scans = %d, want 0: no analysis of a different build may be attributed to this walk", f.scanner.projectCalls)
	}
	if f.scanner.scanCalls != 0 {
		t.Errorf("isolated scans = %d, want 0: the degradation is coordinate-only, not a re-derivation in another frame", f.scanner.scanCalls)
	}

	rec := recordFor(t, f, f.depA)
	if len(rec.Findings) != 1 || rec.Findings[0].ID != "GO-2025-3553" {
		t.Fatalf("depA findings = %+v, want the coordinate match against the version the walk pinned", rec.Findings)
	}
	if r := rec.Findings[0].Reachable; r != nil {
		t.Errorf("depA reachability = %+v, want nil: a silent analysis of another build is not a not-reachable verdict", r)
	}
	if rec.UnscanReason != domain.UnscanReasonProjectBuildDiverged {
		t.Errorf("depA unscan reason = %q, want %q", rec.UnscanReason, domain.UnscanReasonProjectBuildDiverged)
	}
	coverage, findings := domain.RecordAxes(rec)
	if coverage != domain.CoverageUnscannable {
		t.Errorf("depA coverage axis = %s, want Unscannable: the record must not read as an analysed scan", coverage)
	}
	if findings != domain.FindingsRecordAffected {
		t.Errorf("depA findings axis = %s, want Affected: the coordinate answer survives the degradation", findings)
	}
	// Both version sets, named on the record itself.
	for _, want := range []string{dir, f.depA.Path(), "v3.0.1 -> v3.0.2", "reachability was not established"} {
		if !strings.Contains(rec.UnscannableReason, want) {
			t.Errorf("divergence statement %q does not name %q", rec.UnscannableReason, want)
		}
	}
	if run.OverallStatus == domain.WalkStatusAllClean {
		t.Error("a run that established no reachability reported AllClean")
	}
	// The same coverage word the missing-directory degradation reports: the run
	// happened, and part of what it was asked for was not established.
	if run.CoverageStatus != domain.CoveragePartial {
		t.Errorf("run coverage = %s, want Partial", run.CoverageStatus)
	}
	if run.FindingsStatus != domain.FindingsAffected {
		t.Errorf("run findings = %s, want Affected: the coordinate answer is still a finding", run.FindingsStatus)
	}
	if !strings.Contains(f.logs.String(), "no longer requires the module versions this walk resolved") {
		t.Error("the run did not state the divergence in its log")
	}
}
