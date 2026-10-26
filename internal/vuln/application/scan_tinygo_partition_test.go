package application_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"

	application "code.eitanity.com/kanonarion/internal/vuln/application"
	"code.eitanity.com/kanonarion/internal/vuln/domain"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// tinyGoWasiWalk is a wasip1 walk: TinyGo supplies os and runtime, Go supplies
// io and strconv, as the walk measured them.
func tinyGoWasiWalk(t *testing.T) (walkdomain.WalkRecord, coordinate.ModuleCoordinate, coordinate.ModuleCoordinate) {
	t.Helper()
	root := coordinatetest.MustNew("example.com/wexp", coordinate.LocalVersion)
	std := coordinatetest.MustNew(domain.StdlibModulePath, "v1.27.2")
	tg, ok := walkdomain.TinyGoNode("0.42.0", walkdomain.TinyGoFacts{Target: "wasip1", Packages: []string{"os", "runtime"}})
	if !ok {
		t.Fatal("TinyGoNode refused 0.42.0")
	}
	return walkdomain.WalkRecord{
		ID:     "walk-tinygo",
		Target: root,
		Graph: walkdomain.Graph{
			Target: root,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: root, ResolutionSource: walkdomain.ResolutionLocalMainModule},
				tg,
				{Coordinate: std, DirectDependency: true, ResolutionSource: walkdomain.ResolutionStdlib, Packages: []string{"io", "strconv"}},
			},
			BuildEnv: walkdomain.BuildEnv{GOOS: "wasip1", GOARCH: "wasm", GoVersion: "go1.27.2", TinyGoTarget: "wasip1", TinyGoVersion: "0.42.0"},
		},
	}, root, std
}

func reached() *domain.ReachabilityResult {
	return &domain.ReachabilityResult{IsReachable: true, Confidence: domain.ConfidenceHigh,
		DerivedBy: domain.ReachabilityDerivation{Analyser: domain.AnalyserGovulncheck, Fidelity: string(domain.ScanModeSource)}}
}

func scanTinyGoWalk(t *testing.T, findings []domain.VulnerabilityFinding) (domain.WalkScanRun, domain.VulnerabilityRecord, projectScanFixture) {
	t.Helper()
	walk, root, std := tinyGoWasiWalk(t)
	scanner := &fakeScanner{projectFindings: map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{
		coordinatetest.PathOnly(domain.StdlibModulePath): findings,
	}}
	f := newProjectScanFixtureFor(t, scanner, walk, root)
	run, err := f.walkUC.Scan(t.Context(), application.ScanWalkParams{WalkID: walk.ID, Operator: "tester", ProjectDir: "/fake/project"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	rec, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(t.Context(), std, "v1", walk.ID)
	if err != nil || !ok {
		t.Fatalf("stdlib record missing: ok=%v err=%v", ok, err)
	}
	return run, rec, f
}

func findingByID(t *testing.T, rec domain.VulnerabilityRecord, id string) domain.VulnerabilityFinding {
	t.Helper()
	for _, f := range rec.Findings {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("finding %s absent from %+v", id, rec.Findings)
	return domain.VulnerabilityFinding{}
}

func TestScanWalk_TinyGo_PartitionsStdlibFindingsBySupplier(t *testing.T) {
	run, rec, _ := scanTinyGoWalk(t, []domain.VulnerabilityFinding{
		{ID: "GO-OS", AffectedPackages: []string{"os"}, AffectedSymbols: []string{"Root.Open"}, Reachable: reached()},
		{ID: "GO-STRCONV", AffectedPackages: []string{"strconv"}, AffectedSymbols: []string{"Quote"}, Reachable: reached()},
		{ID: "GO-NOPKG", Reachable: reached()},
	})

	os := findingByID(t, rec, "GO-OS")
	if !os.NotEstablished || os.TinyGoNote != "TinyGo supplies os; Go's affected range describes Go's code" {
		t.Errorf("os finding = established %t, note %q", !os.NotEstablished, os.TinyGoNote)
	}
	if s := domain.FindingReachabilityState(os); s != domain.StateNotDetermined {
		t.Errorf("os finding state = %s, want not_determined", s)
	}
	if s, _ := domain.NegativeSoundness(os); s != domain.SoundnessUnconfirmed {
		t.Errorf("os finding soundness = %s, want unconfirmed", s)
	}
	strconv := findingByID(t, rec, "GO-STRCONV")
	if strconv.NotEstablished || strconv.TinyGoNote != "" || domain.FindingReachabilityState(strconv) != domain.StateReachable {
		t.Errorf("strconv finding was not judged as today: %+v", strconv)
	}
	if nopkg := findingByID(t, rec, "GO-NOPKG"); !nopkg.NotEstablished || nopkg.TinyGoNote != domain.NoPackageNote {
		t.Errorf("package-level finding = %+v", nopkg)
	}
	if rec.OverallStatus != domain.StatusAffected {
		t.Errorf("stdlib status = %s, want Affected on the judged strconv finding", rec.OverallStatus)
	}
	if run.Counts.Total != 2 || run.Counts.Affected != 1 {
		t.Errorf("run counts = %+v, want 2 modules (root and stdlib; TinyGo is judged beside the toolchain) and 1 affected", run.Counts)
	}
}

func TestScanWalk_TinyGo_AllNotEstablishedIsInconclusive(t *testing.T) {
	run, rec, f := scanTinyGoWalk(t, []domain.VulnerabilityFinding{
		{ID: "GO-OS", AffectedPackages: []string{"os"}, Reachable: reached()},
		{ID: "GO-NOPKG"},
	})

	if rec.OverallStatus != domain.StatusInconclusive {
		t.Errorf("stdlib status = %s, want Inconclusive", rec.OverallStatus)
	}
	if cov, fin := domain.RecordAxes(rec); cov != domain.CoverageAnalysed || fin != domain.FindingsRecordInconclusive {
		t.Errorf("axes = (%s, %s), want (Analysed, Inconclusive)", cov, fin)
	}
	if run.Counts.Affected != 0 {
		t.Errorf("an Inconclusive module was counted affected: %+v", run.Counts)
	}
	if err := (domain.VulnerabilityRecordHasher{}).VerifyContentHash(rec); err != nil {
		t.Errorf("the Inconclusive record does not verify: %v", err)
	}
	if strings.Contains(f.logs.String(), "tinygo-org") {
		t.Errorf("the TinyGo node was scanned as a module:\n%s", f.logs.String())
	}
}

func TestScanWalk_TinyGo_MixedFindingIsJudgedOnGosPackages(t *testing.T) {
	_, rec, _ := scanTinyGoWalk(t, []domain.VulnerabilityFinding{
		{ID: "GO-MIX", AffectedPackages: []string{"os", "strconv"}, Reachable: reached()},
	})
	mix := findingByID(t, rec, "GO-MIX")
	if mix.NotEstablished {
		t.Error("a finding with a Go-served package was not judged")
	}
	if !strings.Contains(mix.TinyGoNote, "judged on strconv") || !strings.Contains(mix.TinyGoNote, "TinyGo supplies os") {
		t.Errorf("mixed note = %q", mix.TinyGoNote)
	}
	if rec.OverallStatus != domain.StatusAffected {
		t.Errorf("stdlib status = %s, want Affected", rec.OverallStatus)
	}
}

// A TinyGo walk whose project directory is gone falls back to the isolated
// pool. Its stdlib findings are partitioned the same way, on a record rooted at
// the walk's target, and the shared isolated record is left as it came.
func TestScanWalk_TinyGo_IsolatedFallbackPartitionsTheSameWay(t *testing.T) {
	walk, root, std := tinyGoWasiWalk(t)
	gone := filepath.Join(t.TempDir(), "removed")
	if err := os.Mkdir(gone, 0o750); err != nil {
		t.Fatal(err)
	}
	walk.ProjectDir = gone
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	f := newProjectScanFixtureFor(t, &fakeScanner{}, walk, root)
	f.db.findings = map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{std: {
		{ID: "GO-OS", AffectedPackages: []string{"os"}},
		{ID: "GO-STRCONV", AffectedPackages: []string{"strconv"}},
		{ID: "GO-NOPKG"},
	}}

	run, err := f.walkUC.Scan(t.Context(), application.ScanWalkParams{WalkID: walk.ID, Operator: "tester"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if f.scanner.projectCalls != 0 {
		t.Fatalf("the project-rooted path ran although the directory is gone")
	}
	rec, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(t.Context(), std, "v1", walk.ID)
	if err != nil || !ok {
		t.Fatalf("stdlib record missing: ok=%v err=%v", ok, err)
	}
	if run.PerModuleResults[std] != rec.ContentHash {
		t.Errorf("the run names %s for stdlib, the partitioned record is %s", run.PerModuleResults[std], rec.ContentHash)
	}
	if !rec.Rooting.IsRootedAtPath(root.Path()) {
		t.Errorf("partitioned record rooting = %v, want the walk's target", rec.Rooting)
	}
	assertWasiPartition(t, rec)
	shared, ok, err := f.vulnStore.GetVulnerabilityRecordAt(t.Context(), std, "v1", run.Snapshot, domain.RootingIsolated)
	if err != nil || !ok {
		t.Fatalf("shared isolated record missing: ok=%v err=%v", ok, err)
	}
	for _, sf := range shared.Findings {
		if sf.NotEstablished || sf.TinyGoNote != "" {
			t.Errorf("the shared isolated record was partitioned: %+v", sf)
		}
	}
}

// assertWasiPartition holds a wasip1 stdlib record to the split: os and the
// package-level advisory not established, strconv judged, the module Affected.
func assertWasiPartition(t *testing.T, rec domain.VulnerabilityRecord) {
	t.Helper()
	if os := findingByID(t, rec, "GO-OS"); !os.NotEstablished || os.TinyGoNote != "TinyGo supplies os; Go's affected range describes Go's code" {
		t.Errorf("os = %+v", os)
	}
	if nopkg := findingByID(t, rec, "GO-NOPKG"); !nopkg.NotEstablished || nopkg.TinyGoNote != domain.NoPackageNote {
		t.Errorf("no-package = %+v", nopkg)
	}
	if sc := findingByID(t, rec, "GO-STRCONV"); sc.NotEstablished || sc.TinyGoNote != "" {
		t.Errorf("strconv was not judged: %+v", sc)
	}
	if rec.OverallStatus != domain.StatusAffected {
		t.Errorf("stdlib status = %s, want Affected on strconv", rec.OverallStatus)
	}
}

func TestScanWalk_TinyGo_RunLevelInconclusive(t *testing.T) {
	run, _, _ := scanTinyGoWalk(t, []domain.VulnerabilityFinding{{ID: "GO-OS", AffectedPackages: []string{"os"}}})
	if run.FindingsStatus != domain.FindingsInconclusive || run.OverallStatus != domain.WalkStatusInconclusive || run.Counts.Inconclusive != 1 {
		t.Errorf("run = findings %s, overall %s, counts %+v; want Inconclusive with one module", run.FindingsStatus, run.OverallStatus, run.Counts)
	}
	if err := (domain.WalkScanRunHasher{}).VerifyContentHash(run); err != nil {
		t.Errorf("the run does not verify: %v", err)
	}
}
