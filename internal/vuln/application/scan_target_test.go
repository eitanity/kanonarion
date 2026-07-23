package application_test

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	application "github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// targetScanFixture wires a coordinate-keyed walk — a walk rooted at a published
// module rather than a local project — with the target and two dependency nodes.
type targetScanFixture struct {
	walkUC    *application.ScanWalkUseCase
	scanner   *fakeScanner
	vulnStore *fakeVulnStore
	db        *fakeDatabase
	target    coordinate.ModuleCoordinate
	depA      coordinate.ModuleCoordinate
	depB      coordinate.ModuleCoordinate
	walkID    string
}

func newTargetScanFixture(t *testing.T, scanner *fakeScanner, fetchedCoords ...coordinate.ModuleCoordinate) targetScanFixture {
	t.Helper()
	ctx := t.Context()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	walkID := "walk-target"

	target := coordinate.ModuleCoordinate{Path: "github.com/example/engine", Version: "v1.4.0"}
	depA := coordinate.ModuleCoordinate{Path: "gopkg.in/yaml.v3", Version: "v3.0.1"}
	depB := coordinate.ModuleCoordinate{Path: "github.com/spf13/cobra", Version: "v1.8.1"}

	walk := walkdomain.WalkRecord{
		ID:     walkID,
		Target: target,
		Graph: walkdomain.Graph{
			Target: target,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: target, ResolutionSource: walkdomain.ResolutionMVS},
				{Coordinate: depA, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
				{Coordinate: depB, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
			},
		},
	}

	walkStore := newFakeWalkStore()
	if err := walkStore.PutWalk(ctx, walk); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Source: "test", Version: "v1"}}
	clock := fixedClock{t: now}

	if len(fetchedCoords) == 0 {
		fetchedCoords = []coordinate.ModuleCoordinate{target, depA, depB}
	}
	for _, c := range fetchedCoords {
		h, _ := blobs.Put(ctx, strings.NewReader("zip-"+c.Path))
		if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
			ModulePath: c.Path, ModuleVersion: c.Version, PipelineVersion: "v1", ContentLocation: string(h),
		}); err != nil {
			t.Fatalf("PutFetchRecord %s: %v", c, err)
		}
	}

	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	walkUC := application.NewScanWalkUseCase(
		walkStore, vulnStore, moduleUC, nil, clock, "v1", slog.Default(),
	)

	return targetScanFixture{
		walkUC: walkUC, scanner: scanner, vulnStore: vulnStore, db: db,
		target: target, depA: depA, depB: depB, walkID: walkID,
	}
}

// markAllVulnerable gives every node a known advisory so the isolated pool's
// metadata pre-filter cannot short-circuit the heavy scan. A test asserting
// which path answered needs the isolated path to be observable when it runs.
func (f targetScanFixture) markAllVulnerable() {
	f.db.vulnerables = map[coordinate.ModuleCoordinate][]string{
		f.target: {"GO-TEST-0001"},
		f.depA:   {"GO-TEST-0002"},
		f.depB:   {"GO-TEST-0003"},
	}
}

// TestScanWalk_CoordinateKeyed_RootsAnalysisAtTheTarget is the regression test
// for the package-axis defect: a coordinate-keyed walk must derive its verdicts
// from one scan rooted at the walk target, where each dependency contributes
// only the packages the target's build imports, rather than from N isolated
// scans that point ./... at each dependency and load every package in it.
func TestScanWalk_CoordinateKeyed_RootsAnalysisAtTheTarget(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{targetRooted: true}
	f := newTargetScanFixture(t, scanner)

	scanner.targetFindings = map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{
		f.depA: {{ID: "GO-2024-0001", Summary: "bad", Reachable: &domain.ReachabilityResult{IsReachable: true, Confidence: domain.ConfidenceHigh}}},
	}

	run, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if scanner.targetCalls != 1 {
		t.Errorf("expected exactly 1 target-rooted scan, got %d", scanner.targetCalls)
	}
	if scanner.scanCalls != 0 {
		t.Errorf("a coordinate-keyed walk must not run isolated per-module scans once the target-rooted scan succeeds, got %d", scanner.scanCalls)
	}
	if scanner.gotTargetCoord != f.target {
		t.Errorf("analysis rooted at %v, want the walk target %v", scanner.gotTargetCoord, f.target)
	}
	if run.OverallStatus != domain.WalkStatusAffected {
		t.Errorf("OverallStatus = %v, want Affected", run.OverallStatus)
	}

	recA, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(ctx, f.depA, "v1", f.walkID)
	if err != nil || !ok {
		t.Fatalf("record for depA: ok=%v err=%v", ok, err)
	}
	if recA.OverallStatus != domain.StatusAffected || len(recA.Findings) != 1 {
		t.Errorf("depA = %v with %d findings, want Affected with 1", recA.OverallStatus, len(recA.Findings))
	}
	// Every other in-build module is analysed-and-clean, not unscanned: the one
	// analysis covered them, so silence about them is an answer.
	for _, c := range []coordinate.ModuleCoordinate{f.target, f.depB} {
		rec, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(ctx, c, "v1", f.walkID)
		if err != nil || !ok {
			t.Fatalf("record for %s: ok=%v err=%v", c, ok, err)
		}
		if rec.OverallStatus != domain.StatusClean {
			t.Errorf("%s = %v, want Clean", c, rec.OverallStatus)
		}
		if rec.UnscanReason != "" {
			t.Errorf("%s carries unscan reason %q; a module covered by the target-rooted analysis is not a coverage gap", c, rec.UnscanReason)
		}
	}
}

// TestScanWalk_CoordinateKeyed_UnimportedPackageDoesNotDecideAModuleVerdict is
// the regression test for the defect itself, stated in the terms it was measured
// in.
//
// github.com/aymerick/douceur@v0.2.0 has three packages. css imports nothing
// external; parser imports a module the walk holds; inliner imports
// github.com/PuerkitoBio/goquery, which is absent from the walk precisely
// because no consumer imports it. Scanned in isolation, `govulncheck ./...`
// loads inliner, fails to resolve goquery, and the module is recorded as a
// coverage gap — over a package the target never builds. `govulncheck ./css
// ./parser` in the same directory exits 0.
//
// The two sub-tests are an A/B on the same fake: the control reproduces the
// coverage gap on the isolated path, and the fixed path records the module as
// analysed-and-clean. Without the control, a Clean verdict here would prove
// nothing — it is also what an unconfigured fake returns.
func TestScanWalk_CoordinateKeyed_UnimportedPackageDoesNotDecideAModuleVerdict(t *testing.T) {
	// What the isolated scan of such a dependency produces: a coverage gap caused
	// by a package no consumer imports.
	isolatedGap := func(coord coordinate.ModuleCoordinate) domain.VulnerabilityRecord {
		return domain.VulnerabilityRecord{
			Coordinate:        coord,
			OverallStatus:     domain.StatusUnscannable,
			UnscanReason:      domain.UnscanReasonVersionNotInToolchain,
			UnscannableReason: "no required module provides package github.com/PuerkitoBio/goquery",
		}
	}

	t.Run("control: the isolated path records the coverage gap", func(t *testing.T) {
		ctx := t.Context()
		// targetRooted false: the target-rooted scan reports a fault, so the walk
		// falls back to the isolated path this ticket describes.
		scanner := &fakeScanner{}
		f := newTargetScanFixture(t, scanner)
		scanner.results = map[string]domain.VulnerabilityRecord{
			f.depA.String(): isolatedGap(f.depA),
		}

		if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester", Force: true}); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		rec, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(ctx, f.depA, "v1", f.walkID)
		if err != nil || !ok {
			t.Fatalf("record for depA: ok=%v err=%v", ok, err)
		}
		if rec.OverallStatus != domain.StatusUnscannable {
			t.Fatalf("control did not reproduce the defect: depA = %v, want Unscannable", rec.OverallStatus)
		}
		if rec.UnscanReason != domain.UnscanReasonVersionNotInToolchain {
			t.Fatalf("control unscan reason = %q, want %q", rec.UnscanReason, domain.UnscanReasonVersionNotInToolchain)
		}
	})

	t.Run("fixed: the target-rooted path never loads the package", func(t *testing.T) {
		ctx := t.Context()
		scanner := &fakeScanner{targetRooted: true}
		f := newTargetScanFixture(t, scanner)
		// Configured identically: were the isolated path consulted, the gap above
		// is what it would contribute.
		scanner.results = map[string]domain.VulnerabilityRecord{
			f.depA.String(): isolatedGap(f.depA),
		}

		run, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester", Force: true})
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		rec, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(ctx, f.depA, "v1", f.walkID)
		if err != nil || !ok {
			t.Fatalf("record for depA: ok=%v err=%v", ok, err)
		}
		if rec.OverallStatus == domain.StatusUnscannable {
			t.Errorf("depA is still a coverage gap (%s): a package no consumer imports decided the module's verdict",
				rec.UnscannableReason)
		}
		if rec.UnscanReason != "" {
			t.Errorf("depA carries unscan reason %q, want none: the target's build never loads that package", rec.UnscanReason)
		}
		if rec.OverallStatus != domain.StatusClean {
			t.Errorf("depA = %v, want Clean", rec.OverallStatus)
		}
		if run.OverallStatus == domain.WalkStatusPartial {
			t.Error("the walk still reports Partial coverage over a package the target never builds")
		}
	})
}

// TestScanWalk_CoordinateKeyed_TargetAdvisoriesAreMatchedByCoordinate covers the
// one thing the target-rooted analysis structurally cannot do for itself: the
// target is that analysis's main module, and a main module has no version, so an
// advisory about the target can never match by version range. The coordinate
// match has to supply it.
func TestScanWalk_CoordinateKeyed_TargetAdvisoriesAreMatchedByCoordinate(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{targetRooted: true}
	f := newTargetScanFixture(t, scanner)

	// The analysis reports nothing at all, exactly as it would for its own main
	// module, while the pinned snapshot knows the target is affected.
	f.db.findings = map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{
		f.target: {{ID: "GO-2024-3205", Summary: "infinite loop"}},
	}

	run, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	rec, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(ctx, f.target, "v1", f.walkID)
	if err != nil || !ok {
		t.Fatalf("record for target: ok=%v err=%v", ok, err)
	}
	if rec.OverallStatus != domain.StatusAffected {
		t.Fatalf("target = %v, want Affected: a successful target-rooted scan must not hide the target's own advisory", rec.OverallStatus)
	}
	if len(rec.Findings) != 1 || rec.Findings[0].ID != "GO-2024-3205" {
		t.Errorf("target findings = %+v, want GO-2024-3205", rec.Findings)
	}
	if run.OverallStatus != domain.WalkStatusAffected {
		t.Errorf("OverallStatus = %v, want Affected", run.OverallStatus)
	}
}

// TestScanWalk_CoordinateKeyed_FallsBackWhenTargetCannotBeAnalysed asserts the
// walk still gets per-module verdicts when the target does not build as a whole.
// Filling a fault across every module instead would turn one module's build
// failure into a walk-wide coverage gap.
func TestScanWalk_CoordinateKeyed_FallsBackWhenTargetCannotBeAnalysed(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{
		targetRooted: true,
		targetStatus: domain.StatusScanFailed,
		targetReason: "target does not build",
	}
	f := newTargetScanFixture(t, scanner)
	// Every node carries a known advisory so the isolated pool's metadata
	// pre-filter cannot skip the heavy scan: the assertion below is about which
	// path answered, and a pre-filtered Clean would hide that.
	f.markAllVulnerable()

	run, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if scanner.targetCalls != 1 {
		t.Errorf("target-rooted scan attempts = %d, want 1", scanner.targetCalls)
	}
	if scanner.scanCalls != 3 {
		t.Errorf("isolated scans = %d, want one per node (3) after the target-rooted scan could not run", scanner.scanCalls)
	}
	if run.OverallStatus == domain.WalkStatusFailed {
		t.Errorf("a target that cannot be analysed as a whole must not fail the whole walk; got %v", run.OverallStatus)
	}
}

// TestScanWalk_CoordinateKeyed_FallsBackWhenTargetSourceIsAbsent covers a
// shallow walk, which holds no zip for the target: there is nothing to root the
// analysis at, so the isolated path answers instead.
func TestScanWalk_CoordinateKeyed_FallsBackWhenTargetSourceIsAbsent(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{targetRooted: true}
	depA := coordinate.ModuleCoordinate{Path: "gopkg.in/yaml.v3", Version: "v3.0.1"}
	depB := coordinate.ModuleCoordinate{Path: "github.com/spf13/cobra", Version: "v1.8.1"}
	f := newTargetScanFixture(t, scanner, depA, depB) // target deliberately not fetched
	f.markAllVulnerable()

	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester"}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if scanner.targetCalls != 0 {
		t.Errorf("target-rooted scan was attempted with no target source; calls = %d", scanner.targetCalls)
	}
	if scanner.scanCalls == 0 {
		t.Error("expected the isolated path to answer when the target's source is absent")
	}
}

// TestScanWalk_CoordinateKeyed_ThreadsTheWalkModCache asserts the target-rooted
// scan resolves against the versions the walk fetched. Without the walk's
// GOMODCACHE the target would re-resolve against the network and could analyse a
// dependency graph the walk never recorded.
func TestScanWalk_CoordinateKeyed_ThreadsTheWalkModCache(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{targetRooted: true}
	f := newTargetScanFixture(t, scanner)

	modCache := t.TempDir()
	f.walkUC = f.walkUC.WithRealModcache(modCache)

	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester"}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if scanner.gotTargetCache != modCache {
		t.Errorf("target-rooted scan GOMODCACHE = %q, want the walk's cache %q", scanner.gotTargetCache, modCache)
	}
}

// TestScanWalk_LocalProjectWalk_StillTakesTheProjectRootedPath guards the
// dispatch: a walk rooted at a local project has a real working tree with real
// entry points and must keep using it.
func TestScanWalk_LocalProjectWalk_StillTakesTheProjectRootedPath(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{targetRooted: true}
	f := newProjectScanFixture(t, scanner)

	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{
		WalkID: f.walkID, Operator: "tester", ProjectDir: "/fake/project",
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if scanner.projectCalls != 1 {
		t.Errorf("project-rooted scans = %d, want 1", scanner.projectCalls)
	}
	if scanner.targetCalls != 0 {
		t.Errorf("a local project walk must not take the target-rooted path; calls = %d", scanner.targetCalls)
	}
}
