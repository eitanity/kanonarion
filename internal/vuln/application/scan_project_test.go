package application_test

import (
	"context"
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

// projectScanFixture wires a local-rooted (project) walk with a root and two
// dependency nodes, returning the assembled use case and its fake scanner so a
// test can drive the project-rooted path and inspect the verdicts it derives.
type projectScanFixture struct {
	walkUC    *application.ScanWalkUseCase
	scanner   *fakeScanner
	vulnStore *fakeVulnStore
	db        *fakeDatabase
	root      coordinate.ModuleCoordinate
	depA      coordinate.ModuleCoordinate
	depB      coordinate.ModuleCoordinate
	walkID    string
}

func newProjectScanFixture(t *testing.T, scanner *fakeScanner) projectScanFixture {
	t.Helper()
	ctx := t.Context()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	walkID := "walk-project"

	root := coordinate.ModuleCoordinate{Path: "github.com/example/proj", Version: coordinate.LocalVersion}
	depA := coordinate.ModuleCoordinate{Path: "gopkg.in/yaml.v3", Version: "v3.0.1"}
	depB := coordinate.ModuleCoordinate{Path: "github.com/spf13/cobra", Version: "v1.8.1"}

	walk := walkdomain.WalkRecord{
		ID:     walkID,
		Target: root,
		Graph: walkdomain.Graph{
			Target: root,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: root, ResolutionSource: walkdomain.ResolutionLocalMainModule},
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

	// Every in-build node needs a fetch record so the root source (and, on the
	// isolated path, each dependency) can be located.
	for _, c := range []coordinate.ModuleCoordinate{root, depA, depB} {
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

	return projectScanFixture{
		walkUC: walkUC, scanner: scanner, vulnStore: vulnStore, db: db,
		root: root, depA: depA, depB: depB, walkID: walkID,
	}
}

// TestScanWalk_ProjectRooted_DerivesPerModuleVerdicts asserts that a project
// walk takes the single project-rooted scan (not N isolated per-module scans),
// attributes findings to their owning module, and marks every other in-build
// module clean.
func TestScanWalk_ProjectRooted_DerivesPerModuleVerdicts(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{}
	f := newProjectScanFixture(t, scanner)

	// The project-rooted scan attributes one finding to depA.
	scanner.projectFindings = map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{
		f.depA: {{ID: "GO-2024-0001", Summary: "bad", Reachable: &domain.ReachabilityResult{IsReachable: true, Confidence: domain.ConfidenceHigh}}},
	}

	run, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester", ProjectDir: "/fake/project"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if scanner.projectCalls != 1 {
		t.Errorf("expected exactly 1 project-rooted scan, got %d", scanner.projectCalls)
	}
	if scanner.scanCalls != 0 {
		t.Errorf("project walk must not run isolated per-module scans, got %d", scanner.scanCalls)
	}
	if run.OverallStatus != domain.WalkStatusAffected {
		t.Errorf("overall status = %s, want Affected", run.OverallStatus)
	}

	assertModuleStatus(t, ctx, f.vulnStore, f.walkID, f.depA, domain.StatusAffected)
	assertModuleStatus(t, ctx, f.vulnStore, f.walkID, f.depB, domain.StatusClean)
	assertModuleStatus(t, ctx, f.vulnStore, f.walkID, f.root, domain.StatusClean)
}

// TestScanWalk_ProjectRooted_PrunedTestDepScansClean is the ADR-0058 regression:
// a dependency whose *isolated* build would re-add a pruned test dependency and
// report a version-not-in-toolchain Unscannable must instead read Clean on the
// project path, and the run must not degrade to Partial. The fake's per-module
// Scan is primed with that Unscannable verdict, so this test fails on the old
// isolated-scan behaviour and passes only when the project-rooted path is taken.
func TestScanWalk_ProjectRooted_PrunedTestDepScansClean(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{}
	f := newProjectScanFixture(t, scanner)

	// Prime the isolated path to fail exactly as the real hermetic scan does for
	// yaml.v3 (re-adds check.v1, resolves a version the project never builds).
	scanner.results = map[string]domain.VulnerabilityRecord{
		f.depA.String(): {
			Coordinate:    f.depA,
			OverallStatus: domain.StatusUnscannable,
			UnscanReason:  domain.UnscanReasonVersionNotInToolchain,
		},
	}
	// The project-rooted scan finds nothing: the project builds cleanly.
	scanner.projectFindings = nil

	// Force=true defeats the metadata short-circuit, so without the project-rooted
	// branch the isolated path would consult the primed Unscannable and degrade to
	// Partial. The project path ignores Force and reads the live tree clean.
	run, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester", ProjectDir: "/fake/project", Force: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if scanner.projectCalls != 1 || scanner.scanCalls != 0 {
		t.Fatalf("expected the project-rooted path (project=1, isolated=0), got project=%d isolated=%d", scanner.projectCalls, scanner.scanCalls)
	}
	if run.OverallStatus != domain.WalkStatusAllClean {
		t.Errorf("overall status = %s, want AllClean (no Partial from a self-inflicted gap)", run.OverallStatus)
	}
	for _, c := range []coordinate.ModuleCoordinate{f.root, f.depA, f.depB} {
		rec, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(ctx, c, "v1", f.walkID)
		if err != nil || !ok {
			t.Fatalf("record for %s missing: ok=%v err=%v", c, ok, err)
		}
		if rec.OverallStatus != domain.StatusClean {
			t.Errorf("%s status = %s, want Clean", c, rec.OverallStatus)
		}
		if rec.UnscanReason == domain.UnscanReasonVersionNotInToolchain {
			t.Errorf("%s must not carry version-not-in-toolchain on the project path", c)
		}
	}
}

// TestScanWalk_ProjectRooted_GenuineFaultSurfaces asserts that a real fault of
// the project-rooted scan (a build break, OOM, no go.mod) surfaces honestly as
// Unscannable across the build rather than being masked as clean.
func TestScanWalk_ProjectRooted_GenuineFaultSurfaces(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{projectStatus: domain.StatusUnscannable, projectReason: "no go.mod found in the project source"}
	f := newProjectScanFixture(t, scanner)

	run, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester", ProjectDir: "/fake/project"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if run.OverallStatus == domain.WalkStatusAllClean {
		t.Errorf("a genuine project scan fault must not read as AllClean")
	}
	rec, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(ctx, f.depA, "v1", f.walkID)
	if err != nil || !ok {
		t.Fatalf("record for %s missing: ok=%v err=%v", f.depA, ok, err)
	}
	if rec.OverallStatus != domain.StatusUnscannable {
		t.Errorf("%s status = %s, want Unscannable on a genuine fault", f.depA, rec.OverallStatus)
	}
	if rec.UnscannableReason == "" {
		t.Errorf("a fault record must carry a diagnostic reason, never a silent absence")
	}
}

// stdlibProjectFixture wires a project walk whose graph carries the synthetic
// standard-library node alongside a root and one dependency, so a test can drive
// the project-rooted path and inspect the verdict derived for stdlib.
type stdlibProjectFixture struct {
	walkUC    *application.ScanWalkUseCase
	scanner   *fakeScanner
	vulnStore *fakeVulnStore
	std       coordinate.ModuleCoordinate
	walkID    string
}

func newStdlibProjectFixture(t *testing.T, scanner *fakeScanner) stdlibProjectFixture {
	t.Helper()
	ctx := t.Context()
	now := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	walkID := "walk-stdlib"

	root := coordinate.ModuleCoordinate{Path: "github.com/example/proj", Version: coordinate.LocalVersion}
	dep := coordinate.ModuleCoordinate{Path: "gopkg.in/yaml.v3", Version: "v3.0.1"}
	// The stdlib node carries a concrete toolchain version; the grouped parse
	// attributes its findings to the version-less {stdlib, ""} key.
	std := coordinate.ModuleCoordinate{Path: domain.StdlibModulePath, Version: "v1.26.4"}

	walk := walkdomain.WalkRecord{
		ID:     walkID,
		Target: root,
		Graph: walkdomain.Graph{
			Target: root,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: root, ResolutionSource: walkdomain.ResolutionLocalMainModule},
				{Coordinate: dep, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
				{Coordinate: std, DirectDependency: true, ResolutionSource: walkdomain.ResolutionStdlib},
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

	// Root and dep need a fetch record; stdlib is never fetched.
	for _, c := range []coordinate.ModuleCoordinate{root, dep} {
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

	return stdlibProjectFixture{walkUC: walkUC, scanner: scanner, vulnStore: vulnStore, std: std, walkID: walkID}
}

// TestScanWalk_ProjectRooted_StdlibCarriesReachability asserts that
// a stdlib advisory reached from the project's call graph is attributed to the
// synthetic stdlib node carrying Reachable and AffectedSymbols — call-graph
// analysed against the build toolchain, not reachability-independent metadata.
func TestScanWalk_ProjectRooted_StdlibCarriesReachability(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{}
	f := newStdlibProjectFixture(t, scanner)

	// The project-rooted scan reaches a stdlib symbol; the grouped parse files it
	// under the version-less {stdlib, ""} key with reachability populated.
	scanner.projectFindings = map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{
		{Path: domain.StdlibModulePath}: {{
			ID:              "GO-2026-4970",
			Summary:         "Root escape via symlink in os",
			AffectedSymbols: []string{"Root.Lstat"},
			Reachable:       &domain.ReachabilityResult{IsReachable: true, Confidence: domain.ConfidenceHigh},
		}},
	}

	run, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester", ProjectDir: "/fake/project"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if scanner.scanCalls != 0 {
		t.Errorf("stdlib must never be built in isolation, got %d isolated scans", scanner.scanCalls)
	}
	if run.OverallStatus != domain.WalkStatusAffected {
		t.Errorf("overall status = %s, want Affected", run.OverallStatus)
	}

	rec, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(ctx, f.std, "v1", f.walkID)
	if err != nil || !ok {
		t.Fatalf("stdlib record missing: ok=%v err=%v", ok, err)
	}
	if rec.OverallStatus != domain.StatusAffected {
		t.Fatalf("stdlib status = %s, want Affected", rec.OverallStatus)
	}
	if len(rec.Findings) != 1 {
		t.Fatalf("stdlib findings = %d, want 1", len(rec.Findings))
	}
	got := rec.Findings[0]
	if got.Reachable == nil {
		t.Fatalf("stdlib finding has nil Reachable; want a populated reachability verdict, not metadata-only")
	}
	if !got.Reachable.IsReachable {
		t.Errorf("stdlib finding IsReachable = false, want true")
	}
	if len(got.AffectedSymbols) == 0 {
		t.Errorf("stdlib finding has no AffectedSymbols; want the reached symbol recorded")
	}
}

// TestScanWalk_ProjectRooted_StdlibUnreachableIsClean verifies that when the
// project reaches no stdlib symbol, the stdlib node reads Clean — analysed and
// not reachable — consistent with how a fetched module with no reachable finding
// is reported, rather than surfacing every toolchain advisory as Affected.
func TestScanWalk_ProjectRooted_StdlibUnreachableIsClean(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{}
	f := newStdlibProjectFixture(t, scanner)

	// A dependency has a reachable finding, but nothing in stdlib is reached.
	scanner.projectFindings = map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{
		{Path: "gopkg.in/yaml.v3", Version: "v3.0.1"}: {{
			ID:        "GO-2024-0001",
			Reachable: &domain.ReachabilityResult{IsReachable: true, Confidence: domain.ConfidenceHigh},
		}},
	}

	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester", ProjectDir: "/fake/project"}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	rec, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(ctx, f.std, "v1", f.walkID)
	if err != nil || !ok {
		t.Fatalf("stdlib record missing: ok=%v err=%v", ok, err)
	}
	if rec.OverallStatus != domain.StatusClean {
		t.Errorf("stdlib status = %s, want Clean when no stdlib symbol is reached", rec.OverallStatus)
	}
	if len(rec.Findings) != 0 {
		t.Errorf("stdlib findings = %d, want 0 when unreachable", len(rec.Findings))
	}
}

func assertModuleStatus(t *testing.T, ctx context.Context, vs *fakeVulnStore, walkID string, coord coordinate.ModuleCoordinate, want domain.VulnerabilityStatus) {
	t.Helper()
	rec, ok, err := vs.GetLatestVulnerabilityRecordForWalk(ctx, coord, "v1", walkID)
	if err != nil || !ok {
		t.Fatalf("record for %s missing: ok=%v err=%v", coord, ok, err)
	}
	if rec.OverallStatus != want {
		t.Errorf("%s status = %s, want %s", coord, rec.OverallStatus, want)
	}
}
