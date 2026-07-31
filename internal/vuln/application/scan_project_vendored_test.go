package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	application "github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// fakeVendoredClosure stands in for the reader over the vendor context's
// modules.txt parser. It reports a project as vendored and names which modules
// the tree holds, so a test can put a build-list module outside vendor/ without
// materialising a vendor tree on disk.
type fakeVendoredClosure struct {
	closure ports.VendoredClosure
	err     error
	calls   int
	// gotGoMod records the go.mod the reader was pointed at, so a test can assert
	// which project's tree was consulted rather than only that one was.
	gotGoMod string
}

func (f *fakeVendoredClosure) VendoredClosure(_ context.Context, goModPath string) (ports.VendoredClosure, error) {
	f.calls++
	f.gotGoMod = goModPath
	return f.closure, f.err
}

// vendoredFixture wires the standard project fixture with a vendored closure
// that holds depA but not depB.
func vendoredFixture(t *testing.T) (projectScanFixture, *fakeVendoredClosure) {
	t.Helper()
	scanner := &fakeScanner{}
	f := newProjectScanFixture(t, scanner)
	closure := &fakeVendoredClosure{closure: ports.VendoredClosure{
		Vendored: true,
		Listed: map[string]string{
			f.depA.Path(): f.depA.Version(),
			f.depB.Path(): f.depB.Version(),
		},
		Present: map[string]bool{f.depA.Path(): true},
	}}
	f.walkUC = f.walkUC.WithVendoredClosure(closure)
	return f, closure
}

// TestScanWalk_VendoredProject_AnalysesTheVendoredSurface asserts the whole
// point of the change: a project carrying a vendor tree is analysed from that
// tree, the scanner is told so, and every record the run writes names the
// surface its verdict was reached from. A verdict that did not name its surface
// could not be checked against the build it claims to describe.
func TestScanWalk_VendoredProject_AnalysesTheVendoredSurface(t *testing.T) {
	ctx := t.Context()
	f, closure := vendoredFixture(t)

	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{
		WalkID: f.walkID, Operator: "tester", ProjectDir: "/fake/project",
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if closure.calls != 1 {
		t.Errorf("vendored closure read %d times, want 1", closure.calls)
	}
	if !f.scanner.gotProjectVendored {
		t.Error("the scanner was not asked for the vendored surface, so the analysis read the fetched artefacts")
	}
	assertRecordSurface(t, ctx, f, f.depA, domain.AnalysisSurfaceVendored)
	assertRecordSurface(t, ctx, f, f.root, domain.AnalysisSurfaceVendored)
}

// TestScanWalk_VendoredProject_AbsentModuleIsUnscannableNotFetched asserts the
// refusal to substitute. depB is in the walk's build list but its files are not
// under vendor/, so nothing of it was in the analysed build. It is recorded as a
// coverage gap naming the absence — and, critically, the run does not fall back
// to fetching and scanning it in isolation, which would answer with findings
// about bytes the project does not compile.
func TestScanWalk_VendoredProject_AbsentModuleIsUnscannableNotFetched(t *testing.T) {
	ctx := t.Context()
	f, _ := vendoredFixture(t)

	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{
		WalkID: f.walkID, Operator: "tester", ProjectDir: "/fake/project",
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if f.scanner.scanCalls != 0 {
		t.Errorf("a module absent from vendor/ was scanned in isolation %d times; "+
			"substituting a fetched artefact reintroduces the divergence the vendored surface closes", f.scanner.scanCalls)
	}

	rec, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(ctx, f.depB, "v1", f.walkID)
	if err != nil || !ok {
		t.Fatalf("record for %s missing: ok=%v err=%v", f.depB, ok, err)
	}
	if rec.OverallStatus != domain.StatusUnscannable {
		t.Errorf("%s status = %s, want Unscannable", f.depB, rec.OverallStatus)
	}
	if rec.UnscanReason != domain.UnscanReasonAbsentFromVendor {
		t.Errorf("%s unscan reason = %q, want %q", f.depB, rec.UnscanReason, domain.UnscanReasonAbsentFromVendor)
	}
	if rec.UnscannableReason == "" {
		t.Errorf("%s carries no prose naming the absence", f.depB)
	}
	// depA is in the tree and keeps its ordinary analysed verdict, so the gap is
	// attributed to the module it belongs to rather than smeared over the build.
	assertModuleStatus(t, ctx, f.vulnStore, f.walkID, f.depA, domain.StatusClean)
}

// TestScanWalk_NoVendor_ForcesTheFetchedSurface asserts --no-vendor is a real
// override: the vendored closure is not even read, the scanner is asked for the
// fetched surface, and no module is written off as absent from a tree this run
// deliberately did not consult.
func TestScanWalk_NoVendor_ForcesTheFetchedSurface(t *testing.T) {
	ctx := t.Context()
	f, closure := vendoredFixture(t)

	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{
		WalkID: f.walkID, Operator: "tester", ProjectDir: "/fake/project", NoVendor: true,
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if closure.calls != 0 {
		t.Errorf("--no-vendor still read the vendored closure %d times", closure.calls)
	}
	if f.scanner.gotProjectVendored {
		t.Error("--no-vendor still asked the scanner for the vendored surface")
	}
	assertModuleStatus(t, ctx, f.vulnStore, f.walkID, f.depB, domain.StatusClean)
	assertRecordSurface(t, ctx, f, f.depB, domain.AnalysisSurfaceFetched)
}

// TestScanWalk_VendoredClosureUnreadable_FallsBackAndSaysSo asserts a failed
// read of the vendor tree does not silently become a vendored claim. The scan
// continues on the fetched surface — a real analysis — and every record says
// "fetched", so the run never asserts it measured the vendored bytes on the
// strength of a read that did not happen.
func TestScanWalk_VendoredClosureUnreadable_FallsBackAndSaysSo(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{}
	f := newProjectScanFixture(t, scanner)
	f.walkUC = f.walkUC.WithVendoredClosure(&fakeVendoredClosure{err: errors.New("modules.txt is unreadable")})

	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{
		WalkID: f.walkID, Operator: "tester", ProjectDir: "/fake/project",
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if scanner.gotProjectVendored {
		t.Error("an unreadable vendor tree still asked the scanner for the vendored surface")
	}
	assertRecordSurface(t, ctx, f, f.depA, domain.AnalysisSurfaceFetched)
}

// TestScanWalk_UnvendoredProject_RecordsTheFetchedSurface guards the ladder from
// the other side: a project with no vendor tree still names its surface, so a
// reader never has to tell "fetched" apart from "written before the field
// existed" by inspecting the pipeline version.
func TestScanWalk_UnvendoredProject_RecordsTheFetchedSurface(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{}
	f := newProjectScanFixture(t, scanner)
	f.walkUC = f.walkUC.WithVendoredClosure(&fakeVendoredClosure{})

	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{
		WalkID: f.walkID, Operator: "tester", ProjectDir: "/fake/project",
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	assertRecordSurface(t, ctx, f, f.depA, domain.AnalysisSurfaceFetched)
	assertRecordSurface(t, ctx, f, f.depB, domain.AnalysisSurfaceFetched)
}

func assertRecordSurface(
	t *testing.T,
	ctx context.Context,
	f projectScanFixture,
	coord coordinate.ModuleCoordinate,
	want domain.AnalysisSurface,
) {
	t.Helper()
	rec, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(ctx, coord, "v1", f.walkID)
	if err != nil || !ok {
		t.Fatalf("record for %s missing: ok=%v err=%v", coord, ok, err)
	}
	if rec.AnalysisSurface != want {
		t.Errorf("%s analysis surface = %q, want %q", coord, rec.AnalysisSurface, want)
	}
	if got := domain.RecordAnalysisSurface(rec); got != want {
		t.Errorf("%s read back as surface %q, want %q", coord, got, want)
	}
}

// TestScanWalk_VendoredProject_ReplacedModuleIsFoundUnderItsOriginalPath is the
// regression for a replaced dependency being dropped from the analysis.
//
// `go mod vendor` writes a replaced module's files under the ORIGINAL module
// path and records the replacement only on the modules.txt comment line
// (`# original v1.2.1 => replacement v1.2.4`), while the walk's resolved build
// list keys on the REPLACEMENT coordinate. Looked up directly, the replacement
// path is in neither the listed set nor the present set — so before the mapping
// was resolved, every replaced dependency was reported absent-from-vendor under
// a reason positively asserting `go mod vendor` had pruned it, while its files
// sat in the tree. Two real dependencies stopped being scanned and the record
// explained their absence with a false statement.
func TestScanWalk_VendoredProject_ReplacedModuleIsFoundUnderItsOriginalPath(t *testing.T) {
	ctx := t.Context()

	root := coordinatetest.MustNew("github.com/example/proj", coordinate.LocalVersion)
	// The build list holds the replacement coordinate; the tree holds the files
	// under the original path.
	replaced := coordinatetest.MustNew("github.com/cortezaproject/gval", "v1.2.4")
	original := "github.com/PaesslerAG/gval"
	unlisted := coordinatetest.MustNew("github.com/example/pruned", "v1.0.0")

	scanner := &fakeScanner{}
	f := newProjectScanFixtureFor(t, scanner, walkdomain.WalkRecord{
		ID:     "walk-replace",
		Target: root,
		Graph: walkdomain.Graph{
			Target: root,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: root, ResolutionSource: walkdomain.ResolutionLocalMainModule},
				{Coordinate: replaced, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
				{Coordinate: unlisted, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
			},
		},
	}, root, replaced, unlisted)

	f.walkUC = f.walkUC.WithVendoredClosure(&fakeVendoredClosure{closure: ports.VendoredClosure{
		Vendored:   true,
		Listed:     map[string]string{original: "v1.2.1"},
		Present:    map[string]bool{original: true},
		ReplacedBy: map[string]string{replaced.Path(): original},
	}})

	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{
		WalkID: f.walkID, Operator: "tester", ProjectDir: "/fake/project",
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	rec, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(ctx, replaced, "v1", f.walkID)
	if err != nil || !ok {
		t.Fatalf("record for %s missing: ok=%v err=%v", replaced, ok, err)
	}
	if rec.UnscanReason == domain.UnscanReasonAbsentFromVendor {
		t.Fatalf("the replaced module %s was reported absent from vendor/ though the tree holds it under %s: %q",
			replaced, original, rec.UnscannableReason)
	}
	if rec.OverallStatus != domain.StatusClean {
		t.Errorf("%s status = %s, want Clean — a vendored replacement is analysed like any other module", replaced, rec.OverallStatus)
	}

	// The genuine case must keep working: a module the tree neither lists nor
	// holds is still a coverage gap, and resolving replacements must not blunt it.
	pruned, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(ctx, unlisted, "v1", f.walkID)
	if err != nil || !ok {
		t.Fatalf("record for %s missing: ok=%v err=%v", unlisted, ok, err)
	}
	if pruned.UnscanReason != domain.UnscanReasonAbsentFromVendor {
		t.Errorf("%s unscan reason = %q, want %q", unlisted, pruned.UnscanReason, domain.UnscanReasonAbsentFromVendor)
	}
}
