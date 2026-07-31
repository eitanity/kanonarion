package application_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	application "github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// recordedProjectFixture wires a project walk that remembers the directory it
// was taken from, with a real vendor/modules.txt on disk under that directory —
// the file the scan stats to decide whether the recorded directory still leads
// anywhere. The vendored closure reports both dependencies present, so nothing
// in these tests turns on the absent-from-vendor path.
//
// It returns the fixture, the closure reader and the directory, so a test can
// delete the directory and re-scan the same walk.
func recordedProjectFixture(t *testing.T) (projectScanFixture, *fakeVendoredClosure, string) {
	t.Helper()

	dir := filepath.Join(t.TempDir(), "proj")
	if err := os.MkdirAll(filepath.Join(dir, "vendor"), 0o750); err != nil {
		t.Fatalf("creating vendor dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vendor", "modules.txt"), []byte("# gopkg.in/yaml.v3 v3.0.1\n"), 0o600); err != nil {
		t.Fatalf("writing modules.txt: %v", err)
	}

	root := coordinatetest.MustNew("github.com/example/proj", coordinate.LocalVersion)
	depA := coordinatetest.MustNew("gopkg.in/yaml.v3", "v3.0.1")
	depB := coordinatetest.MustNew("github.com/spf13/cobra", "v1.8.1")

	scanner := &fakeScanner{}
	f := newProjectScanFixtureFor(t, scanner, walkdomain.WalkRecord{
		ID:     "walk-project",
		Target: root,
		Graph: walkdomain.Graph{
			Target: root,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: root, ResolutionSource: walkdomain.ResolutionLocalMainModule},
				{Coordinate: depA, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
				{Coordinate: depB, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
			},
		},
		// The fact under test: the walk names the tree it was rooted at.
		ProjectDir: dir,
	}, root, depA, depB)
	f.depA, f.depB = depA, depB

	closure := &fakeVendoredClosure{closure: ports.VendoredClosure{
		Vendored: true,
		Listed: map[string]string{
			depA.Path(): depA.Version(),
			depB.Path(): depB.Version(),
		},
		Present: map[string]bool{depA.Path(): true, depB.Path(): true},
	}}
	f.walkUC = f.walkUC.WithVendoredClosure(closure)
	return f, closure, dir
}

// TestScanWalk_ByWalkID_ReachesTheRecordedVendoredTree is the regression: a walk
// taken from a vendored project, re-scanned by id with no project directory
// supplied, must analyse the same vendored tree the original run did. Before the
// walk recorded its root, this spelling of the command could only reach the
// fetched artefacts — one walk, two answers, decided by how the operator typed
// the command.
func TestScanWalk_ByWalkID_ReachesTheRecordedVendoredTree(t *testing.T) {
	ctx := t.Context()
	f, closure, dir := recordedProjectFixture(t)

	// No ProjectDir: this is `vuln-scan <walk-id>`, which has none to give.
	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{
		WalkID: f.walkID, Operator: "tester",
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if closure.calls != 1 {
		t.Fatalf("vendored closure read %d times, want 1: the walk's directory was not reached", closure.calls)
	}
	if want := filepath.Join(dir, "go.mod"); closure.gotGoMod != want {
		t.Errorf("vendored closure read %q, want %q", closure.gotGoMod, want)
	}
	if f.scanner.gotProjectDir != dir {
		t.Errorf("project scan ran in %q, want the directory the walk was taken from (%q)", f.scanner.gotProjectDir, dir)
	}
	if !f.scanner.gotProjectVendored {
		t.Error("the scanner was not asked for the vendored surface, so a re-scan by id still measured the fetched artefacts")
	}
	assertRecordSurface(t, ctx, f, f.depA, domain.AnalysisSurfaceVendored)
	assertRecordSurface(t, ctx, f, f.root, domain.AnalysisSurfaceVendored)
}

// TestScanWalk_ByWalkID_RemovedDirectoryDegradesToFetched is the other
// direction: the recorded directory is provenance, not an oracle. A checkout
// that has been moved or deleted must not make a stored walk unscannable — the
// scan proceeds on the fetched surface, every record says so, and the reason
// names the directory that is gone.
func TestScanWalk_ByWalkID_RemovedDirectoryDegradesToFetched(t *testing.T) {
	ctx := t.Context()
	f, closure, dir := recordedProjectFixture(t)

	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("removing the project directory: %v", err)
	}

	run, err := f.walkUC.Scan(ctx, application.ScanWalkParams{
		WalkID: f.walkID, Operator: "tester",
	})
	if err != nil {
		t.Fatalf("a walk whose directory is gone must still scan, got: %v", err)
	}

	if closure.calls != 0 {
		t.Errorf("the vendored closure of a directory that no longer exists was read %d times", closure.calls)
	}
	if f.scanner.projectCalls != 0 {
		t.Errorf("a project-rooted scan ran in a directory that no longer exists (%d calls)", f.scanner.projectCalls)
	}
	if run.OverallStatus == domain.WalkStatusFailed {
		t.Errorf("run status = %s: a moved checkout must not fail the scan", run.OverallStatus)
	}
	assertRecordSurface(t, ctx, f, f.depA, domain.AnalysisSurfaceFetched)

	if got := f.logs.String(); !strings.Contains(got, dir) || !strings.Contains(got, "no longer available") {
		t.Errorf("the run does not name the absent directory as the reason it analysed the fetched artefacts; logs:\n%s", got)
	}
}

// TestScanWalk_ByWalkID_UnvendoredDirectoryStaysOnFetched covers the second
// degradation the field allows: the directory is still there but no longer holds
// a vendor tree. There is no vendored surface to reach, so the scan stays
// exactly where it was before the directory was recorded, and says why.
func TestScanWalk_ByWalkID_UnvendoredDirectoryStaysOnFetched(t *testing.T) {
	ctx := t.Context()
	f, closure, dir := recordedProjectFixture(t)

	if err := os.RemoveAll(filepath.Join(dir, "vendor")); err != nil {
		t.Fatalf("removing the vendor tree: %v", err)
	}

	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{
		WalkID: f.walkID, Operator: "tester",
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if closure.calls != 0 {
		t.Errorf("a directory with no vendor tree was still read as a vendored closure %d times", closure.calls)
	}
	assertRecordSurface(t, ctx, f, f.depA, domain.AnalysisSurfaceFetched)
	if got := f.logs.String(); !strings.Contains(got, dir) || !strings.Contains(got, "no vendored tree") {
		t.Errorf("the run does not say why it left the recorded directory alone; logs:\n%s", got)
	}
}

// TestScanWalk_SuppliedProjectDirWinsOverTheRecordedOne asserts the caller's
// directory is never overridden by the walk's memory of an older one. `--gomod`
// names the tree the operator means; a stored path from a previous run must not
// redirect the analysis somewhere else.
func TestScanWalk_SuppliedProjectDirWinsOverTheRecordedOne(t *testing.T) {
	ctx := t.Context()
	f, _, _ := recordedProjectFixture(t)

	supplied := t.TempDir()
	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{
		WalkID: f.walkID, Operator: "tester", ProjectDir: supplied,
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if f.scanner.gotProjectDir != supplied {
		t.Errorf("project scan ran in %q, want the caller's directory %q", f.scanner.gotProjectDir, supplied)
	}
}

// TestScanWalk_ByWalkID_NoVendorLeavesTheRecordedDirectoryAlone asserts
// --no-vendor is honoured before the directory is reached for, not merely
// afterwards. The operator has asked for the fetched surface, and the recorded
// directory is only ever adopted to reach the vendored one.
func TestScanWalk_ByWalkID_NoVendorLeavesTheRecordedDirectoryAlone(t *testing.T) {
	ctx := t.Context()
	f, closure, _ := recordedProjectFixture(t)

	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{
		WalkID: f.walkID, Operator: "tester", NoVendor: true,
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if closure.calls != 0 {
		t.Errorf("--no-vendor still read the vendored closure %d times", closure.calls)
	}
	if f.scanner.gotProjectVendored {
		t.Error("--no-vendor still asked the scanner for the vendored surface")
	}
	assertRecordSurface(t, ctx, f, f.depA, domain.AnalysisSurfaceFetched)
}
