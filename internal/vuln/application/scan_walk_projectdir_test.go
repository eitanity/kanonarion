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

	if got := f.logs.String(); !strings.Contains(got, dir) || !strings.Contains(got, "no longer readable") {
		t.Errorf("the run does not name the absent directory as the reason it analysed the fetched artefacts; logs:\n%s", got)
	}
	if got := f.logs.String(); !strings.Contains(got, "scanning each module in isolation") {
		t.Errorf("the run does not say what it did instead of rooting at the project; logs:\n%s", got)
	}
}

// TestScanWalk_ByWalkID_UnvendoredDirectoryIsStillRootedAtTheProject is the
// headline regression. A project that carries no vendor tree — the ordinary
// case — must still be scanned rooted at its own build when the walk is named
// by id, not re-derived module by module. The isolated route is where the
// standard library goes metadata-only and where a dependency whose isolated
// build re-selects a version the project never chose is reported as an
// unanalysed coverage gap, so a run that took it reports Partial for a walk the
// same tool reports Complete when the directory is spelled out on the command
// line. Which surface the project compiles from decides which SOURCE is read,
// never whether the project's build is the frame.
func TestScanWalk_ByWalkID_UnvendoredDirectoryIsStillRootedAtTheProject(t *testing.T) {
	ctx := t.Context()
	f, closure, dir := recordedProjectFixture(t)

	if err := os.RemoveAll(filepath.Join(dir, "vendor")); err != nil {
		t.Fatalf("removing the vendor tree: %v", err)
	}
	closure.closure = ports.VendoredClosure{}

	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{
		WalkID: f.walkID, Operator: "tester",
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if f.scanner.projectCalls != 1 {
		t.Fatalf("project-rooted scans = %d, want 1: an unvendored project walk was re-derived module by module", f.scanner.projectCalls)
	}
	if f.scanner.gotProjectDir != dir {
		t.Errorf("project scan ran in %q, want the directory the walk was taken from (%q)", f.scanner.gotProjectDir, dir)
	}
	if f.scanner.gotProjectVendored {
		t.Error("the scanner was asked for a vendored surface a project with no vendor tree cannot supply")
	}
	assertRecordSurface(t, ctx, f, f.depA, domain.AnalysisSurfaceFetched)
}

// TestScanWalk_ByWalkID_NonProjectWalkStaysIsolated is the other side of the
// same decision. A walk of a published coordinate has no working tree to be
// rooted at; the isolated per-module route is the honest one there, and nothing
// in the project-rooted path may be reached for it.
func TestScanWalk_ByWalkID_NonProjectWalkStaysIsolated(t *testing.T) {
	ctx := t.Context()

	target := coordinatetest.MustNew("github.com/example/lib", "v1.2.3")
	dep := coordinatetest.MustNew("gopkg.in/yaml.v3", "v3.0.1")
	scanner := &fakeScanner{}
	f := newProjectScanFixtureFor(t, scanner, walkdomain.WalkRecord{
		ID:     "walk-coordinate",
		Target: target,
		Graph: walkdomain.Graph{
			Target: target,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: target, ResolutionSource: walkdomain.ResolutionMVS},
				{Coordinate: dep, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
			},
		},
	}, target, dep)
	f.walkUC = f.walkUC.WithVendoredClosure(&fakeVendoredClosure{})

	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{
		WalkID: f.walkID, Operator: "tester",
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if f.scanner.projectCalls != 0 {
		t.Errorf("a walk of a published coordinate was scanned as a project (%d calls, dir %q)",
			f.scanner.projectCalls, f.scanner.gotProjectDir)
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

// TestScanWalk_ByWalkID_NoVendorKeepsTheProjectFrameOnTheFetchedSurface asserts
// what --no-vendor selects and what it does not. It names a surface — analyse
// the artefacts kanonarion fetched, not the tree the project compiles — so the
// vendored closure is never read and the scanner is never asked for the vendored
// source. It does not name a frame: the project's own build is still what the
// run derives its verdicts from, because answering a narrower question about
// every dependency in isolation is not what the operator asked for.
func TestScanWalk_ByWalkID_NoVendorKeepsTheProjectFrameOnTheFetchedSurface(t *testing.T) {
	ctx := t.Context()
	f, closure, dir := recordedProjectFixture(t)

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
	if f.scanner.gotProjectDir != dir {
		t.Errorf("project scan ran in %q, want the directory the walk was taken from (%q): --no-vendor changed the frame, not only the surface", f.scanner.gotProjectDir, dir)
	}
	assertRecordSurface(t, ctx, f, f.depA, domain.AnalysisSurfaceFetched)
}
