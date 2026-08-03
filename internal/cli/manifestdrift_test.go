package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// driftWalk builds a project walk record: a local root, the synthetic stdlib
// node every project walk carries, and the given dependency nodes.
func driftWalk(id string, nodes ...walkdomain.GraphNode) walkdomain.WalkRecord {
	target := coordinatetest.MustNew("example.com/app", coordinate.LocalVersion)
	all := []walkdomain.GraphNode{
		{Coordinate: target, ResolutionSource: walkdomain.ResolutionLocalMainModule},
		{Coordinate: coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.5"), ResolutionSource: walkdomain.ResolutionStdlib},
	}
	all = append(all, nodes...)
	return walkdomain.WalkRecord{ID: id, Target: target, Graph: walkdomain.Graph{Nodes: all}}
}

func depNode(coord string) walkdomain.GraphNode {
	c, err := coordinate.ParseModuleCoordinate(coord)
	if err != nil {
		panic(err)
	}
	return walkdomain.GraphNode{Coordinate: c, ResolutionSource: walkdomain.ResolutionMVS}
}

// TestDriftAgainstWalk_VersionBumpDrifts is the reproduction, reduced: a go.mod
// whose only edit is a patch bump resolves to a set the stored walk does not
// describe, and the comparison has to say so. The walk lookup itself cannot —
// it keys on the project's module path, which the bump does not touch.
//
// A comparison that matched on module path alone passes every other test in
// this file and fails this one: the path is in both sets, and only the version
// moved.
func TestDriftAgainstWalk_VersionBumpDrifts(t *testing.T) {
	rec := driftWalk("walk-old", depNode("github.com/golang-jwt/jwt/v4@v4.5.1"))
	resolved := []string{"github.com/golang-jwt/jwt/v4@v4.5.2"}

	d := driftAgainstWalk(resolved, rec)

	if !d.drifted() {
		t.Fatalf("a version bump read as identical: %+v", d)
	}
	if len(d.changed) != 1 || !strings.Contains(d.changed[0], "v4.5.1 -> v4.5.2") {
		t.Errorf("changed = %v, want the bump named", d.changed)
	}
	if len(d.added) != 0 || len(d.removed) != 0 {
		t.Errorf("a bump reported as add/remove: added=%v removed=%v", d.added, d.removed)
	}
	reason := d.reason("walk-old")
	for _, want := range []string{"walk-old", "github.com/golang-jwt/jwt/v4 v4.5.1 -> v4.5.2"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason %q does not name %q", reason, want)
		}
	}
}

// The paired control: the same walk against the manifest it was taken from is
// identical, so the warm serve survives the check. This one passes whether the
// comparison keys on path or on path and version — which is what makes it a
// control rather than a second copy of the test above.
func TestDriftAgainstWalk_UnchangedManifestIsIdentical(t *testing.T) {
	rec := driftWalk("walk-old",
		depNode("github.com/golang-jwt/jwt/v4@v4.5.1"),
		depNode("golang.org/x/net@v0.33.0"),
	)
	resolved := []string{"github.com/golang-jwt/jwt/v4@v4.5.1", "golang.org/x/net@v0.33.0"}

	d := driftAgainstWalk(resolved, rec)

	if d.drifted() {
		t.Fatalf("an unchanged manifest read as drifted: %+v", d)
	}
	if d.resolved != 2 || d.walked != 2 {
		t.Errorf("counts = resolved %d / walked %d, want 2/2", d.resolved, d.walked)
	}
	if got := d.agreement("walk-old"); !strings.Contains(got, "2 module versions") || !strings.Contains(got, "walk-old") {
		t.Errorf("agreement %q does not state the basis it checked", got)
	}
}

// A dependency added to the manifest, and one dropped from it, are both drift:
// the stored run answers for neither build.
func TestDriftAgainstWalk_AddedAndRemovedModulesDrift(t *testing.T) {
	rec := driftWalk("walk-old", depNode("golang.org/x/net@v0.33.0"))

	added := driftAgainstWalk([]string{"golang.org/x/net@v0.33.0", "golang.org/x/text@v0.21.0"}, rec)
	if len(added.added) != 1 || added.added[0] != "golang.org/x/text@v0.21.0" {
		t.Errorf("added = %v, want the new module named", added.added)
	}

	removed := driftAgainstWalk(nil, rec)
	if len(removed.removed) != 1 || removed.removed[0] != "golang.org/x/net@v0.33.0" {
		t.Errorf("removed = %v, want the dropped module named", removed.removed)
	}
}

// A replace directive must not read as drift. The toolchain reports the require
// entry, the walk records the replacement it actually fetched, and comparing
// those two coordinates directly would report drift on every run of every
// project that replaces anything — corteza replaces two modules, so the check
// would have fired on a manifest nobody had touched.
func TestDriftAgainstWalk_ReplacedModuleMatchesItsRequireEntry(t *testing.T) {
	replaced := depNode("github.com/cortezaproject/goqu/v9@v9.18.4")
	replaced.ResolutionSource = walkdomain.ResolutionReplace
	replaced.OriginalCoordinate = coordinatetest.MustNew("github.com/doug-martin/goqu/v9", "v9.18.0")
	rec := driftWalk("walk-old", replaced)

	d := driftAgainstWalk([]string{"github.com/doug-martin/goqu/v9@v9.18.0"}, rec)

	if d.drifted() {
		t.Fatalf("a replace directive read as drift: %+v", d)
	}
}

// The stdlib node and the local root are in every project walk and in no
// manifest resolution: counting them would make every walk look drifted by two.
func TestDriftAgainstWalk_StdlibAndLocalRootAreNotDrift(t *testing.T) {
	local := depNode("example.com/app/internal/tool@v0.0.0")
	local.Coordinate = coordinatetest.MustNew("example.com/fork", coordinate.LocalVersion)
	local.ResolutionSource = walkdomain.ResolutionLocalReplace
	rec := driftWalk("walk-old", local)

	d := driftAgainstWalk(nil, rec)

	if d.drifted() {
		t.Fatalf("the stdlib node or a local-path replace read as drift: %+v", d)
	}
	if d.walked != 0 {
		t.Errorf("walked = %d, want 0 comparable modules", d.walked)
	}
}

// reason names a bounded sample rather than the whole build list: a `go get -u`
// moves hundreds of modules at once, and a reason line that printed all of them
// would bury the statement.
func TestManifestDriftReason_SamplesRatherThanPrintingTheBuildList(t *testing.T) {
	d := manifestDrift{resolved: 10, walked: 4, added: []string{"a@v1", "b@v1", "c@v1", "d@v1", "e@v1"}}
	got := d.reason("walk-old")
	if !strings.Contains(got, "and 2 more") {
		t.Errorf("reason %q does not say how many it left out", got)
	}
	if strings.Contains(got, "e@v1") {
		t.Errorf("reason %q printed the whole list", got)
	}
}

// driftFixture writes a module with no dependencies and returns its go.mod
// path. `go list` resolves it to the empty set, so the walk record alone
// decides whether the comparison sees drift.
func driftFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gomodPath := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomodPath, []byte("module example.com/app\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.go"), []byte("package app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return gomodPath
}

// The check reads the manifest on disk, not the walk's memory of it: the walk
// carries a dependency the module no longer requires, and the drift is
// measured against the toolchain's own resolution.
func TestManifestDriftAgainstWalk_ResolvesTheManifestOnDisk(t *testing.T) {
	gomodPath := driftFixture(t)
	walks := testfakes.NewFakeQueryWalks()
	walks.AddWalk(driftWalk("walk-old", depNode("golang.org/x/net@v0.33.0")))

	d, rec, err := manifestDriftAgainstWalk(t.Context(), walks, "walk-old", gomodPath, scopeCode)
	if err != nil {
		t.Fatalf("manifestDriftAgainstWalk: %v", err)
	}
	if rec.ID != "walk-old" {
		t.Errorf("returned walk %q, want the one compared against", rec.ID)
	}
	if !d.drifted() || len(d.removed) != 1 {
		t.Fatalf("a dependency dropped from the manifest read as identical: %+v", d)
	}
}

// scanScopeFixture is the vuln-scan decision under test: a selected walk, a
// store, and a walk use case that witnesses whether a re-walk was driven.
func scanScopeFixture(t *testing.T, rec walkdomain.WalkRecord) (*Container, *testfakes.FakeExecuteWalk, walkports.WalkSummary, string) {
	t.Helper()
	gomodPath := driftFixture(t)
	walks := testfakes.NewFakeQueryWalks()
	walks.AddWalk(rec)
	exec := &testfakes.FakeExecuteWalk{Result: walkapp.ExecuteWalkResult{
		Record: walkdomain.WalkRecord{ID: "walk-fresh", OverallStatus: walkdomain.WalkSucceeded},
	}}
	return &Container{QueryWalks: walks, ExecuteWalk: exec}, exec, walkports.WalkSummary{ID: rec.ID}, gomodPath
}

// The headline for the command path: a drifted manifest is not answered from
// the stored walk. The scan is re-pointed at a walk of the build in front of
// the caller, and the drift is stated as the reason.
func TestScanWalkForCurrentManifest_DriftedManifestReWalks(t *testing.T) {
	ctr, exec, selected, gomodPath := scanScopeFixture(t, driftWalk("walk-old", depNode("golang.org/x/net@v0.33.0")))
	var stderr bytes.Buffer

	walkID, err := scanWalkForCurrentManifest(t.Context(), ctr, selected, gomodPath, scopeCode, vulnScanFlags{}, &stderr)
	if err != nil {
		t.Fatalf("scanWalkForCurrentManifest: %v", err)
	}
	if walkID != "walk-fresh" {
		t.Errorf("scanned walk %q, want the freshly walked one", walkID)
	}
	if exec.Calls != 1 {
		t.Errorf("re-walks driven = %d, want exactly 1", exec.Calls)
	}
	if !strings.Contains(stderr.String(), "no longer resolves to walk walk-old") {
		t.Errorf("stderr does not name the drift as the reason: %q", stderr.String())
	}
}

// --force on a drifted manifest re-walks too. Before, the remedy the tool
// printed could not be taken: --force re-measured the stale walk and failed.
func TestScanWalkForCurrentManifest_ForceOnDriftReWalks(t *testing.T) {
	ctr, exec, selected, gomodPath := scanScopeFixture(t, driftWalk("walk-old", depNode("golang.org/x/net@v0.33.0")))
	var stderr bytes.Buffer

	walkID, err := scanWalkForCurrentManifest(t.Context(), ctr, selected, gomodPath, scopeCode, vulnScanFlags{force: true}, &stderr)
	if err != nil {
		t.Fatalf("scanWalkForCurrentManifest --force: %v", err)
	}
	if walkID != "walk-fresh" || exec.Calls != 1 {
		t.Errorf("--force on a drifted manifest gave walk %q after %d re-walk(s)", walkID, exec.Calls)
	}
	if !exec.LastRequest.Force {
		t.Error("--force did not reach the walk it drove")
	}
}

// The control: an unchanged manifest keeps the warm path exactly as it was —
// the selected walk is scanned, nothing is re-walked, and the run says what it
// checked to be allowed to say so.
func TestScanWalkForCurrentManifest_UnchangedManifestServesTheSelectedWalk(t *testing.T) {
	ctr, exec, selected, gomodPath := scanScopeFixture(t, driftWalk("walk-old"))
	var stderr bytes.Buffer

	walkID, err := scanWalkForCurrentManifest(t.Context(), ctr, selected, gomodPath, scopeCode, vulnScanFlags{}, &stderr)
	if err != nil {
		t.Fatalf("scanWalkForCurrentManifest: %v", err)
	}
	if walkID != "walk-old" {
		t.Errorf("scanned walk %q, want the selected one", walkID)
	}
	if exec.Calls != 0 {
		t.Errorf("an unchanged manifest drove %d re-walk(s)", exec.Calls)
	}
	if !strings.Contains(stderr.String(), "manifest re-resolved") {
		t.Errorf("the served answer does not state the check it passed: %q", stderr.String())
	}
}

// A check that cannot be made is not a passed check. Each way the comparison
// can fail names what it stopped — the walk, the manifest, or the re-walk — so a
// reader is never left to infer that a stored answer was validated.
func TestManifestDriftAgainstWalk_FailuresNameWhatTheyStopped(t *testing.T) {
	t.Run("the walk cannot be read", func(t *testing.T) {
		walks := testfakes.NewFakeQueryWalks()
		walks.GetErr = errDriftSeam
		_, _, err := manifestDriftAgainstWalk(t.Context(), walks, "walk-old", driftFixture(t), scopeCode)
		if err == nil || !strings.Contains(err.Error(), "walk-old") {
			t.Fatalf("err = %v, want the unreadable walk named", err)
		}
	})

	t.Run("the manifest does not resolve", func(t *testing.T) {
		walks := testfakes.NewFakeQueryWalks()
		walks.AddWalk(driftWalk("walk-old"))
		missing := filepath.Join(t.TempDir(), "gone", "go.mod")
		_, _, err := manifestDriftAgainstWalk(t.Context(), walks, "walk-old", missing, scopeCode)
		if err == nil || !strings.Contains(err.Error(), "still describes") {
			t.Fatalf("err = %v, want the check named as what failed", err)
		}
	})

	t.Run("the re-walk fails", func(t *testing.T) {
		ctr, exec, selected, gomodPath := scanScopeFixture(t, driftWalk("walk-old", depNode("golang.org/x/net@v0.33.0")))
		exec.Err = errDriftSeam
		var stderr bytes.Buffer
		_, err := scanWalkForCurrentManifest(t.Context(), ctr, selected, gomodPath, scopeCode, vulnScanFlags{}, &stderr)
		if err == nil {
			t.Fatal("a failed re-walk was reported as success, so the scan would have run against nothing")
		}
	})

	t.Run("the re-walk produces no record", func(t *testing.T) {
		ctr, exec, selected, gomodPath := scanScopeFixture(t, driftWalk("walk-old", depNode("golang.org/x/net@v0.33.0")))
		exec.Result = walkapp.ExecuteWalkResult{}
		var stderr bytes.Buffer
		_, err := scanWalkForCurrentManifest(t.Context(), ctr, selected, gomodPath, scopeCode, vulnScanFlags{}, &stderr)
		if err == nil || !strings.Contains(err.Error(), "no walk record") {
			t.Fatalf("err = %v, want the empty re-walk named", err)
		}
	})
}

type driftSeamError struct{}

func (driftSeamError) Error() string { return "walk store unavailable" }

var errDriftSeam = driftSeamError{}
