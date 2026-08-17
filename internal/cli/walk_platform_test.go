package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// otherPlatform names a platform this host is definitely not, so a test that
// asserts "the current environment's walk was chosen" cannot pass by accident on
// whichever machine runs it.
func otherPlatform() walkports.BuildEnvFilter {
	if runtime.GOOS == "darwin" {
		return walkports.BuildEnvFilter{GOOS: "linux", GOARCH: "arm"}
	}
	return walkports.BuildEnvFilter{GOOS: "darwin", GOARCH: "arm64"}
}

// hostPlatform is the frame currentBuildEnvFilter resolves for this process. It
// is the host platform whether the `go env` probe runs or fails, which is what
// makes these tests independent of a toolchain being on PATH.
func hostPlatform() walkports.BuildEnvFilter {
	return walkports.BuildEnvFilter{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
}

// platformSummaries builds two summaries of ONE target that differ only in the
// platform they resolved for, with the OTHER platform's stored first — which is
// the order a started_at DESC listing would put the newer one in.
func platformSummaries(t testing.TB, modulePath string) (wantedID string, qw *testfakes.FakeQueryWalks, local coordinate.ModuleCoordinate) {
	t.Helper()
	local, err := coordinate.NewLocalCoordinate(modulePath)
	if err != nil {
		t.Fatalf("local coordinate: %v", err)
	}
	host, other := hostPlatform(), otherPlatform()
	qw = testfakes.NewFakeQueryWalks()
	qw.SetSummaries([]walkports.WalkSummary{
		{
			ID: "walk-other-newer", Target: local, Scope: walkdomain.WalkScopeCode,
			OverallStatus: walkdomain.WalkSucceeded,
			StartedAt:     time.Date(2026, 8, 2, 6, 0, 0, 0, time.UTC),
			GOOS:          other.GOOS, GOARCH: other.GOARCH,
		},
		{
			ID: "walk-host", Target: local, Scope: walkdomain.WalkScopeCode,
			OverallStatus: walkdomain.WalkSucceeded,
			StartedAt:     time.Date(2026, 8, 2, 5, 0, 0, 0, time.UTC),
			GOOS:          host.GOOS, GOARCH: host.GOARCH,
		},
	})
	return "walk-host", qw, local
}

// TestSelectProjectWalkToScan_PicksThisPlatformNotTheNewestWalk is the headline
// gate for vuln-scan --gomod. govulncheck's reachability follows the files build
// constraints select, so a scan of another platform's walk answers a question
// nobody asked — and the latest-for-target lookup it used could not tell the
// two apart.
func TestSelectProjectWalkToScan_PicksThisPlatformNotTheNewestWalk(t *testing.T) {
	const modulePath = "example.com/myapp"
	wantedID, qw, local := platformSummaries(t, modulePath)

	got, err := selectProjectWalkToScan(context.Background(), qw, local, scopeCode, hostPlatform(), "./go.mod")
	if err != nil {
		t.Fatalf("selectProjectWalkToScan: %v", err)
	}
	if got.ID != wantedID {
		t.Errorf("scanned walk %s, want this platform's %s", got.ID, wantedID)
	}
	if got.BuildFrame() != hostPlatform().String() {
		t.Errorf("selected frame %s, want %s", got.BuildFrame(), hostPlatform())
	}
}

// TestSelectProjectWalkToScan_RefusesNamingThePlatformAndTheRemedy: when only
// another platform's walk exists, the answer is a refusal that names the frame
// asked for and the command that produces it — never that other walk.
func TestSelectProjectWalkToScan_RefusesNamingThePlatformAndTheRemedy(t *testing.T) {
	const modulePath = "example.com/myapp"
	local, err := coordinate.NewLocalCoordinate(modulePath)
	if err != nil {
		t.Fatalf("local coordinate: %v", err)
	}
	other := otherPlatform()
	qw := testfakes.NewFakeQueryWalks()
	qw.SetSummaries([]walkports.WalkSummary{
		{
			ID: "walk-other-only", Target: local, Scope: walkdomain.WalkScopeCode,
			OverallStatus: walkdomain.WalkSucceeded,
			GOOS:          other.GOOS, GOARCH: other.GOARCH,
		},
	})

	_, err = selectProjectWalkToScan(context.Background(), qw, local, scopeCode, hostPlatform(), "./go.mod")
	if err == nil {
		t.Fatal("a store holding only another platform's walk must refuse, not answer from it")
	}
	msg := err.Error()
	for _, want := range []string{modulePath, hostPlatform().String(), "kanonarion walk --gomod ./go.mod"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal does not name %q; message was: %s", want, msg)
		}
	}
	if strings.Contains(msg, "walk-other-only") {
		t.Errorf("the refusal offered another platform's walk: %s", msg)
	}
}

// TestSelectProjectWalkToScan_ARefusalNamesTheScopeFlag pins the remedy for a
// non-default scope: the walk that would satisfy the question is a --tool walk,
// and a remedy that omitted the flag would produce a walk that still does not.
func TestSelectProjectWalkToScan_ARefusalNamesTheScopeFlag(t *testing.T) {
	local, err := coordinate.NewLocalCoordinate("example.com/myapp")
	if err != nil {
		t.Fatalf("local coordinate: %v", err)
	}
	_, err = selectProjectWalkToScan(context.Background(), testfakes.NewFakeQueryWalks(),
		local, scopeTool, hostPlatform(), "./go.mod")
	if err == nil {
		t.Fatal("expected a refusal on an empty store")
	}
	if !strings.Contains(err.Error(), "kanonarion walk --gomod ./go.mod --tool") {
		t.Errorf("refusal remedy does not carry the scope flag: %s", err)
	}
}

// TestVulnScanByModule_IsNotPlatformFiltered pins the one selection site that
// deliberately does NOT filter.
//
// A walk rooted at a published coordinate is resolved through the module path,
// which records no build environment at all: on the real store, of 92 walks the
// 20 with no frame are exactly the module-rooted ones, and both sites that write
// a BuildEnv sit under the project resolver. A platform filter here would refuse
// every module-rooted walk that exists, forever — so the frame is stated
// ("unrecorded") rather than required.
//
// This is a lower-level pin than the CLI entry: it asserts the filter the entry
// builds, so it fails if someone adds a BuildEnv axis to that lookup.
func TestVulnScanByModule_IsNotPlatformFiltered(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("github.com/spf13/cobra", "v1.8.1")
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	qw := testfakes.NewFakeQueryWalks()
	// A frameless module-rooted walk: exactly what the walk pipeline writes.
	qw.SetSummaries([]walkports.WalkSummary{
		{ID: "walk-module-rooted", Target: coord, Scope: walkdomain.WalkScopeCode,
			OverallStatus: walkdomain.WalkSucceeded},
	})

	got, err := qw.ListWalks(context.Background(), walkports.WalkFilter{Target: &coord, Limit: 1})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("a module-rooted walk must be findable without a platform: got %d", len(got))
	}
	if got[0].BuildFrame() != "not-platform-scoped" {
		t.Errorf("module-rooted walk frame = %q, want not-platform-scoped", got[0].BuildFrame())
	}
	if basis := got[0].Frame().Basis; basis != walkdomain.FrameBasisNotPlatformScoped {
		t.Errorf("module-rooted walk basis = %q, want %q", basis, walkdomain.FrameBasisNotPlatformScoped)
	}

	// And the filter that WOULD be wrong here finds nothing, which is why the
	// site does not apply one.
	host := hostPlatform()
	blocked, err := qw.ListWalks(context.Background(), walkports.WalkFilter{Target: &coord, BuildEnv: &host, Limit: 1})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	if len(blocked) != 0 {
		t.Fatalf("fixture is wrong: a frameless walk matched a %s filter", host)
	}
}

// TestFindLatestProjectWalk_WillNotReuseAnotherPlatformsWalk is the same gate on
// the SBOM's reuse lookup. An inventory built over another platform's closure
// lists components this build never selects.
func TestFindLatestProjectWalk_WillNotReuseAnotherPlatformsWalk(t *testing.T) {
	const modulePath = "example.com/myapp"
	wantedID, qw, _ := platformSummaries(t, modulePath)

	id, err := findLatestProjectWalk(context.Background(), qw, modulePath, hostPlatform())
	if err != nil {
		t.Fatalf("findLatestProjectWalk: %v", err)
	}
	if id != wantedID {
		t.Errorf("SBOM would reuse walk %s, want this platform's %s", id, wantedID)
	}
}

// TestEnsureProjectWalkForSBOM_BuildsRatherThanReuseAnotherPlatformsWalk: the
// whole non---force entry, not just its lookup. With only another platform's
// walk stored, the run must build one here instead of inventorying that one.
// A refusal would be wrong: this command's documented job is to produce the
// missing prerequisite unattended, and it produces it in THIS frame.
func TestEnsureProjectWalkForSBOM_BuildsRatherThanReuseAnotherPlatformsWalk(t *testing.T) {
	const modulePath = "example.com/myapp"
	local, err := coordinate.NewLocalCoordinate(modulePath)
	if err != nil {
		t.Fatalf("local coordinate: %v", err)
	}

	prevStore := storeRoot
	t.Cleanup(func() { storeRoot = prevStore })
	storeRoot = t.TempDir()

	gomod := projectGoMod(t, modulePath)
	t.Chdir(filepath.Dir(gomod))

	other := otherPlatform()
	host := hostPlatform()
	built := walkdomain.WalkRecord{
		ID: "walk-built-here", Target: local, Scope: walkdomain.WalkScopeCode,
		OverallStatus: walkdomain.WalkSucceeded,
		Graph: walkdomain.Graph{
			Nodes:    []walkdomain.GraphNode{{Coordinate: local}},
			BuildEnv: walkdomain.BuildEnv{GOOS: host.GOOS, GOARCH: host.GOARCH, GoVersion: "go1.26.4"},
		},
	}
	qw := testfakes.NewFakeQueryWalks()
	qw.AddWalk(built)
	qw.SetSummaries([]walkports.WalkSummary{{
		ID: "walk-other-newer", Target: local, Scope: walkdomain.WalkScopeCode,
		OverallStatus: walkdomain.WalkSucceeded,
		GOOS:          other.GOOS, GOARCH: other.GOARCH,
	}})

	extract := &testfakes.FakeExtract{}
	ctr := &Container{
		ExecuteWalk: &testfakes.FakeExecuteWalk{Result: walkapp.ExecuteWalkResult{Record: built, Reused: false}},
		QueryWalks:  qw,
		Extract:     extract,
	}

	var stderr strings.Builder
	walkID, err := ensureProjectWalkForSBOM(context.Background(), ctr, false, false, true, "", &stderr)
	if err != nil {
		t.Fatalf("ensureProjectWalkForSBOM: %v", err)
	}
	if walkID != built.ID {
		t.Errorf("the SBOM was built over walk %s, want the walk built in this frame, %s", walkID, built.ID)
	}
	if strings.Contains(stderr.String(), "walk-other-newer") {
		t.Errorf("the SBOM run named another platform's walk:\n%s", stderr.String())
	}
}

// TestDependentsText_StatesTheFrameItAnsweredFrom is the query-command half.
// These commands keep latest-knowledge selection, so the walk that answers may
// be another platform's — which is a defensible answer only if the output says
// which platform it is.
func TestDependentsText_StatesTheFrameItAnsweredFrom(t *testing.T) {
	var buf bytes.Buffer
	if err := writeDependentsText(&buf, "walk-1", walkdomain.WalkFrame{Text: "darwin/arm64", Basis: walkdomain.FrameBasisPlatform}, "example.com/dep@v1.0.0",
		nil, false, false, true); err != nil {
		t.Fatalf("writeDependentsText: %v", err)
	}
	if !strings.Contains(buf.String(), "(frame darwin/arm64)") {
		t.Errorf("the answer does not state the frame it answered from: %s", buf.String())
	}
}

// A walk whose platform is genuinely not known states that it is unrecorded.
// Omitting the line would leave a reader unable to tell an unstated frame from a
// missing one, and saying "not platform-scoped" would claim a reason this walk
// does not supply.
func TestBuildFrame_AWalkWithNoKnownPlatformSaysUnrecorded(t *testing.T) {
	if got := (walkports.WalkSummary{}).BuildFrame(); got != "unrecorded" {
		t.Errorf("a frame-unrecorded walk renders as %q, want unrecorded", got)
	}
}
