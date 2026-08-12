package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// fakeLicenseOverrides supplies the empty override set; the walk-selection tests
// have no dependency rows and never consult it for a verdict.
type fakeLicenseOverrides struct{}

func (fakeLicenseOverrides) LoadOverrides(_ context.Context) (licensedomain.LicenseOverrideSet, error) {
	return licensedomain.LicenseOverrideSet{}, nil
}

func (fakeLicenseOverrides) SaveOverrides(_ context.Context, _ licensedomain.LicenseOverrideSet) error {
	return nil
}

// crossPlatformWalks builds two walks of ONE target that differ only in build
// environment, with the other platform's walk stored as the newer of the two.
//
// This is the shape a cross-compiled release run leaves behind: several audits
// of the same project on one store, one per target platform. The walks are
// distinct analyses — GOOS gates which files build, so the dependency sets can
// genuinely differ — but they share a target and a scope, which is all a
// latest-for-target lookup can discriminate on.
func crossPlatformWalks(t testing.TB, modulePath string) (wanted, newerOther walkdomain.WalkRecord, local coordinate.ModuleCoordinate) {
	t.Helper()
	local, err := coordinate.NewLocalCoordinate(modulePath)
	if err != nil {
		t.Fatalf("local coordinate: %v", err)
	}
	node := walkdomain.GraphNode{Coordinate: local}

	wanted = walkdomain.WalkRecord{
		ID:            "walk-darwin",
		Target:        local,
		Scope:         walkdomain.WalkScopeCode,
		OverallStatus: walkdomain.WalkSucceeded,
		CompletedAt:   time.Date(2026, 8, 2, 5, 0, 0, 0, time.UTC),
		Graph: walkdomain.Graph{
			Nodes:    []walkdomain.GraphNode{node},
			BuildEnv: walkdomain.BuildEnv{GOOS: "darwin", GOARCH: "amd64", GoVersion: "go1.26.4"},
		},
	}
	newerOther = walkdomain.WalkRecord{
		ID:            "walk-linux",
		Target:        local,
		Scope:         walkdomain.WalkScopeCode,
		OverallStatus: walkdomain.WalkSucceeded,
		CompletedAt:   time.Date(2026, 8, 2, 6, 0, 0, 0, time.UTC),
		Graph: walkdomain.Graph{
			Nodes:    []walkdomain.GraphNode{node},
			BuildEnv: walkdomain.BuildEnv{GOOS: "linux", GOARCH: "amd64", GoVersion: "go1.26.4"},
		},
	}
	return wanted, newerOther, local
}

// projectGoMod writes a minimal go.mod and returns its path.
func projectGoMod(t testing.TB, modulePath string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte("module "+modulePath+"\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	return path
}

// walkStoreWithNewerOtherPlatform returns a query fake holding both walks, with
// the other platform's the one a latest-for-target lookup would return.
func walkStoreWithNewerOtherPlatform(wanted, newerOther walkdomain.WalkRecord) *testfakes.FakeQueryWalks {
	qw := testfakes.NewFakeQueryWalks()
	qw.AddWalk(wanted)
	qw.AddWalk(newerOther)
	qw.SetSummaries([]walkports.WalkSummary{
		{ID: newerOther.ID, Target: newerOther.Target, Scope: newerOther.Scope, OverallStatus: newerOther.OverallStatus},
		{ID: wanted.ID, Target: wanted.Target, Scope: wanted.Scope, OverallStatus: wanted.OverallStatus},
	})
	return qw
}

// TestAuditScope_UsesTheWalkItExecutedNotTheLatestForTheTarget is the
// walk-selection gate.
//
// An audit resolves one walk and then licences it, scans it, asks whether its
// scan can be reused, and reports it. All five have to be the SAME walk. They
// were not: the walk leg used the walk it executed, and every downstream leg
// re-found "the latest walk for this target and scope" — a question that cannot
// tell two platforms apart, because WalkFilter has no build-environment axis. On
// a store holding audits of several platforms, one audit therefore extracted,
// scanned and reported another platform's walk while its own derivation line
// named the walk it had actually resolved.
func TestAuditScope_UsesTheWalkItExecutedNotTheLatestForTheTarget(t *testing.T) {
	const modulePath = "example.com/myapp"
	wanted, newerOther, _ := crossPlatformWalks(t, modulePath)

	prevStore := storeRoot
	t.Cleanup(func() { storeRoot = prevStore })
	storeRoot = t.TempDir()

	scanWalk := &testfakes.FakeScanWalk{}
	ctr := &Container{
		ExecuteWalk:      &testfakes.FakeExecuteWalk{Result: walkapp.ExecuteWalkResult{Record: wanted, Reused: true}},
		QueryWalks:       walkStoreWithNewerOtherPlatform(wanted, newerOther),
		ScanWalk:         scanWalk,
		LicenseOverrides: fakeLicenseOverrides{},
	}

	var stderr strings.Builder
	f := auditFlags{gomodPath: projectGoMod(t, modulePath)}
	_, derivation, err := auditScope(context.Background(), nil, scopeCode, f, nil, ctr, &stderr)
	if err != nil {
		t.Fatalf("auditScope: %v", err)
	}

	if derivation.walkRecord.ID != wanted.ID {
		t.Errorf("derivation names walk %s, want the executed %s", derivation.walkRecord.ID, wanted.ID)
	}
	narration := stderr.String()
	for _, banner := range []string{
		"extracting licenses for walk " + wanted.ID,
		"scanning vulnerabilities for walk " + wanted.ID,
	} {
		if !strings.Contains(narration, banner) {
			t.Errorf("audit did not report %q; narration was:\n%s", banner, narration)
		}
	}
	if strings.Contains(narration, newerOther.ID) {
		t.Errorf("audit named another platform's walk %s:\n%s", newerOther.ID, narration)
	}
	if scanWalk.ReusableRunWalkID != wanted.ID {
		t.Errorf("the reuse question was asked about walk %s, want the executed %s",
			scanWalk.ReusableRunWalkID, wanted.ID)
	}
}

// TestAuditScope_AsksTheReuseQuestionAboutTheTreeItAudits pins the other half of
// that question. Whether a stored run may be served depends on the project
// directory still requiring the module versions the walk resolved, and that
// judgement belongs to the use case — but the use case can only make it about a
// directory it was told. A caller that asks the reuse question without naming
// the tree it is auditing gets a cache hit the guard never saw, which is how a
// diverged directory came to be answered from the cache in the first place.
func TestAuditScope_AsksTheReuseQuestionAboutTheTreeItAudits(t *testing.T) {
	const modulePath = "example.com/myapp"
	wanted, newerOther, _ := crossPlatformWalks(t, modulePath)

	prevStore := storeRoot
	t.Cleanup(func() { storeRoot = prevStore })
	storeRoot = t.TempDir()

	scanWalk := &testfakes.FakeScanWalk{}
	ctr := &Container{
		ExecuteWalk:      &testfakes.FakeExecuteWalk{Result: walkapp.ExecuteWalkResult{Record: wanted, Reused: true}},
		QueryWalks:       walkStoreWithNewerOtherPlatform(wanted, newerOther),
		ScanWalk:         scanWalk,
		LicenseOverrides: fakeLicenseOverrides{},
	}

	var stderr strings.Builder
	gomodPath := projectGoMod(t, modulePath)
	f := auditFlags{gomodPath: gomodPath}
	if _, _, err := auditScope(context.Background(), nil, scopeCode, f, nil, ctr, &stderr); err != nil {
		t.Fatalf("auditScope: %v", err)
	}

	if !scanWalk.ReusableRunProjectDirSet {
		t.Fatal("the reuse question was never asked, so nothing checked the tree against the walk")
	}
	if want := filepath.Dir(gomodPath); scanWalk.ReusableRunProjectDir != want {
		t.Errorf("the reuse question named project directory %q, want the audited tree %q",
			scanWalk.ReusableRunProjectDir, want)
	}
}

// TestAuditScope_RestrictsTheAdvisoryRefreshToTheWalkItExecuted: the refresh
// compares advisories over the walk's module set, so it has to be handed the
// same walk as every other leg.
func TestAuditScope_RestrictsTheAdvisoryRefreshToTheWalkItExecuted(t *testing.T) {
	const modulePath = "example.com/myapp"
	wanted, newerOther, _ := crossPlatformWalks(t, modulePath)

	prevStore := storeRoot
	t.Cleanup(func() { storeRoot = prevStore })
	storeRoot = t.TempDir()

	scanWalk := &testfakes.FakeScanWalk{}
	ctr := &Container{
		ExecuteWalk:      &testfakes.FakeExecuteWalk{Result: walkapp.ExecuteWalkResult{Record: wanted, Reused: true}},
		QueryWalks:       walkStoreWithNewerOtherPlatform(wanted, newerOther),
		ScanWalk:         scanWalk,
		LicenseOverrides: fakeLicenseOverrides{},
	}

	var stderr strings.Builder
	f := auditFlags{gomodPath: projectGoMod(t, modulePath), fresh: true}
	if _, _, err := auditScope(context.Background(), nil, scopeCode, f, nil, ctr, &stderr); err != nil {
		t.Fatalf("auditScope: %v", err)
	}

	if scanWalk.RefreshSnapshotCalls != 1 {
		t.Errorf("--fresh refreshed the advisory database %d times, want 1", scanWalk.RefreshSnapshotCalls)
	}
	if scanWalk.RefreshSnapshotWalkID != wanted.ID {
		t.Errorf("the refresh compared advisories over walk %s, want the executed %s",
			scanWalk.RefreshSnapshotWalkID, wanted.ID)
	}
}

// TestEnsureProjectWalkForSBOM_UsesTheWalkItBuiltNotTheLatestForTheTarget is the
// same gate on the SBOM's walk leg. An inventory that names one platform's
// build environment while listing another platform's components describes a
// build that never happened.
func TestEnsureProjectWalkForSBOM_UsesTheWalkItBuiltNotTheLatestForTheTarget(t *testing.T) {
	const modulePath = "example.com/myapp"
	wanted, newerOther, _ := crossPlatformWalks(t, modulePath)

	prevStore := storeRoot
	t.Cleanup(func() { storeRoot = prevStore })
	storeRoot = t.TempDir()

	// --force so the entry-side reuse lookup is skipped and the walk is built:
	// this test is about which walk the legs AFTER the build use.
	gomod := projectGoMod(t, modulePath)
	t.Chdir(filepath.Dir(gomod))

	extract := &testfakes.FakeExtract{}
	ctr := &Container{
		ExecuteWalk: &testfakes.FakeExecuteWalk{Result: walkapp.ExecuteWalkResult{Record: wanted, Reused: true}},
		QueryWalks:  walkStoreWithNewerOtherPlatform(wanted, newerOther),
		Extract:     extract,
	}

	var stderr strings.Builder
	walkID, err := ensureProjectWalkForSBOM(context.Background(), ctr, true, false, true, "", &stderr)
	if err != nil {
		t.Fatalf("ensureProjectWalkForSBOM: %v", err)
	}
	if walkID != wanted.ID {
		t.Errorf("the SBOM was built over walk %s, want the walk this run built, %s", walkID, wanted.ID)
	}
	if len(extract.Calls) != 1 || extract.Calls[0].WalkID != wanted.ID {
		t.Errorf("licences were extracted for %+v, want walk %s", extract.Calls, wanted.ID)
	}
	// The build environment is what the two walks disagree on, and it is what the
	// SBOM reports as kanonarion:build:goos. Naming the walk is naming the frame.
	if got := wanted.Graph.BuildEnv.GOOS; got != "darwin" {
		t.Fatalf("fixture: wanted walk GOOS = %q, want darwin", got)
	}
	if newerOther.Graph.BuildEnv.GOOS == wanted.Graph.BuildEnv.GOOS {
		t.Fatal("fixture: the two walks must disagree on GOOS for this test to mean anything")
	}
}
