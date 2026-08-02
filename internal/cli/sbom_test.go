package cli

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"

	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// sbomTestPlatform is the frame these selection tests ask in. The fixtures
// below record the same one, so a test that is not about platform mismatch
// still finds its walk.
var sbomTestPlatform = walkports.BuildEnvFilter{GOOS: "linux", GOARCH: "amd64"}

// ---- findLatestProjectWalk ----

func TestFindLatestProjectWalk_Found(t *testing.T) {
	qw := testfakes.NewFakeQueryWalks()
	coord, _ := coordinate.NewModuleCoordinate("example.com/myapp", coordinate.LocalVersion)
	qw.SetSummaries([]walkports.WalkSummary{
		{ID: "walk-proj-1", Target: coord, Scope: walkdomain.WalkScopeCode, OverallStatus: walkdomain.WalkSucceeded, GOOS: "linux", GOARCH: "amd64"},
	})

	id, err := findLatestProjectWalk(context.Background(), qw, "example.com/myapp", sbomTestPlatform)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "walk-proj-1" {
		t.Errorf("want walk-proj-1, got %q", id)
	}
}

func TestFindLatestProjectWalk_NotFound(t *testing.T) {
	qw := testfakes.NewFakeQueryWalks()
	// Store has walks, but none matching this module.
	other, _ := coordinate.NewModuleCoordinate("example.com/other", coordinate.LocalVersion)
	qw.SetSummaries([]walkports.WalkSummary{
		{ID: "walk-other", Target: other, Scope: walkdomain.WalkScopeCode, OverallStatus: walkdomain.WalkSucceeded, GOOS: "linux", GOARCH: "amd64"},
	})

	_, err := findLatestProjectWalk(context.Background(), qw, "example.com/myapp", sbomTestPlatform)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errNoProjectWalk) {
		t.Errorf("error should be errNoProjectWalk, got: %v", err)
	}
}

func TestFindLatestProjectWalk_ListError(t *testing.T) {
	qw := testfakes.NewFakeQueryWalks()
	qw.ListErr = walkports.ErrWalkNotFound

	_, err := findLatestProjectWalk(context.Background(), qw, "example.com/myapp", sbomTestPlatform)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestFindLatestProjectWalk_ExcludesFailedWalks(t *testing.T) {
	qw := testfakes.NewFakeQueryWalks()
	coord, _ := coordinate.NewModuleCoordinate("example.com/myapp", coordinate.LocalVersion)
	// Only a failed walk is present.
	qw.SetSummaries([]walkports.WalkSummary{
		{ID: "walk-failed", Target: coord, Scope: walkdomain.WalkScopeCode, OverallStatus: walkdomain.WalkFailed, GOOS: "linux", GOARCH: "amd64"},
	})

	_, err := findLatestProjectWalk(context.Background(), qw, "example.com/myapp", sbomTestPlatform)
	if err == nil {
		t.Fatal("expected error for no succeeded walks, got nil")
	}
}

// ---- projectWalkToReuse ----

func TestProjectWalkToReuse_ReusesSucceededWalk(t *testing.T) {
	qw := testfakes.NewFakeQueryWalks()
	coord, _ := coordinate.NewModuleCoordinate("example.com/myapp", coordinate.LocalVersion)
	qw.SetSummaries([]walkports.WalkSummary{
		{ID: "walk-1", Target: coord, Scope: walkdomain.WalkScopeCode, OverallStatus: walkdomain.WalkSucceeded, GOOS: "linux", GOARCH: "amd64"},
	})

	id, reuse, err := projectWalkToReuse(context.Background(), qw, "example.com/myapp", false, sbomTestPlatform)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reuse || id != "walk-1" {
		t.Errorf("want reuse of walk-1, got reuse=%v id=%q", reuse, id)
	}
}

// A cold store (no succeeded walk) signals build, not error.
func TestProjectWalkToReuse_ColdStoreSignalsBuild(t *testing.T) {
	qw := testfakes.NewFakeQueryWalks()

	id, reuse, err := projectWalkToReuse(context.Background(), qw, "example.com/myapp", false, sbomTestPlatform)
	if err != nil {
		t.Fatalf("cold store must not error, got: %v", err)
	}
	if reuse || id != "" {
		t.Errorf("want build signal (reuse=false, id=\"\"), got reuse=%v id=%q", reuse, id)
	}
}

// --force never reuses, even when a succeeded walk exists.
func TestProjectWalkToReuse_ForceAlwaysBuilds(t *testing.T) {
	qw := testfakes.NewFakeQueryWalks()
	coord, _ := coordinate.NewModuleCoordinate("example.com/myapp", coordinate.LocalVersion)
	qw.SetSummaries([]walkports.WalkSummary{
		{ID: "walk-1", Target: coord, Scope: walkdomain.WalkScopeCode, OverallStatus: walkdomain.WalkSucceeded, GOOS: "linux", GOARCH: "amd64"},
	})

	_, reuse, err := projectWalkToReuse(context.Background(), qw, "example.com/myapp", true, sbomTestPlatform)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reuse {
		t.Error("--force must never reuse an existing walk")
	}
}

// A genuine lookup error is propagated, never mistaken for a cold store.
func TestProjectWalkToReuse_ListErrorPropagates(t *testing.T) {
	qw := testfakes.NewFakeQueryWalks()
	qw.ListErr = errors.New("db down")

	_, _, err := projectWalkToReuse(context.Background(), qw, "example.com/myapp", false, sbomTestPlatform)
	if err == nil {
		t.Fatal("expected the lookup error to propagate, got nil")
	}
	if errors.Is(err, errNoProjectWalk) {
		t.Error("a real lookup error must not be reported as a cold store")
	}
}

// ---- extractLicencesForProjectWalk ----

// The walk the caller names gets exactly the licence stage extracted, with force
// threaded through, and its ID returned.
func TestExtractLicencesForProjectWalk_RunsLicenceStage(t *testing.T) {
	ex := &testfakes.FakeExtract{}

	id, err := extractLicencesForProjectWalk(context.Background(), ex, "walk-1", true, io.Discard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "walk-1" {
		t.Errorf("want walk-1, got %q", id)
	}
	if len(ex.Calls) != 1 {
		t.Fatalf("want exactly one extract call, got %d", len(ex.Calls))
	}
	call := ex.Calls[0]
	if call.WalkID != "walk-1" {
		t.Errorf("extract walk ID = %q, want walk-1", call.WalkID)
	}
	if len(call.Stages) != 1 || call.Stages[0] != "license" {
		t.Errorf("want only the license stage, got %v", call.Stages)
	}
	if !call.Force {
		t.Error("force flag should be threaded through to extraction")
	}
}

// A failing extraction surfaces wrapped, never swallowed.
func TestExtractLicencesForProjectWalk_ExtractError(t *testing.T) {
	ex := &testfakes.FakeExtract{Err: errors.New("boom")}

	_, err := extractLicencesForProjectWalk(context.Background(), ex, "walk-1", false, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "extracting licences") {
		t.Fatalf("want wrapped extraction error, got: %v", err)
	}
}

// ---- sbom command argument validation ----

func TestSBOMCmd_NoArgsNoPackage_Error(t *testing.T) {
	var stdout, stderr strings.Builder
	err := Run([]string{"sbom", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error when no walk ID and no --package, got nil")
	}
	if !strings.Contains(err.Error(), "walk ID") && !strings.Contains(err.Error(), "--package") {
		t.Errorf("error should mention walk ID or --package, got: %v", err)
	}
}

// ---- buildPackageAllowList ----

// TestBuildPackageAllowList_LiveRepo verifies that buildPackageAllowList returns
// a non-empty allowlist containing known transitive deps of the kanonarion binary.
// Requires the Go toolchain; skipped in short mode.
func TestBuildPackageAllowList_LiveRepo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live go list test in short mode")
	}

	list, err := buildPackageAllowList("github.com/eitanity/kanonarion/cmd/kanonarion")
	if err != nil {
		t.Fatalf("buildPackageAllowList: %v", err)
	}
	if len(list) == 0 {
		t.Fatal("expected non-empty allowlist")
	}
	// Every entry must have a non-empty path and version.
	for _, c := range list {
		if c.Path() == "" || c.Version() == "" {
			t.Errorf("coordinate has empty field: %+v", c)
		}
	}
	// cobra is a known direct dep of cmd/kanonarion.
	found := false
	for _, c := range list {
		if c.Path() == "github.com/spf13/cobra" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected github.com/spf13/cobra in allowlist (known binary dep)")
	}
}
