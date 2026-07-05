package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

func TestWalkCmd_GomodAndArgMutuallyExclusive(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"walk", "--gomod", "go.mod", "github.com/spf13/cobra@v1.8.1"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error when --gomod and positional arg are both provided")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected 'mutually exclusive' in error, got: %v", err)
	}
}

func TestWalkCmd_NoVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"walk", "foo"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for target with no version")
	}
	if !strings.Contains(err.Error(), "version required") {
		t.Errorf("expected 'version required' in error, got: %v", err)
	}
}

func TestWalkCmd_TooManyArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"walk", "example.com/a@v1.0.0", "example.com/b@v1.0.0"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for too many positional args")
	}
	if !strings.Contains(err.Error(), "accepts 1 arg") {
		t.Errorf("expected 'accepts 1 arg' in error, got: %v", err)
	}
}

func TestWalkCmd_GomodFileNotFound(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"walk", "--gomod", "/nonexistent/go.mod", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for missing go.mod file")
	}
}

// --tool and --project select mutually exclusive scopes.
func TestWalkCmd_ToolAndProjectMutuallyExclusive(t *testing.T) {
	gomodPath := filepath.Join(t.TempDir(), "go.mod")
	var stdout, stderr bytes.Buffer
	err := Run([]string{"walk", "--gomod", gomodPath, "--tool", "--project", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error when --tool and --project are both set")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected 'mutually exclusive' in error, got: %v", err)
	}
}

// Scope flags select a projection of a go.mod walk; they do not apply to a
// positional module walk.
func TestWalkCmd_ScopeFlagsRequireGoMod(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"walk", "github.com/spf13/cobra@v1.8.1", "--tool", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for --tool on a positional walk")
	}
	if !strings.Contains(err.Error(), "go.mod walk") {
		t.Errorf("expected go.mod-walk error, got: %v", err)
	}
}

// --shallow is a positional-only depth lens; it does not apply to a go.mod walk.
func TestWalkCmd_ShallowRejectedOnGoMod(t *testing.T) {
	gomodPath := filepath.Join(t.TempDir(), "go.mod")
	var stdout, stderr bytes.Buffer
	err := Run([]string{"walk", "--gomod", gomodPath, "--shallow", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for --shallow on a go.mod walk")
	}
	if !strings.Contains(err.Error(), "positional module walk") {
		t.Errorf("expected positional-only error, got: %v", err)
	}
}

// --analyse-root attaches to a go.mod (project) walk; a positional walk has no
// local working tree to analyse.
func TestWalkCmd_AnalyseRootRequiresGoMod(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"walk", "github.com/spf13/cobra@v1.8.1", "--analyse-root", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for --analyse-root on a positional walk")
	}
	if !strings.Contains(err.Error(), "--analyse-root requires a go.mod walk") {
		t.Errorf("expected '--analyse-root requires a go.mod walk' in error, got: %v", err)
	}
}

// --analyse-root analyses the project's own packages, which a --tool walk does
// not cover.
func TestWalkCmd_AnalyseRootRejectsToolScope(t *testing.T) {
	gomodPath := filepath.Join(t.TempDir(), "go.mod")
	var stdout, stderr bytes.Buffer
	err := Run([]string{"walk", "--gomod", gomodPath, "--analyse-root", "--tool", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error when --analyse-root combined with --tool")
	}
	if !strings.Contains(err.Error(), "a --tool walk does not cover") {
		t.Errorf("expected the --tool rejection, got: %v", err)
	}
}

// --- unit tests using testfakes (no SQLite) ---

func TestRunWalkList_Empty(t *testing.T) {
	uc := testfakes.NewFakeQueryWalks()
	var buf bytes.Buffer
	err := runWalkList(context.Background(), commonWalkFlags{}, "", "", "", "", "", 20, false, false, uc, &buf, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "no walk records found") {
		t.Errorf("expected empty message, got: %q", buf.String())
	}
}

func TestRunWalkList_WithSummaries(t *testing.T) {
	uc := testfakes.NewFakeQueryWalks()
	coord, _ := fetchdomain.NewModuleCoordinate("example.com/pkg", "v1.0.0")
	uc.SetSummaries([]walkports.WalkSummary{
		{
			ID:            "WALK001",
			Target:        coord,
			StartedAt:     time.Now(),
			OverallStatus: walkdomain.WalkSucceeded,
			NodeCount:     5,
		},
	})

	var buf bytes.Buffer
	err := runWalkList(context.Background(), commonWalkFlags{}, "", "", "", "", "", 20, false, false, uc, &buf, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "WALK001") {
		t.Errorf("expected walk ID in output, got: %q", buf.String())
	}
}

func TestRunWalkList_ByID_NotFound(t *testing.T) {
	uc := testfakes.NewFakeQueryWalks()
	var buf bytes.Buffer
	err := runWalkList(context.Background(), commonWalkFlags{}, "", "", "", "", "MISSING", 20, false, false, uc, &buf, &buf)
	if err == nil {
		t.Fatal("expected error for missing walk")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not-found error, got: %v", err)
	}
}

func TestRunWalkList_ByID_Found(t *testing.T) {
	uc := testfakes.NewFakeQueryWalks()
	coord, _ := fetchdomain.NewModuleCoordinate("example.com/app", "v2.0.0")
	rec := walkdomain.WalkRecord{
		ID:             "WALK002",
		Target:         coord,
		StartedAt:      time.Now(),
		OverallStatus:  walkdomain.WalkSucceeded,
		PerNodeResults: map[fetchdomain.ModuleCoordinate]walkdomain.NodeResult{coord: {Status: walkdomain.NodeSucceeded}},
	}
	uc.AddWalk(rec)

	var buf bytes.Buffer
	err := runWalkList(context.Background(), commonWalkFlags{}, "", "", "", "", "WALK002", 20, false, false, uc, &buf, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "WALK002") {
		t.Errorf("expected walk ID in output, got: %q", buf.String())
	}
}

func TestRunWalkList_ListError(t *testing.T) {
	uc := testfakes.NewFakeQueryWalks()
	uc.ListErr = fmt.Errorf("database offline")
	var buf bytes.Buffer
	err := runWalkList(context.Background(), commonWalkFlags{}, "", "", "", "", "", 20, false, false, uc, &buf, &buf)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRunWalkShow_NotFound(t *testing.T) {
	uc := testfakes.NewFakeQueryWalks()
	var buf bytes.Buffer
	err := runWalkShow(context.Background(), commonWalkFlags{}, "MISSING", uc, &buf)
	if err == nil {
		t.Fatal("expected error")
	}
	var exitErr *exitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected exitError, got: %T %v", err, err)
	}
	if exitErr.code != ExitConfig {
		t.Errorf("expected ExitConfig, got: %d", exitErr.code)
	}
}

func TestRunWalkShow_Found(t *testing.T) {
	uc := testfakes.NewFakeQueryWalks()
	coord, _ := fetchdomain.NewModuleCoordinate("example.com/thing", "v0.1.0")
	rec := walkdomain.WalkRecord{
		ID:             "WALK003",
		Target:         coord,
		StartedAt:      time.Now(),
		OverallStatus:  walkdomain.WalkSucceeded,
		PerNodeResults: map[fetchdomain.ModuleCoordinate]walkdomain.NodeResult{},
	}
	uc.AddWalk(rec)

	var buf bytes.Buffer
	err := runWalkShow(context.Background(), commonWalkFlags{}, "WALK003", uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "WALK003") {
		t.Errorf("expected walk ID in output, got: %q", buf.String())
	}
}

func TestRunWalkDiff_NotFound(t *testing.T) {
	uc := &testfakes.FakeDiffWalks{Err: walkports.ErrWalkNotFound}
	var buf bytes.Buffer
	err := runWalkDiff(context.Background(), commonWalkFlags{}, "A", "B", uc, &buf)
	if err == nil {
		t.Fatal("expected error")
	}
	var exitErr *exitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected exitError, got: %T", err)
	}
	if exitErr.code != ExitConfig {
		t.Errorf("expected ExitConfig, got: %d", exitErr.code)
	}
}

func TestRunWalkDiff_EmptyDiff(t *testing.T) {
	uc := &testfakes.FakeDiffWalks{
		Result: walkapp.WalkDiff{WalkA: "A", WalkB: "B"},
	}
	var buf bytes.Buffer
	err := runWalkDiff(context.Background(), commonWalkFlags{}, "A", "B", uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "diff A..B") {
		t.Errorf("expected diff header, got: %q", buf.String())
	}
}

func TestRunWalkList_InvalidSince(t *testing.T) {
	uc := testfakes.NewFakeQueryWalks()
	var buf bytes.Buffer
	err := runWalkList(context.Background(), commonWalkFlags{}, "", "not-a-time", "", "", "", 20, false, false, uc, &buf, &buf)
	if err == nil {
		t.Fatal("expected error for invalid --since")
	}
	if !strings.Contains(err.Error(), "parsing --since") {
		t.Errorf("expected 'parsing --since' in error, got: %v", err)
	}
}

func TestRunWalkList_InvalidStatus(t *testing.T) {
	uc := testfakes.NewFakeQueryWalks()
	var buf bytes.Buffer
	err := runWalkList(context.Background(), commonWalkFlags{}, "", "", "unknown", "", "", 20, false, false, uc, &buf, &buf)
	if err == nil {
		t.Fatal("expected error for invalid --status")
	}
	if !strings.Contains(err.Error(), "parsing --status") {
		t.Errorf("expected 'parsing --status' in error, got: %v", err)
	}
}

func TestRunWalkList_InvalidTarget(t *testing.T) {
	uc := testfakes.NewFakeQueryWalks()
	var buf bytes.Buffer
	err := runWalkList(context.Background(), commonWalkFlags{}, "badmodule", "", "", "", "", 20, false, false, uc, &buf, &buf)
	if err == nil {
		t.Fatal("expected error for --target without version")
	}
	if !strings.Contains(err.Error(), "invalid target coordinate") {
		t.Errorf("expected 'invalid target coordinate' in error, got: %v", err)
	}
}

func TestWalkListCmd_ToolAndScopeMutuallyExclusive(t *testing.T) {
	t.Cleanup(func() { jsonOut = false })
	var stdout, stderr bytes.Buffer
	err := Run([]string{"walk-list", "--tool", "--scope", "production"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error when both --tool and --scope given")
	}
	if !strings.Contains(err.Error(), "cannot combine --tool and --scope") {
		t.Errorf("expected 'cannot combine --tool and --scope' in error, got: %v", err)
	}
}

func TestRunWalkList_ToolScope_Empty(t *testing.T) {
	prev := jsonOut
	jsonOut = false
	t.Cleanup(func() { jsonOut = prev })
	uc := testfakes.NewFakeQueryWalks()
	var buf bytes.Buffer
	err := runWalkList(context.Background(), commonWalkFlags{}, "", "", "", "tool", "", 20, false, false, uc, &buf, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "no walk records found") {
		t.Errorf("expected empty message, got: %q", buf.String())
	}
}

func TestRunWalkList_ToolScope_FiltersMixedScopes(t *testing.T) {
	uc := testfakes.NewFakeQueryWalks()
	prod, _ := fetchdomain.NewModuleCoordinate("example.com/app", "v1.0.0")
	tool, _ := fetchdomain.NewModuleCoordinate("golang.org/x/tools", "v0.30.0")
	uc.SetSummaries([]walkports.WalkSummary{
		{ID: "PROD001", Target: prod, Scope: walkdomain.WalkScopeCode, OverallStatus: walkdomain.WalkSucceeded},
		{ID: "TOOL001", Target: tool, Scope: walkdomain.WalkScopeTool, OverallStatus: walkdomain.WalkSucceeded},
	})

	var buf bytes.Buffer
	err := runWalkList(context.Background(), commonWalkFlags{}, "", "", "", "tool", "", 20, false, false, uc, &buf, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "TOOL001") {
		t.Errorf("expected tool walk TOOL001 in output, got: %q", out)
	}
	if strings.Contains(out, "PROD001") {
		t.Errorf("unexpected production walk PROD001 in output, got: %q", out)
	}
}

func buildFixtureWalkSummaries(t *testing.T) []walkports.WalkSummary {
	t.Helper()
	app, err := fetchdomain.NewModuleCoordinate("example.com/app", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	startA := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)
	startB := time.Date(2025, 1, 15, 13, 0, 0, 0, time.UTC)
	return []walkports.WalkSummary{
		{
			ID:            "01ARZ3NDEKTSV4RRFFQ69G5FBB",
			Target:        app,
			StartedAt:     startB,
			OverallStatus: walkdomain.WalkSucceeded,
			NodeCount:     3,
			FailureCount:  0,
		},
		{
			ID:            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
			Target:        app,
			StartedAt:     startA,
			OverallStatus: walkdomain.WalkSucceeded,
			NodeCount:     2,
			FailureCount:  0,
		},
	}
}

func TestRunWalkList_TextOutput(t *testing.T) {
	prev := jsonOut
	jsonOut = false
	t.Cleanup(func() { jsonOut = prev })
	uc := testfakes.NewFakeQueryWalks()
	uc.SetSummaries(buildFixtureWalkSummaries(t))
	var buf bytes.Buffer
	err := runWalkList(context.Background(), commonWalkFlags{}, "", "", "", "", "", 20, false, false, uc, &buf, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"01ARZ3NDEKTSV4RRFFQ69G5FBB",
		"01ARZ3NDEKTSV4RRFFQ69G5FAV",
		"example.com/app@v1.0.0",
		"2025-01-15T13:00:00Z",
		"2025-01-15T12:00:00Z",
		"succeeded",
		"nodes=3 failures=0",
		"nodes=2 failures=0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got:\n%s", want, out)
		}
	}
}

func TestRunWalkList_JSONOutput(t *testing.T) {
	jsonOut = true
	t.Cleanup(func() { jsonOut = false })
	uc := testfakes.NewFakeQueryWalks()
	uc.SetSummaries(buildFixtureWalkSummaries(t))
	var buf bytes.Buffer
	err := runWalkList(context.Background(), commonWalkFlags{}, "", "", "", "", "", 20, false, false, uc, &buf, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`"id": "01ARZ3NDEKTSV4RRFFQ69G5FBB"`,
		`"id": "01ARZ3NDEKTSV4RRFFQ69G5FAV"`,
		`"overall_status": "succeeded"`,
		`"target": "example.com/app@v1.0.0"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got:\n%s", want, out)
		}
	}
}

// TestRunWalkList_LatestSuccess_JSONObject guards that the documented
// idiom `walk-list --latest-success --json | jq -r '.id'` must
// receive a single JSON object (so `.id` resolves), not an array — otherwise
// failed/empty fixture walks at index 0 poison $WALK_ID and `extract` dies.
func TestRunWalkList_LatestSuccess_JSONObject(t *testing.T) {
	jsonOut = true
	t.Cleanup(func() { jsonOut = false })
	uc := testfakes.NewFakeQueryWalks()
	uc.SetSummaries(buildFixtureWalkSummaries(t))
	var buf bytes.Buffer
	err := runWalkList(context.Background(), commonWalkFlags{}, "", "", "", "", "", 20, false, true, uc, &buf, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var obj map[string]any
	if uerr := json.Unmarshal(buf.Bytes(), &obj); uerr != nil {
		t.Fatalf("--latest-success must emit a JSON object, got %q: %v", buf.String(), uerr)
	}
	if _, ok := obj["id"]; !ok {
		t.Errorf("object missing \"id\" key: %q", buf.String())
	}
}

// TestRunWalkList_LatestSuccess_NoneErrors guards when there is no
// succeeded walk, --latest-success must fail loudly (non-nil error / non-zero
// exit) rather than emit nothing and let `extract ""` run with an empty ID.
func TestRunWalkList_LatestSuccess_NoneErrors(t *testing.T) {
	uc := testfakes.NewFakeQueryWalks()
	var buf bytes.Buffer
	err := runWalkList(context.Background(), commonWalkFlags{}, "", "", "", "", "", 20, false, true, uc, &buf, &buf)
	if err == nil {
		t.Fatalf("--latest-success with no succeeded walk returned nil error")
	}
}

func TestRunWalkList_FilterStatusSucceeded(t *testing.T) {
	uc := testfakes.NewFakeQueryWalks()
	uc.SetSummaries(buildFixtureWalkSummaries(t))
	var buf bytes.Buffer
	err := runWalkList(context.Background(), commonWalkFlags{}, "", "", "succeeded", "", "", 20, false, false, uc, &buf, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"01ARZ3NDEKTSV4RRFFQ69G5FBB", "01ARZ3NDEKTSV4RRFFQ69G5FAV"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got:\n%s", want, out)
		}
	}
}

func TestRunWalkList_FilterStatusFailed(t *testing.T) {
	uc := testfakes.NewFakeQueryWalks()
	var buf bytes.Buffer
	err := runWalkList(context.Background(), commonWalkFlags{}, "", "", "failed", "", "", 20, false, false, uc, &buf, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "no walk records found") {
		t.Errorf("expected empty message, got: %q", buf.String())
	}
}

func buildFixtureWalkRecordA(t *testing.T) walkdomain.WalkRecord {
	t.Helper()
	app, _ := fetchdomain.NewModuleCoordinate("example.com/app", "v1.0.0")
	dep, _ := fetchdomain.NewModuleCoordinate("example.com/dep", "v1.0.0")
	startA := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)
	outcome := walkdomain.WalkOutcome{
		Target: app,
		Graph: walkdomain.Graph{
			Target: app,
			Nodes:  []walkdomain.GraphNode{{Coordinate: app}, {Coordinate: dep, DirectDependency: true}},
			Edges:  []walkdomain.GraphEdge{{From: app, To: dep, ConstraintVersion: "v1.0.0"}},
		},
		PerNodeResults: map[fetchdomain.ModuleCoordinate]walkdomain.NodeResult{
			app: {Coordinate: app, Status: walkdomain.NodeSucceeded},
			dep: {Coordinate: dep, Status: walkdomain.NodeSucceeded},
		},
		StartedAt:     startA,
		CompletedAt:   startA.Add(time.Second),
		OverallStatus: walkdomain.WalkSucceeded,
	}
	rec := walkdomain.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "fixture", "1.0.0", walkdomain.WalkScopeCode, walkdomain.WalkDepthFull, outcome, walkdomain.DefaultDepthPolicy(), "")
	var hasher walkdomain.WalkRecordHasher
	rec, _ = hasher.SetContentHash(rec)
	return rec
}

func TestRunWalkShow_JSONOutput(t *testing.T) {
	jsonOut = true
	t.Cleanup(func() { jsonOut = false })
	uc := testfakes.NewFakeQueryWalks()
	uc.AddWalk(buildFixtureWalkRecordA(t))
	var buf bytes.Buffer
	err := runWalkShow(context.Background(), commonWalkFlags{}, "01ARZ3NDEKTSV4RRFFQ69G5FAV", uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV"`,
		`"content_hash":"sha256:`,
		`"overall_status":0`,
		`example.com/app`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got:\n%s", want, out)
		}
	}
}

func TestRunWalkDiff_TextOutput(t *testing.T) {
	app, _ := fetchdomain.NewModuleCoordinate("example.com/app", "v1.0.0")
	newDep, _ := fetchdomain.NewModuleCoordinate("example.com/new", "v1.0.0")
	uc := &testfakes.FakeDiffWalks{
		Result: walkapp.WalkDiff{
			WalkA:          "01ARZ3NDEKTSV4RRFFQ69G5FAV",
			WalkB:          "01ARZ3NDEKTSV4RRFFQ69G5FBB",
			Added:          []fetchdomain.ModuleCoordinate{newDep},
			VersionChanged: []walkapp.VersionChange{{Path: "example.com/dep", VersionA: "v1.0.0", VersionB: "v1.1.0"}},
			StatusChanged:  []walkapp.StatusChange{{Coordinate: app, StatusA: walkdomain.NodeSucceeded, StatusB: walkdomain.NodeSucceeded}},
		},
	}
	var buf bytes.Buffer
	err := runWalkDiff(context.Background(), commonWalkFlags{}, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FBB", uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"diff 01ARZ3NDEKTSV4RRFFQ69G5FAV..01ARZ3NDEKTSV4RRFFQ69G5FBB",
		"+ example.com/new@v1.0.0",
		"~ example.com/dep: v1.0.0 -> v1.1.0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got:\n%s", want, out)
		}
	}
}

func TestRunWalkDiff_JSONOutput(t *testing.T) {
	jsonOut = true
	t.Cleanup(func() { jsonOut = false })
	newDep, _ := fetchdomain.NewModuleCoordinate("example.com/new", "v1.0.0")
	uc := &testfakes.FakeDiffWalks{
		Result: walkapp.WalkDiff{
			WalkA:          "01ARZ3NDEKTSV4RRFFQ69G5FAV",
			WalkB:          "01ARZ3NDEKTSV4RRFFQ69G5FBB",
			Added:          []fetchdomain.ModuleCoordinate{newDep},
			VersionChanged: []walkapp.VersionChange{{Path: "example.com/dep", VersionA: "v1.0.0", VersionB: "v1.1.0"}},
		},
	}
	var buf bytes.Buffer
	err := runWalkDiff(context.Background(), commonWalkFlags{}, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FBB", uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`"walk_a": "01ARZ3NDEKTSV4RRFFQ69G5FAV"`,
		`"walk_b": "01ARZ3NDEKTSV4RRFFQ69G5FBB"`,
		`"example.com/new@v1.0.0"`,
		`"module": "example.com/dep"`,
		`"from": "v1.0.0"`,
		`"to": "v1.1.0"`,
		`"license_regressions": []`,
		`"new_reachable_cves": []`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got:\n%s", want, out)
		}
	}
}

func TestParseWalkScope_Valid(t *testing.T) {
	cases := []struct {
		input string
		want  walkdomain.WalkScope
	}{
		{"code", walkdomain.WalkScopeCode},
		{"CODE", walkdomain.WalkScopeCode},
		{"tool", walkdomain.WalkScopeTool},
		{"Tool", walkdomain.WalkScopeTool},
		{"complete", walkdomain.WalkScopeComplete},
		{"Complete", walkdomain.WalkScopeComplete},
	}
	for _, tc := range cases {
		got, err := parseWalkScope(tc.input)
		if err != nil {
			t.Errorf("parseWalkScope(%q): unexpected error: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseWalkScope(%q): got %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestParseWalkScope_Invalid(t *testing.T) {
	_, err := parseWalkScope("unknown")
	if err == nil {
		t.Fatal("expected error for unknown scope")
	}
	if !strings.Contains(err.Error(), "unknown scope") {
		t.Errorf("expected 'unknown scope' in error, got: %v", err)
	}
}

func TestIsWalkIntegrity(t *testing.T) {
	if !isWalkIntegrity(walkports.ErrWalkIntegrity) {
		t.Error("expected true for ErrWalkIntegrity")
	}
	if isWalkIntegrity(errors.New("other error")) {
		t.Error("expected false for unrelated error")
	}
}
