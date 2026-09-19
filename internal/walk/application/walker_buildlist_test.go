package application_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	domain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"

	application2 "github.com/eitanity/kanonarion/internal/walk/application"
)

// walkBuildListProject runs one project walk whose build list resolves the way
// bl says, with every node fetchable, so the only thing that can make the walk
// anything but clean is the build list itself.
func walkBuildListProject(t *testing.T, bl walkports.BuildListResolver, resolutionDir string) domain.WalkOutcome {
	t.Helper()
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(t, "example.com/dep", "v1.0.0", "module example.com/dep\ngo 1.21\n", blobs)

	wf := newWalkerFetcher()
	wf.addRecord(t, "example.com/dep", "v1.0.0")

	w := buildWalkerWithBuildList(rf, wf, blobs, bl)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target:          coord("example.com/project", coordinate.LocalVersion),
		ProjectMode:     true,
		MainModuleGoMod: []byte(resolutionDirGoMod),
		ProjectDir:      "/work/project",
		ResolutionDir:   resolutionDir,
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	return outcome
}

// TestWalker_BuildListUnavailable_IsRecordedIncomplete is the defect: every node
// fetched cleanly, so nothing in the per-node results is anything but succeeded,
// and the module set is still the go.mod require directives rather than the
// modules that compile. The walk must not report succeeded.
func TestWalker_BuildListUnavailable_IsRecordedIncomplete(t *testing.T) {
	bl := &fakeBuildListResolver{err: errors.New(
		"go list -m -mod=readonly -json all: exit status 1\n" +
			"go: example.com/dep@v1.0.0: missing go.sum entry for go.mod file")}

	outcome := walkBuildListProject(t, bl, "/work/project")

	if outcome.OverallStatus != domain.WalkPartial {
		t.Errorf("overall status = %s, want partial", outcome.OverallStatus)
	}
	if !strings.Contains(outcome.Graph.BuildListUnavailable, "missing go.sum entry") {
		t.Errorf("Graph.BuildListUnavailable = %q, want the toolchain's own reason",
			outcome.Graph.BuildListUnavailable)
	}
	if outcome.Graph.PartialReason != domain.BuildListUnavailableReason {
		t.Errorf("PartialReason = %q, want %q",
			outcome.Graph.PartialReason, domain.BuildListUnavailableReason)
	}
	// Every node still came back clean: the degradation is about the set, not
	// about any member of it, and a reader must not be able to find it by
	// counting failures.
	for c, r := range outcome.PerNodeResults {
		if r.Status != domain.NodeSucceeded {
			t.Errorf("node %s status = %s, want succeeded", c, r.Status)
		}
	}
}

// TestWalker_BuildListResolves_StaysClean is the control: the same project with
// a working toolchain is untouched by any of this.
func TestWalker_BuildListResolves_StaysClean(t *testing.T) {
	bl := &fakeBuildListResolver{list: oneDepBuildList()}

	outcome := walkBuildListProject(t, bl, "/work/project")

	if outcome.OverallStatus != domain.WalkSucceeded {
		t.Errorf("overall status = %s, want succeeded", outcome.OverallStatus)
	}
	if outcome.Graph.BuildListUnavailable != "" {
		t.Errorf("BuildListUnavailable = %q, want empty", outcome.Graph.BuildListUnavailable)
	}
	if outcome.Graph.Partial {
		t.Errorf("graph should not be partial: %s", outcome.Graph.PartialReason)
	}
}

// TestWalker_NoResolutionDir_IsApproximateNotAToolchainFailure guards the other
// caller of the same fallback: a driver that names no resolution directory never
// asks the toolchain at all. That is not a toolchain FAILURE — nothing is quoted
// on the graph, and the exit message must not blame one — but the module set is
// still the internal resolver's approximation of the build, so the walk is
// recorded incomplete like any other approximate set.
func TestWalker_NoResolutionDir_IsApproximateNotAToolchainFailure(t *testing.T) {
	bl := &fakeBuildListResolver{list: oneDepBuildList()}

	outcome := walkBuildListProject(t, bl, "")

	if outcome.Graph.BuildListUnavailable != "" {
		t.Errorf("BuildListUnavailable = %q, want empty when no directory was named",
			outcome.Graph.BuildListUnavailable)
	}
	if !strings.Contains(outcome.Graph.PartialReason, "build_list_approximate") {
		t.Errorf("PartialReason = %q, want the approximate-set reason", outcome.Graph.PartialReason)
	}
	if outcome.OverallStatus != domain.WalkPartial {
		t.Errorf("overall status = %s, want partial: the set is an approximation of the build",
			outcome.OverallStatus)
	}
}

// TestWalker_BuildListUnavailable_DoesNotOutrankAWorseStatus: a walk that failed
// outright keeps its own status. An incomplete graph is a downgrade from clean,
// never an upgrade from broken.
func TestWalker_BuildListUnavailable_DoesNotOutrankAWorseStatus(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher() // example.com/dep is absent: its fetch fails

	wf := newWalkerFetcher()
	bl := &fakeBuildListResolver{err: errors.New("go: toolchain unavailable")}

	w := buildWalkerWithBuildList(rf, wf, blobs, bl)
	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target:          coord("example.com/project", coordinate.LocalVersion),
		ProjectMode:     true,
		MainModuleGoMod: []byte(resolutionDirGoMod),
		ProjectDir:      "/work/project",
		ResolutionDir:   "/work/project",
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if outcome.OverallStatus != domain.WalkPartial {
		t.Errorf("overall status = %s, want partial", outcome.OverallStatus)
	}
	if !strings.Contains(outcome.Graph.PartialReason, "fetch_failed") {
		t.Errorf("PartialReason = %q, want it to keep the fetch failure too",
			outcome.Graph.PartialReason)
	}
}

// oneDepBuildList is the toolchain answer for resolutionDirGoMod: the project
// and the one module it requires.
func oneDepBuildList() walkports.BuildList {
	return walkports.BuildList{
		Modules: []walkports.BuildListModule{
			{Path: "example.com/project", Main: true},
			{Path: "example.com/dep", Version: "v1.0.0"},
		},
		Edges: []walkports.BuildListEdge{
			{From: "example.com/project", To: "example.com/dep@v1.0.0"},
		},
	}
}
