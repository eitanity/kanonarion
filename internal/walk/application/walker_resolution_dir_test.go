package application_test

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	application2 "github.com/eitanity/kanonarion/internal/walk/application"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// countingBuildListResolver records how many times the Go toolchain would have
// been asked for the authoritative build list.
type countingBuildListResolver struct {
	calls atomic.Int64
	list  walkports.BuildList
}

func (c *countingBuildListResolver) Resolve(_ context.Context, _ string) (walkports.BuildList, error) {
	c.calls.Add(1)
	return c.list, nil
}

func buildWalkerWithBuildList(rf *fakeModuleFetcher, wf *walkerFakeFetcher, blobs *fakeBlobStore, bl walkports.BuildListResolver) *application2.Walker {
	resolver := application2.NewGraphResolver(
		newXmodParser(), rf, blobs,
		fixedClock{fixedNow}, "",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	).WithBuildListResolver(bl)
	return application2.NewWalker(
		resolver, wf, nil,
		fixedClock{fixedNow}, fakeStopwatch{},
		1, slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
}

const resolutionDirGoMod = `module example.com/project

go 1.21

require example.com/dep v1.0.0
`

// TestWalker_RecordedProjectDirDoesNotGrantResolutionAuthority is the regression
// test for the two meanings that used to share one field: recording where a walk
// happened must not decide who resolves its module set. A project-rooted walk
// that names its directory but leaves resolution authority unset is still served
// by the internal resolver, exactly as an unset directory was before.
func TestWalker_RecordedProjectDirDoesNotGrantResolutionAuthority(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(t, "example.com/dep", "v1.0.0", "module example.com/dep\ngo 1.21\n", blobs)
	wf := newWalkerFetcher()
	wf.addRecord(t, "example.com/dep", "v1.0.0")

	bl := &countingBuildListResolver{list: sampleBuildList()}
	w := buildWalkerWithBuildList(rf, wf, blobs, bl)

	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target:          coord("example.com/project", coordinate.LocalVersion),
		ProjectMode:     true,
		MainModuleGoMod: []byte(resolutionDirGoMod),
		ProjectDir:      "/work/project",
		// ResolutionDir deliberately empty: the internal resolver keeps the walk.
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if got := bl.calls.Load(); got != 0 {
		t.Errorf("build list consulted %d times, want 0 — an empty ResolutionDir must select the internal resolver", got)
	}
	if _, ok := outcome.PerNodeResults[coord("example.com/dep", "v1.0.0")]; !ok {
		t.Error("the internal resolver did not resolve the go.mod require entry")
	}
}

// TestWalker_ResolutionDirRoutesThroughTheToolchain pins the other half: naming a
// resolution directory is what hands the toolchain build list the last word.
func TestWalker_ResolutionDirRoutesThroughTheToolchain(t *testing.T) {
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	wf := newWalkerFetcher()

	bl := &countingBuildListResolver{list: sampleBuildList()}
	w := buildWalkerWithBuildList(rf, wf, blobs, bl)

	if _, err := w.Walk(context.Background(), application2.WalkRequest{
		Target:          coord("example.com/project", coordinate.LocalVersion),
		ProjectMode:     true,
		MainModuleGoMod: []byte(resolutionDirGoMod),
		ProjectDir:      "/work/project",
		ResolutionDir:   "/work/project",
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if got := bl.calls.Load(); got != 1 {
		t.Errorf("build list consulted %d times, want 1", got)
	}
}
