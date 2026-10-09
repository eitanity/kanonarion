package cli

import (
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// TestWalkModules_ListsTheBuildListAJoinLoadsGraphsFor: the standard library
// and the walk's own tree are left out, and a local replace is marked.
func TestWalkModules_ListsTheBuildListAJoinLoadsGraphsFor(t *testing.T) {
	walks := testfakes.NewFakeQueryWalks()
	walks.AddWalk(walkdomain.WalkRecord{ID: "w1", Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{
		{Coordinate: coordinatetest.MustNew("example.com/app", coordinate.LocalVersion)},
		{Coordinate: coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.6"), ResolutionSource: walkdomain.ResolutionStdlib},
		{Coordinate: coordinatetest.MustNew("example.com/wrap", "v0.0.0"), ResolutionSource: walkdomain.ResolutionLocalReplace},
		{Coordinate: coordinatetest.MustNew("golang.org/x/mod", "v0.41.0"), ResolutionSource: walkdomain.ResolutionMVS},
	}}})
	r := walkProjectDirs{walks: walks}

	mods, ok, err := r.WalkModules(t.Context(), "w1")
	if err != nil || !ok || len(mods) != 2 || !mods[0].LocalReplace || mods[1].LocalReplace ||
		mods[1].Coordinate.String() != "golang.org/x/mod@v0.41.0" {
		t.Errorf("WalkModules = %+v, %v, %v; want wrap (local replace) and x/mod", mods, ok, err)
	}
	if _, ok, err := r.WalkModules(t.Context(), "absent"); ok || err != nil {
		t.Errorf("an unknown walk -> %v, %v; want not found and no error", ok, err)
	}
	if _, ok, err := (walkProjectDirs{}).WalkModules(t.Context(), "w1"); ok || err != nil {
		t.Errorf("no walk store -> %v, %v; want not found and no error", ok, err)
	}
	walks.GetErr = errors.New("disk on fire")
	if _, _, err := r.WalkModules(t.Context(), "w1"); err == nil {
		t.Error("a store fault was not returned")
	}
}
