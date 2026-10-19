package application

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// A local replacement at its local identity, and a go.work member, are scanned
// through the build as the root is; only a local-replace node recorded under
// the published coordinate, never read from disk, goes to the unscannable set.
func TestSplitLocalReplaceNodes_LocalIdentityIsScanned(t *testing.T) {
	root := coordinatetest.MustNew("example.com/a", coordinate.LocalVersion)
	replaced := coordinatetest.MustNew("example.com/c", coordinate.LocalVersion)
	member := coordinatetest.MustNew("example.com/b", coordinate.LocalVersion)
	legacy := coordinatetest.MustNew("example.com/old", "v1.0.0")
	walk := walkdomain.WalkRecord{Target: root, Graph: walkdomain.Graph{Target: root, Nodes: []walkdomain.GraphNode{
		{Coordinate: root, ResolutionSource: walkdomain.ResolutionLocalMainModule},
		{Coordinate: replaced, ResolutionSource: walkdomain.ResolutionLocalReplace, OriginalCoordinate: coordinatetest.MustNew("example.com/c", "v1.2.3")},
		{Coordinate: member, ResolutionSource: walkdomain.ResolutionLocalWorkspaceMember},
		{Coordinate: legacy, ResolutionSource: walkdomain.ResolutionLocalReplace, LocalPath: "../old"},
	}}}

	scanned, unscannable := splitLocalReplaceNodes(walk)
	in := map[coordinate.ModuleCoordinate]bool{}
	for _, c := range scanned {
		in[c] = true
	}
	for _, c := range []coordinate.ModuleCoordinate{root, replaced, member} {
		if !in[c] {
			t.Errorf("%s is not scanned", c)
		}
	}
	if in[legacy] || len(unscannable) != 1 || unscannable[0].Coordinate != legacy {
		t.Errorf("unscannable = %v, want only %s", unscannable, legacy)
	}
}
