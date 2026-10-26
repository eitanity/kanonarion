package application

import (
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"

	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// The TinyGo node has no fetched module artefact, so every stage skips it with
// a reason rather than failing on a fetch record nobody owed.
func TestUnfetchableReason_TinyGoNode(t *testing.T) {
	node := walkdomain.GraphNode{
		Coordinate:       coordinatetest.MustNew(walkdomain.TinyGoModulePath, "v0.42.0"),
		ResolutionSource: walkdomain.ResolutionTinyGo,
	}
	reason, skip := unfetchableReason(node)
	if !skip || !strings.Contains(reason, "TinyGo") {
		t.Errorf("unfetchableReason = (%q, %t), want a TinyGo skip", reason, skip)
	}
}
