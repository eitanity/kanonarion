package domain_test

import (
	"testing"

	domain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// TestStdlibNode_UnusableToolchainVersion covers the leg where the toolchain
// string normalises to something that is not a version.
//
// A development toolchain reports "devel …" rather than "go1.26.4", which
// NormaliseStdlibVersion turns into "vdevel" — non-empty, so it clears the
// existing guard, and not a version, so the coordinate constructor refuses it.
// The node is skipped on the same terms as an undeterminable toolchain: an
// injected stdlib node at a version that does not exist would be scanned and
// reported against for advisories it cannot be compared to.
func TestStdlibNode_UnusableToolchainVersion(t *testing.T) {
	if node, ok := domain.StdlibNode("go1.26.4"); !ok {
		t.Fatalf("a real toolchain version yielded no stdlib node")
	} else if node.Coordinate.String() != "stdlib@v1.26.4" {
		t.Fatalf("got %s, want stdlib@v1.26.4", node.Coordinate)
	}

	for _, goVersion := range []string{"devel", "go", "  "} {
		node, ok := domain.StdlibNode(goVersion)
		if ok {
			t.Errorf("StdlibNode(%q) = %s, true; an unusable toolchain version must yield no node", goVersion, node.Coordinate)
		}
		if !node.Coordinate.IsZero() {
			t.Errorf("StdlibNode(%q) returned coordinate %s, want the zero node", goVersion, node.Coordinate)
		}
	}
}
