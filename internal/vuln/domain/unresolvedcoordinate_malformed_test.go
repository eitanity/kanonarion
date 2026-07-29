package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestUnresolvedCoordinate_MalformedVersionNamesNoModule covers the leg where a
// line survives every shape check and the constructor still refuses it.
//
// The shape checks narrow a GOPROXY=off line to something that looks like a
// coordinate — a trailing token with an "@", a version starting with "v", no
// path separator or colon in the version. A token that passes all of them and
// still carries a malformed version is not a module this scan failed to
// resolve, so it must yield no coordinate rather than one no downstream lookup
// could ever match.
func TestUnresolvedCoordinate_MalformedVersionNamesNoModule(t *testing.T) {
	const marker = ": module lookup disabled by GOPROXY=off"

	coord, ok := domain.UnresolvedCoordinate("example.com/mod@v1.2.3" + marker)
	if !ok {
		t.Fatalf("a well-formed line yielded no coordinate")
	}
	if coord.String() != "example.com/mod@v1.2.3" {
		t.Fatalf("got %s, want example.com/mod@v1.2.3", coord)
	}

	for _, line := range []string{
		"example.com/mod@vNOTSEMVER" + marker,
		"example.com/mod@v1.2.3.4.5" + marker,
	} {
		if got, ok := domain.UnresolvedCoordinate(line); ok {
			t.Errorf("UnresolvedCoordinate(%q) = %s, true; a malformed version names no module", line, got)
		}
	}
}
