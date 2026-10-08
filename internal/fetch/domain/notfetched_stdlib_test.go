package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
)

// TestNotFetchedRemedy_NeverNamesFetchForTheStandardLibrary is the whole class
// in one assertion: `fetch` rejects "stdlib" before it reaches the proxy —
// "malformed module path: missing dot in first path element" — so naming it is
// advice that cannot be taken however often it is run.
func TestNotFetchedRemedy_NeverNamesFetchForTheStandardLibrary(t *testing.T) {
	t.Parallel()

	coord, err := coordinate.NewStdlibCoordinateAt("v1.26.5")
	if err != nil {
		t.Fatalf("stdlib coordinate: %v", err)
	}
	got := domain.NotFetchedRemedy(coord)
	if strings.Contains(got, "kanonarion fetch") {
		t.Errorf("the remedy names a command that refuses this coordinate: %s", got)
	}
	if !strings.Contains(got, "kanonarion walk") {
		t.Errorf("the remedy names no command that records the standard library: %s", got)
	}
}

// TestNotFetchedRemedy_StillNamesFetchForAPublishedModule is the control: the
// stdlib branch must not widen into one that leaves every module without a
// remedy.
func TestNotFetchedRemedy_StillNamesFetchForAPublishedModule(t *testing.T) {
	t.Parallel()

	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	if got := domain.NotFetchedRemedy(coord); !strings.Contains(got, "kanonarion fetch example.com/mod@v1.0.0") {
		t.Errorf("the remedy for a published module no longer names the fetch: %s", got)
	}
}
