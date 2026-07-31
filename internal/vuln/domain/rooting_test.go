package domain

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

func mustRootingCoord(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate(%q, %q): %v", path, version, err)
	}
	return c
}

// A nil reachability answer has more than one cause and only the frame can say
// which. IsRootedAt is what separates "nobody asked for reachability" from "the
// module was its own root, so there was no consumer entry point" — the two
// absences that a single message conflated, sending an operator who HAD passed
// --reachability to pass it again.
func TestRootingIsRootedAt(t *testing.T) {
	self := mustRootingCoord(t, "github.com/golang-jwt/jwt/v4", "v4.5.1")
	other := mustRootingCoord(t, "example.com/app", "v1.0.0")
	sameVersionDifferentPath := mustRootingCoord(t, "github.com/golang-jwt/jwt/v5", "v4.5.1")
	samePathDifferentVersion := mustRootingCoord(t, "github.com/golang-jwt/jwt/v4", "v4.5.2")

	for _, tc := range []struct {
		name    string
		rooting Rooting
		coord   coordinate.ModuleCoordinate
		want    bool
	}{
		{name: "rooted at itself", rooting: TargetRootedAt(self), coord: self, want: true},
		{name: "rooted at a consumer", rooting: TargetRootedAt(other), coord: self},
		{name: "another version of the same path", rooting: TargetRootedAt(samePathDifferentVersion), coord: self},
		{name: "another path at the same version", rooting: TargetRootedAt(sameVersionDifferentPath), coord: self},
		{
			// "target-rooted, root unstated" states that some target was the
			// root without saying which. Reading it as this coordinate would
			// assert a root the record never recorded.
			name: "bare target-rooted names no target", rooting: RootingTargetRooted, coord: self,
		},
		{name: "isolated", rooting: RootingIsolated, coord: self},
		{name: "unrecorded", rooting: RootingUnrecorded, coord: self},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rooting.IsRootedAt(tc.coord); got != tc.want {
				t.Errorf("Rooting(%q).IsRootedAt(%s) = %v, want %v", tc.rooting, tc.coord, got, tc.want)
			}
		})
	}
}
