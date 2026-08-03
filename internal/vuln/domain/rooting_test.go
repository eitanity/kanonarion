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

// A working tree declares a module path and no version — a main module has none
// in a Go build — while the walks that scanned it recorded a root coordinate
// carrying whatever version the walk assigned. The path is therefore what the
// tree's own frame is recognised by.
func TestRootingIsRootedAtPath(t *testing.T) {
	app := "example.com/app"

	for _, tc := range []struct {
		name    string
		rooting Rooting
		path    string
		want    bool
	}{
		{name: "local root", rooting: TargetRootedAt(mustRootingCoord(t, app, "local")), path: app, want: true},
		{name: "tagged root", rooting: TargetRootedAt(mustRootingCoord(t, app, "v1.2.3")), path: app, want: true},
		{name: "different path", rooting: TargetRootedAt(mustRootingCoord(t, "example.com/other", "local")), path: app},
		{
			// A path that extends the root's is a different module, and the cut at
			// "@" is what keeps it one.
			name: "submodule of the root path", rooting: TargetRootedAt(mustRootingCoord(t, app+"/sub", "local")), path: app,
		},
		{name: "bare target-rooted names no target", rooting: RootingTargetRooted, path: app},
		{name: "isolated", rooting: RootingIsolated, path: app},
		{name: "unrecorded", rooting: RootingUnrecorded, path: app},
		{name: "empty path matches nothing", rooting: TargetRootedAt(mustRootingCoord(t, app, "local")), path: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rooting.IsRootedAtPath(tc.path); got != tc.want {
				t.Errorf("Rooting(%q).IsRootedAtPath(%q) = %v, want %v", tc.rooting, tc.path, got, tc.want)
			}
		})
	}
}
