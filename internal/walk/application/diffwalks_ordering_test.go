package application

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/walk/domain"
)

// assertOrders checks that less decides a pair differing in exactly one field,
// in both directions, and reports an element equal to itself.
func assertOrders[T any](t *testing.T, key string, less func(a, b T) bool, lower, upper T) {
	t.Helper()
	if !less(lower, upper) {
		t.Errorf("%s: the comparator does not order two elements differing only in this field", key)
	}
	if less(upper, lower) {
		t.Errorf("%s: the comparator is not antisymmetric", key)
	}
	if less(lower, lower) {
		t.Errorf("%s: the comparator reports an element less than itself", key)
	}
}

// TestDiffOrdering_IsKeyedOnEveryField exercises the walk-diff comparators
// against every field their elements carry.
//
// The version changes are the ones that matter: they are keyed on the COMPILED
// path while their identity is the require path, so a replace can put two
// entries under one path, and a comparator stopping there would hand their
// order to map iteration.
func TestDiffOrdering_IsKeyedOnEveryField(t *testing.T) {
	t.Parallel()

	must := func(path, version string) coordinate.ModuleCoordinate {
		t.Helper()
		c, err := coordinate.NewModuleCoordinate(path, version)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	a := must("example.com/a", "v1.0.0")
	b := must("example.com/b", "v1.0.0")
	a2 := must("example.com/a", "v2.0.0")

	assertOrders(t, "coordinate.path", coordinateLess, a, b)
	assertOrders(t, "coordinate.version", coordinateLess, a, a2)

	assertOrders(t, "version_change.path", versionChangeLess,
		VersionChange{Path: "a"}, VersionChange{Path: "b"})
	assertOrders(t, "version_change.version_a", versionChangeLess,
		VersionChange{VersionA: "v1"}, VersionChange{VersionA: "v2"})
	assertOrders(t, "version_change.version_b", versionChangeLess,
		VersionChange{VersionB: "v1"}, VersionChange{VersionB: "v2"})

	assertOrders(t, "status_change.coordinate.path", statusChangeLess,
		StatusChange{Coordinate: a}, StatusChange{Coordinate: b})
	assertOrders(t, "status_change.coordinate.version", statusChangeLess,
		StatusChange{Coordinate: a}, StatusChange{Coordinate: a2})
	assertOrders(t, "status_change.status_a", statusChangeLess,
		StatusChange{StatusA: domain.NodeSucceeded}, StatusChange{StatusA: domain.NodeSucceeded + 1})
	assertOrders(t, "status_change.status_b", statusChangeLess,
		StatusChange{StatusB: domain.NodeSucceeded}, StatusChange{StatusB: domain.NodeSucceeded + 1})
}
