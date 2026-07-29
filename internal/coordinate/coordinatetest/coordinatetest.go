// Package coordinatetest builds module coordinates for tests. Import it from
// any test in the module that needs a coordinate as a fixture; it is a normal
// package rather than a _test one for the same reason internal/fetch/fetchtest
// is.
//
// It exists because ModuleCoordinate's fields are unexported: a test can no
// longer write a struct literal, and the validating constructor returns an
// error that a fixture line has no useful way to handle. MustNew panics
// instead, which in a test is a failure with a stack trace pointing at the bad
// fixture — the outcome an error check would have produced anyway, without the
// three lines.
//
// It takes no testing.TB deliberately. Coordinates are built in table-driven
// test cases and package-level vars where no testing handle is in scope, and
// requiring one there would push tests into init-time indirection to satisfy a
// helper. The cost is that a panic here is attributed to the test that first
// touches the fixture rather than to the fixture's own line.
//
// Nothing in the production tree may import this package: it is the one place
// that turns an invalid coordinate into a panic rather than an error, which is
// acceptable in a test and never acceptable in a running pipeline.
package coordinatetest

import (
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// MustNew returns the coordinate for path and version, panicking if it is not
// a valid one. Use it wherever a test needs a coordinate that is a fixture
// rather than the subject; a test whose subject is the validation itself
// should call coordinate.NewModuleCoordinate and assert on the error.
func MustNew(path, version string) coordinate.ModuleCoordinate {
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		panic(fmt.Sprintf("coordinatetest: invalid coordinate %s@%s: %v", path, version, err))
	}
	return c
}

// PathOnly returns the versionless coordinate naming path, panicking if path
// is empty. It is for the tests whose subject is a coordinate that pins no
// content — a `go mod graph` main-module endpoint or a wildcard replace target.
func PathOnly(path string) coordinate.ModuleCoordinate {
	c, err := coordinate.NewPathOnlyCoordinate(path)
	if err != nil {
		panic(fmt.Sprintf("coordinatetest: invalid path-only coordinate %q: %v", path, err))
	}
	return c
}
