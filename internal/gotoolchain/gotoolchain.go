// Package gotoolchain names the Go toolchain that produced a stored record.
//
// Three ledgers record answers the Go toolchain decides — the call graph it
// builds, the public API its release tags select, the vulnerability verdict it
// compiles the module for — and the version that decided them is a fact about
// the record, not about the host reading it. Naming it here rather than three
// times keeps one rendering of "not recorded" across the three read surfaces.
package gotoolchain

import (
	"fmt"
	"regexp"
	"strings"
)

// Version is a Go toolchain version in `go env GOVERSION` form ("go1.26.6").
//
// It is a DIMENSION, not a ladder. Two toolchains' answers for one coordinate
// are both correct and neither supersedes the other, so composition groups on it
// and never picks between two values by recency or by completeness.
type Version string

// Unrecorded is the zero value: the record does not say which toolchain produced
// it. See the ladder rule in each ledger's composition for how it is read.
const Unrecorded Version = ""

// Recorded reports whether the record named a toolchain at all.
func (v Version) Recorded() bool { return v != Unrecorded }

// String renders the version, showing the zero value as "not recorded" rather
// than as a blank a reader would take for an absence of toolchain.
func (v Version) String() string {
	if v == Unrecorded {
		return "not recorded"
	}
	return string(v)
}

// versionForm is the shape of a released toolchain's version: "go" and then the
// number, which is what `go env GOVERSION` reports and what a toolchain module's
// own version states.
var versionForm = regexp.MustCompile(`^go[0-9][0-9a-z.]*$`)

// ParseVersion reads a toolchain version a person wrote, refusing anything no
// record could hold.
//
// A stated version is only ever compared against what records say, so a value
// outside this form matches nothing and would sit in a config file resolving
// nothing. A bare "1.26.6" and a GOROOT path are both things people type, and
// refusing them while the operator is typing is the whole point.
func ParseVersion(s string) (Version, error) {
	if !versionForm.MatchString(s) {
		return Unrecorded, fmt.Errorf(
			"%q is not a Go toolchain version in `go env GOVERSION` form (e.g. go1.26.6)", s)
	}
	return Version(s), nil
}

// toolchainModuleRoot matches the GOROOT of a toolchain downloaded as a module,
// whose module version states the Go version exactly:
// ".../golang.org/toolchain@v0.0.1-go1.26.6.linux-amd64".
var toolchainModuleRoot = regexp.MustCompile(`golang\.org/toolchain@v[0-9.]+-(go[0-9][0-9a-z.]*)\.[a-z0-9]+-[a-z0-9]+$`)

// FromGOROOT reports the toolchain version a GOROOT path states, and whether it
// states one at all.
//
// A toolchain fetched as a module carries its Go version in its own module
// version, so the path IS the version. Every other GOROOT — /usr/local/go and
// the like — is a LOCATION: the toolchain installed there is upgraded in place,
// so the path says where the stdlib came from and never which version it was.
// Returning false for those is the point; guessing a version from a directory
// name is the fabrication this whole axis exists to stop.
func FromGOROOT(root string) (Version, bool) {
	m := toolchainModuleRoot.FindStringSubmatch(strings.TrimSuffix(root, "/"))
	if m == nil {
		return Unrecorded, false
	}
	return Version(m[1]), true
}
