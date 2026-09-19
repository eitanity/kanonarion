package goenv

import (
	"fmt"
	"runtime"
	"strings"
)

// Target is the platform an analysis is about, as the invocation declares it.
//
// It is the third statement in the separation (*Toolchains).Apply already names:
// the posture says what the child may do, the toolchain says which Go does it,
// and this says which platform it does it for. All three are layered onto a
// freshly built environment rather than folded into one, so each stays legible
// on its own.
//
// The zero value declares nothing, which is NOT the same as declaring the host.
// The difference is only ever visible to a reader — Apply writes the host pair
// for an undeclared target, because a child that is told the pair cannot be told
// a different one by the environment this process happens to have inherited.
// Declared reports which of the two a value is, for the callers that record or
// filter on a declaration rather than on a platform.
type Target struct {
	goos   string
	goarch string
}

// hostTarget is measured once, from the running binary. runtime rather than
// `go env GOOS` is the authority on purpose: `go env` answers about the
// environment it is run in, which is the very thing a declared target exists to
// stop deciding this. The running binary's own platform is the one fact about
// the host that no export can move.
var hostTarget = Target{goos: runtime.GOOS, goarch: runtime.GOARCH}

// Host is the platform this process is running on.
func Host() Target { return hostTarget }

// NewTarget is a declared pair. Both halves are required: half a pair is a
// declaration whose other half would be taken from the environment, which is
// the shape this type exists to remove.
func NewTarget(goos, goarch string) (Target, error) {
	switch {
	case goos == "" && goarch == "":
		return Target{}, fmt.Errorf("a build target names both halves: GOOS and GOARCH")
	case goos == "":
		return Target{}, fmt.Errorf("GOARCH=%s was declared without a GOOS; name both halves or neither", goarch)
	case goarch == "":
		return Target{}, fmt.Errorf("GOOS=%s was declared without a GOARCH; name both halves or neither", goos)
	}
	return Target{goos: goos, goarch: goarch}, nil
}

// ParseTarget reads the canonical "GOOS/GOARCH" spelling — the one `go tool dist
// list` prints and the one the docs use.
func ParseTarget(pair string) (Target, error) {
	goos, goarch, ok := strings.Cut(strings.TrimSpace(pair), "/")
	if !ok {
		return Target{}, fmt.Errorf("build target %q is not GOOS/GOARCH (for example linux/amd64)", pair)
	}
	return NewTarget(strings.TrimSpace(goos), strings.TrimSpace(goarch))
}

// GOOS is the declared target operating system, empty when nothing was declared.
func (t Target) GOOS() string { return t.goos }

// GOARCH is the declared target architecture, empty when nothing was declared.
func (t Target) GOARCH() string { return t.goarch }

// Declared reports whether this value names a platform at all.
func (t Target) Declared() bool { return t.goos != "" && t.goarch != "" }

// OrHost is the platform a child will actually be run for: the declaration when
// there is one, and the measured host otherwise.
func (t Target) OrHost() Target {
	if t.Declared() {
		return t
	}
	return hostTarget
}

// IsHost reports whether this target resolves to the platform this process runs
// on. An undeclared target does.
func (t Target) IsHost() bool { return t.OrHost() == hostTarget }

// String renders the pair the way `go tool dist list` prints it and the way a
// refusal has to name it. An undeclared target says so rather than rendering as
// half a pair.
func (t Target) String() string {
	if !t.Declared() {
		return "undeclared"
	}
	return t.goos + "/" + t.goarch
}

// Apply returns env as a child resolving for this target must see it: the pair
// written explicitly, last, so exec and the go command both resolve it to the
// value stated here.
//
// An undeclared target applies the measured host, and that is the whole of how
// the inherited pair stops reaching a resolution. Before this, no resolving
// child set GOOS at all, so an export in the operator's shell chose the platform
// every walk, scope list and scan was about, and the record named the result
// without naming the cause. Writing the pair on every such child either way
// means the platform an analysis is about is always one the invocation stated.
//
// Appended rather than rewritten in place: a repeated key resolves to its last
// value for the go command and for exec, which is how every other value in these
// environments is set.
func (t Target) Apply(env []string) []string {
	r := t.OrHost()
	return append(env[:len(env):len(env)], "GOOS="+r.goos, "GOARCH="+r.goarch)
}

// PostureTarget is the pair the declared-target posture is stated against. The
// producer under test is called with this value so the table and the assertion
// cannot drift apart, on the same terms as ModCache.
//
// It is a real pair rather than a sentinel because the posture assertions share
// their producers with tests that run a go command, and a GOOS the toolchain
// does not know refuses before it resolves anything. It is deliberately not this
// host's: a producer that dropped the declaration and left the ambient pair in
// place would then pass.
var PostureTarget = Target{goos: "plan9", goarch: "386"}
