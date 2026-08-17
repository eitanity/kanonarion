package cli

import (
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/clock"
	staleports "github.com/eitanity/kanonarion/internal/staleness/ports"
)

// cliClock is the wall clock every CLI-layer time question goes through.
//
// The CLI reads the wall clock in four places — the age of a release, the age
// of a served ledger lookup, the age of a walk named in a note, and the TTL a
// recorded staleness lookup is judged against — and each of them puts a value
// derived from "now" into what a command prints. That makes the output of those
// commands a function of the moment they ran, which is fine for an operator and
// fatal for a recorded copy of the output: a golden holding "1272 days" is
// wrong tomorrow.
//
// One package-level clock rather than a parameter on each of the four call
// sites: the alternative threads a clock through renderers that otherwise have
// no reason to know what time it is, and a renderer that takes a clock is a
// renderer someone will pass time.Now to.
var cliClock staleports.Clock = clock.System{}

// cliNow is the current instant as the CLI sees it.
func cliNow() time.Time { return cliClock.Now() }

// cliSince is how long ago t was, as the CLI sees it. It replaces time.Since at
// every CLI call site whose result is printed.
func cliSince(t time.Time) time.Duration { return cliNow().Sub(t) }

// SetClockForTest pins the CLI's wall clock to at, and returns the function
// that restores the system clock.
//
// It is exported because the golden-output tests live outside this package: a
// recorded copy of a command's output can only be compared against a later run
// if every "now" the command consulted is the same in both. Nothing in the
// operating path calls it, and the production default is the system clock, so
// a build that never runs a test never leaves it.
func SetClockForTest(at time.Time) (restore func()) {
	previous := cliClock
	cliClock = clock.Fixed{T: at.UTC()}
	return func() { cliClock = previous }
}
