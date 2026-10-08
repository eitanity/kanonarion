package domain

import (
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// NotFetchedRemedy names the command that puts coord's artefact in the store,
// for a diagnostic that has just found no fetch record for it.
//
// The remedy is decided by where the module's source is, not by which stage
// asked. A local coordinate names no published version, so the proxy fetch that
// serves every other module can never reach it; the project's own working tree
// enters the store through a root-ingesting walk instead. The standard library
// is the same shape one step further out: `fetch` rejects the coordinate
// outright — "stdlib" is not a module path — so naming it is advice that cannot
// be taken, and what records the standard library is a walk's custody chain.
func NotFetchedRemedy(coord coordinate.ModuleCoordinate) string {
	if coord.IsLocal() {
		return "run 'kanonarion walk --gomod ./go.mod --analyse-root' from the project's tree first"
	}
	if coord.IsStdlib() {
		return "the standard library arrives with the toolchain rather than through the module proxy, " +
			"so there is nothing to fetch; run 'kanonarion walk --gomod ./go.mod' from the project's tree " +
			"to record its chain of custody"
	}
	return fmt.Sprintf("run 'kanonarion fetch %s' first", coord)
}
