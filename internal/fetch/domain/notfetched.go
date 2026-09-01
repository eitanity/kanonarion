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
// enters the store through a root-ingesting walk instead.
func NotFetchedRemedy(coord coordinate.ModuleCoordinate) string {
	if coord.IsLocal() {
		return "run 'kanonarion walk --gomod ./go.mod --analyse-root' from the project's tree first"
	}
	return fmt.Sprintf("run 'kanonarion fetch %s' first", coord)
}
