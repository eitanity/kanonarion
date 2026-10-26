package domain

import (
	"fmt"
	"sync/atomic"

	"code.eitanity.com/kanonarion/internal/coordinate"
)

// privateRule names the module paths GOPRIVATE/GONOPROXY makes private. The
// domain cannot read the environment, so the entry points install the rule.
var privateRule atomic.Pointer[func(path string) bool]

// SetPrivateModuleRule installs the rule NotFetchedRemedy uses to name the
// route a private module takes; nil removes it.
func SetPrivateModuleRule(isPrivate func(path string) bool) {
	if isPrivate == nil {
		privateRule.Store(nil)
		return
	}
	privateRule.Store(&isPrivate)
}

// PrivateModuleRemedy is the fetch that works for a private module: one run
// from the project that requires it, so its go.sum can verify the bytes.
func PrivateModuleRemedy(coord coordinate.ModuleCoordinate) string {
	return fmt.Sprintf("run 'kanonarion fetch %s --gomod <path to the project's go.mod>' from the project that requires it "+
		"(a private module is verified against its go.sum)", coord)
}

// NotFetchedRemedy names the command that puts coord's artefact in the store,
// for a diagnostic that has just found no fetch record for it.
//
// The remedy is decided by where the module's source is, not by which stage
// asked. A local coordinate names no published version, so the proxy fetch that
// serves every other module can never reach it; the project's own working tree
// enters the store through a root-ingesting walk instead. The standard library
// has no route: `fetch` rejects the coordinate, and a walk records its custody
// chain but no artefact these stages read, so no invocation is named.
func NotFetchedRemedy(coord coordinate.ModuleCoordinate) string {
	if coord.IsLocal() {
		return "run 'kanonarion walk --gomod ./go.mod --analyse-root' from the project's tree first"
	}
	if coord.IsStdlib() {
		return "the standard library arrives with the toolchain rather than through the module proxy, " +
			"and this build does not extract this record from it"
	}
	if rule := privateRule.Load(); rule != nil && (*rule)(coord.Path()) {
		return PrivateModuleRemedy(coord)
	}
	return fmt.Sprintf("run 'kanonarion fetch %s' first", coord)
}
