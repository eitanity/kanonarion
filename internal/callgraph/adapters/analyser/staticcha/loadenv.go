package staticcha

import "os"

// isolatedModuleEnv is the process environment for loading packages from an
// extracted module directory.
//
// A published module zip may contain a go.work at its root — a workspace the
// author uses for development, listing sibling modules (test harnesses, fuzz
// targets, generated-code checkouts) that are not part of the published module
// and are therefore absent from the zip. Loading with the ambient environment
// lets the toolchain discover that file and enter workspace mode, at which point
// it fails trying to open sibling go.mod files that do not exist, and the whole
// module records as a load failure with an empty call graph.
//
// A module is analysed in isolation as its own main module, so any workspace it
// ships is dev-time configuration that does not apply here, exactly as its own
// filesystem replace directives do not. GOWORK=off is appended last because a
// duplicate key resolves to its final value, so it also overrides an inherited
// GOWORK pointing at the invoking user's workspace.
//
// This applies only to extracted module directories. A local working-tree
// analysis must keep honouring the project's own go.work: there the workspace is
// the real build configuration rather than a stale artefact of packaging.
func isolatedModuleEnv() []string {
	return append(os.Environ(), "GOWORK=off")
}
