package staticcha

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// TestIsolatedModuleEnv_DisablesWorkspaceMode is the regression guard for
// modules that ship a go.work in their published zip. Left in workspace mode the
// loader tries to open sibling go.mod files that are not in the zip, and the
// module is stored as a load failure with an empty call graph — its reachability
// and capability results silently degraded for a packaging artefact rather than
// anything about the module's own code.
func TestIsolatedModuleEnv_DisablesWorkspaceMode(t *testing.T) {
	env := isolatedModuleEnv()

	if !slices.Contains(env, "GOWORK=off") {
		t.Fatal("isolatedModuleEnv must disable workspace mode for an extracted module directory")
	}
}

// TestIsolatedModuleEnv_OverridesInheritedWorkspace guards that an ambient GOWORK
// pointing at the invoking user's workspace cannot leak into an isolated module
// analysis. The Go toolchain resolves a duplicate key to its last value, so the
// override must come after anything inherited.
func TestIsolatedModuleEnv_OverridesInheritedWorkspace(t *testing.T) {
	t.Setenv("GOWORK", "/home/dev/go.work")

	env := isolatedModuleEnv()

	last := ""
	for _, kv := range env {
		if strings.HasPrefix(kv, "GOWORK=") {
			last = kv
		}
	}
	if last != "GOWORK=off" {
		t.Errorf("effective GOWORK = %q, want GOWORK=off to win over the inherited workspace", last)
	}
}

// TestIsolatedModuleEnv_PreservesAmbientEnvironment guards that disabling
// workspace mode does not discard the rest of the environment — the loader still
// needs PATH, HOME and the caller's GOMODCACHE/GOFLAGS to resolve anything.
func TestIsolatedModuleEnv_PreservesAmbientEnvironment(t *testing.T) {
	t.Setenv("KANONARION_LOADENV_PROBE", "present")

	env := isolatedModuleEnv()

	if len(env) < len(os.Environ()) {
		t.Errorf("env has %d entries, want at least the ambient %d", len(env), len(os.Environ()))
	}
	if !slices.Contains(env, "KANONARION_LOADENV_PROBE=present") {
		t.Error("ambient environment variables must survive")
	}
}
