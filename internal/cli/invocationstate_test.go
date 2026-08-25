package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/config/domain"
)

// The process-wide state a command leaves behind must not be readable by the
// next command in the same process.
//
// One process runs one command in production, so none of this is reachable
// there. The golden harness runs the whole command set in one binary, and a
// case that inherits an earlier case's fetch mode is a case that can pass for
// the wrong reason — or, as happened once, invert its own exit code.
//
// The tests below come in two kinds and the difference matters:
//
//   - Discriminators. They plant a previous invocation's value, run a command,
//     and fail unless the value is gone. Each one fails without the reset.
//   - Controls. They record that the flag-BOUND variables were already safe,
//     because StringVar/BoolVar assign the flag's default at registration and
//     newRootCmd registers every flag on every invocation. These pass either
//     way; they exist so a later change that registers a flag once, lazily,
//     is caught rather than assumed away.

// staleInvocationState plants the state a previous command would have left and
// restores the package to a clean slate afterwards.
func staleInvocationState(t *testing.T) {
	t.Helper()
	cfg, cfgErr := activeConfig, activeConfigErr
	t.Cleanup(func() {
		modcacheMode, modcacheDir, goSumPath, projectGoSumPath = false, "", "", ""
		activeConfig, activeConfigErr = cfg, cfgErr
	})
}

// A previous `audit --from-modcache` puts modcacheMode, modcacheDir and
// goSumPath in place. Three commands call resolveModcacheMode; every command
// builds a Container that reads those variables. The reset is what makes the
// forty-odd that never see the flag run on the network path they asked for.
func TestRun_ModcacheModeDoesNotSurviveIntoTheNextCommand(t *testing.T) {
	staleInvocationState(t)

	// The previous command, run for real rather than simulated by assigning the
	// variables: whatever else this audit does, it passes through
	// resolveModcacheMode and leaves the process in module-cache mode.
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "go.mod"), []byte("module example.com/previous\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(project, "go.sum"), nil, 0o600); err != nil {
		t.Fatalf("write go.sum: %v", err)
	}
	cache := t.TempDir()
	var primeOut, primeErr bytes.Buffer
	_ = Run([]string{"audit", "--gomod", filepath.Join(project, "go.mod"),
		"--from-modcache=" + cache, "--store-root", t.TempDir()}, &primeOut, &primeErr)
	if !modcacheMode {
		t.Fatalf("the priming audit never entered module-cache mode, so this test proves nothing\nstderr:\n%s",
			primeErr.String())
	}

	var stdout, stderr bytes.Buffer
	err := Run([]string{"walk-list", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("a command that never named --from-modcache took the module-cache path: %v\nstderr:\n%s",
			err, stderr.String())
	}
	if modcacheMode || modcacheDir != "" || goSumPath != "" {
		t.Errorf("module-cache state survived the invocation: mode=%v dir=%q goSum=%q",
			modcacheMode, modcacheDir, goSumPath)
	}
}

// projectGoSumPath decides which go.sum anchors checksum verification on the
// normal network path. Inherited, a command verifies this project's modules
// against the previous project's checksums.
func TestRun_ProjectGoSumDoesNotSurviveIntoTheNextCommand(t *testing.T) {
	staleInvocationState(t)

	// The previous command, run for real: an audit of a project that has a
	// go.sum beside its go.mod.
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "go.mod"), []byte("module example.com/previous\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(project, "go.sum"), nil, 0o600); err != nil {
		t.Fatalf("write go.sum: %v", err)
	}
	var primeOut, primeErr bytes.Buffer
	_ = Run([]string{"audit", "--gomod", filepath.Join(project, "go.mod"),
		"--store-root", t.TempDir()}, &primeOut, &primeErr)
	if projectGoSumPath == "" {
		t.Fatalf("the priming audit never anchored on its own go.sum, so this test proves nothing\nstderr:\n%s",
			primeErr.String())
	}

	var stdout, stderr bytes.Buffer
	err := Run([]string{"walk-list", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("a command with no go.mod of its own anchored on a previous project's go.sum: %v\nstderr:\n%s",
			err, stderr.String())
	}
	if projectGoSumPath != "" {
		t.Errorf("projectGoSumPath = %q after an unrelated command, want empty", projectGoSumPath)
	}
}

// --help and --version are answered before any PersistentPreRunE, so the config
// the previous command loaded is never overwritten on that path. The reset runs
// at construction for that reason.
func TestRun_ConfigDoesNotSurviveOntoThePathThatSkipsPreRun(t *testing.T) {
	staleInvocationState(t)
	activeConfigErr = errors.New("a previous store's config file was rejected")

	var stdout, stderr bytes.Buffer
	if err := Run([]string{"--help"}, &stdout, &stderr); err != nil {
		t.Fatalf("--help: %v", err)
	}
	if activeConfigErr != nil {
		t.Errorf("activeConfigErr = %v after an unrelated invocation, want nil", activeConfigErr)
	}
}

// Discriminator at the resolver: an absent go.sum must mean "no local anchor",
// not "keep the last one".
func TestResolveProjectGoSum_AbsentGoSumClearsAPreviousProjectsPath(t *testing.T) {
	staleInvocationState(t)
	previous := filepath.Join(t.TempDir(), "previous-project", "go.sum")
	projectGoSumPath = previous

	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module x\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	// No go.sum beside it.
	resolveProjectGoSum(gomod)
	if projectGoSumPath != "" {
		t.Errorf("projectGoSumPath = %q, want empty; this project has no go.sum", projectGoSumPath)
	}
}

// Same at the --from-modcache early return, where go.sum is threaded through
// goSumPath instead and the normal-path variable must not be left behind.
func TestResolveProjectGoSum_ModcacheModeClearsAPreviousProjectsPath(t *testing.T) {
	staleInvocationState(t)
	projectGoSumPath = filepath.Join(t.TempDir(), "previous-project", "go.sum")
	modcacheMode = true

	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module x\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), nil, 0o600); err != nil {
		t.Fatalf("write go.sum: %v", err)
	}
	resolveProjectGoSum(gomod)
	if projectGoSumPath != "" {
		t.Errorf("projectGoSumPath = %q, want empty in --from-modcache mode", projectGoSumPath)
	}
}

// Control, not a discriminator. Every flag-bound package variable is re-assigned
// its default by StringVar/BoolVar when newRootCmd registers the flag, which it
// does on every invocation. That is why --allow-verification-downgrade is not in
// the class the reset exists for. It is asserted rather than argued so that
// registering one of these flags lazily — inside a RunE, or once per process —
// shows up here.
func TestRun_FlagBoundStateIsResetWhenTheFlagIsRegistered(t *testing.T) {
	storeWas, levelWas, jsonWas, downgradeWas := storeRoot, logLevel, jsonOut, allowVerificationDowngrade
	t.Cleanup(func() {
		storeRoot, logLevel, jsonOut, allowVerificationDowngrade = storeWas, levelWas, jsonWas, downgradeWas
	})

	stale := filepath.Join(t.TempDir(), "previous-store")
	storeRoot, logLevel, jsonOut, allowVerificationDowngrade = stale, "debug", true, true

	var stdout, stderr bytes.Buffer
	if err := Run([]string{"--help"}, &stdout, &stderr); err != nil {
		t.Fatalf("--help: %v", err)
	}
	if storeRoot == stale {
		t.Errorf("storeRoot kept the previous invocation's %q", stale)
	}
	if logLevel != "warn" {
		t.Errorf("logLevel = %q, want the registered default %q", logLevel, "warn")
	}
	if jsonOut {
		t.Error("jsonOut stayed true, want the registered default false")
	}
	if allowVerificationDowngrade {
		t.Error("allowVerificationDowngrade stayed true, want the registered default false")
	}
}

// Control for the reset's own value: a fresh invocation starts on the built-in
// defaults, which is what a store with no config file loads — not the zero
// Config, whose thresholds are all zero.
func TestResetInvocationState_StartsFromTheBuiltInDefaults(t *testing.T) {
	staleInvocationState(t)
	resetInvocationState()
	if activeConfig.Preferences.LogLevel != domain.DefaultConfig().Preferences.LogLevel {
		t.Errorf("activeConfig is not the built-in defaults: %+v", activeConfig.Preferences)
	}
}
