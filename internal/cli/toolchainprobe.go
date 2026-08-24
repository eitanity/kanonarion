package cli

import (
	"context"
	"errors"
	"os/exec"
	"strings"
)

// goToolchainVersionProbe asks the go command on PATH to state its own version,
// and returns it.
//
// It is the production implementation of the staticcha analyser's toolchain
// probe, wired in by the container: the analyser is an extraction package and
// must not carry process-spawning capability itself, so the one command it
// needs the environment to answer lives here, at the composition root.
//
// The command is deliberately the cheapest possible question that still requires
// a working toolchain: no module, no network, no build cache. It resolves "go"
// through PATH rather than through the analyser's configured binary because
// that is precisely what go/packages does, so the probe fails exactly when the
// load failed for environmental reasons — a shim that resolves but has no
// version behind it is the reproduction that motivated the whole axis, and
// naming the binary directly would have stepped around it.
//
// It runs in dir, the directory the loader was pointed at. A version manager
// resolves the toolchain from a version file in the tree it is invoked in, so a
// probe left to inherit the CLI process's own working directory can report a
// usable toolchain for a load that had none.
func goToolchainVersionProbe(ctx context.Context, dir string, env []string) (string, error) {
	cmd := exec.CommandContext(ctx, "go", "env", "GOVERSION") // #nosec G204 -- fixed command and arguments; the binary is resolved through the analysis PATH by design
	cmd.Dir = dir
	// The loader's own environment, which pins GOTOOLCHAIN=local. Inheriting this
	// process's instead lets the probe switch toolchains where the loader could
	// not, and answer about one that never ran. A nil env means the caller has
	// none to offer and the process's is the honest answer.
	if env != nil {
		cmd.Env = env
	}
	// Output, not CombinedOutput: the version is now the answer rather than a
	// liveness signal, and a toolchain that writes a warning to stderr would
	// otherwise have it recorded as part of its own version string.
	out, err := cmd.Output()
	if err != nil {
		return "", err //nolint:wrapcheck // the error is classified, never rendered
	}
	version := strings.TrimSpace(string(out))
	if version == "" {
		// The command succeeded and said nothing. A toolchain that cannot name its
		// own version is not one an analysis can be trusted to have run against.
		return "", errEmptyToolchainVersion
	}
	return version, nil
}

// errEmptyToolchainVersion is returned by the probe when the go command exits
// zero without naming a version.
var errEmptyToolchainVersion = errors.New("go env GOVERSION produced no version")
