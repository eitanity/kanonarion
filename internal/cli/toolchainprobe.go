package cli

import (
	"context"
	"errors"
	"os/exec"
	"strings"
)

// goToolchainVersionProbe asks the go command on PATH to state its own version.
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
func goToolchainVersionProbe(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "go", "env", "GOVERSION").CombinedOutput() // #nosec G204 -- fixed command and arguments; the binary is resolved through the analysis PATH by design
	if err != nil {
		return err //nolint:wrapcheck // the error is classified, never rendered
	}
	if strings.TrimSpace(string(out)) == "" {
		// The command succeeded and said nothing. A toolchain that cannot name its
		// own version is not one an analysis can be trusted to have run against.
		return errEmptyToolchainVersion
	}
	return nil
}

// errEmptyToolchainVersion is returned by the probe when the go command exits
// zero without naming a version.
var errEmptyToolchainVersion = errors.New("go env GOVERSION produced no version")
