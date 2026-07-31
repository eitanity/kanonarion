package staticcha

import (
	"context"
	"errors"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// toolchainProbe reports whether the Go toolchain the analysis is about to use —
// or has just failed to use — can be run at all. A nil error means it answered.
//
// It is a package variable so a test can install a deterministic outcome; the
// production implementation is runGoVersionProbe.
var toolchainProbe = runGoVersionProbe

// runGoVersionProbe asks the go command on PATH to state its own version.
//
// The command is deliberately the cheapest possible question that still requires
// a working toolchain: no module, no network, no build cache. It resolves "go"
// through PATH rather than through a.goBinary because that is precisely what
// go/packages does, so the probe fails exactly when the load failed for
// environmental reasons — a shim that resolves but has no version behind it is
// the reproduction that motivated the whole axis, and naming the binary directly
// would have stepped around it.
//
// It must be called while the analysis PATH is still in force (i.e. before
// setupGoEnv's cleanup runs), or it would answer about a different environment
// from the one that failed.
func runGoVersionProbe(ctx context.Context) error {
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

// classifyLoadFailure decides whether a failure raised by the package loader is
// a fact about the module or about the run.
//
// The two are genuinely indistinguishable from the error text — "exit status 1"
// with the toolchain's stderr attached covers both a module whose go.sum does
// not cover its own module graph and a PATH whose go is a shim with no version
// behind it — so this does not try to read them apart. It asks the one question
// that separates them and that the module cannot influence: can this environment
// run the Go toolchain at all?
//
// If it cannot, nothing was measured about the module and the record must not be
// served back. If it can, the loader ran and reported about the module, and the
// failure is a finding worth caching.
//
// This is the classification the ticket for this axis calls "at the boundary,
// where the go/packages error is still a value rather than prose": the decision
// is made here, once, at the moment of failure, and travels on the record. No
// later reader re-derives it from a string.
func (a *Analyser) classifyLoadFailure(ctx context.Context) domain.FailureCause {
	// A cancelled or expired context is environmental on its own terms, and would
	// also make the probe fail for a reason that says nothing about the toolchain.
	if ctx.Err() != nil {
		return domain.FailureCauseEnvironment
	}
	if err := toolchainProbe(ctx); err != nil {
		a.logger.WarnContext(ctx, "callgraph_toolchain_unusable",
			slog.String("error", err.Error()),
		)
		return domain.FailureCauseEnvironment
	}
	return domain.FailureCauseModule
}
