package staticcha

import (
	"context"
	"log/slog"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// ToolchainProbe reports whether the Go toolchain the analysis is about to use —
// or has just failed to use — can be run at all. A nil error means it answered.
//
// dir is the directory the load it is being asked about ran in. A toolchain is
// resolved per directory — a version manager reads a version file from the tree
// it is invoked in — so a probe that answered from anywhere else would be
// answering about a different toolchain from the one that failed.
type ToolchainProbe func(ctx context.Context, dir string) error

// toolchainProbe is the probe classifyLoadFailure consults. It defaults to
// assumeUsableToolchain and is replaced by the composition root via
// SetToolchainProbe: this package is an extraction package and must not carry
// process-spawning capability itself (the restricted-imports gate enforces
// that), so the implementation that actually shells out to the toolchain lives
// with the caller that wires the analyser.
//
// It is a package variable so a test can install a deterministic outcome.
var toolchainProbe ToolchainProbe = assumeUsableToolchain

// SetToolchainProbe installs the probe classifyLoadFailure consults. It is
// called once by the composition root; the probe must be callable while the
// analysis PATH is still in force (i.e. before setupGoEnv's cleanup runs), or
// it would answer about a different environment from the one that failed.
func SetToolchainProbe(fn ToolchainProbe) {
	if fn != nil {
		toolchainProbe = fn
	}
}

// assumeUsableToolchain is the zero seam: with no probe wired, the environment
// is assumed able to run the toolchain, and a load failure files as a fact
// about the module. That is the classification a real probe returns wherever
// the suite itself runs; a composition root that wants environment failures
// told apart must wire a real probe.
func assumeUsableToolchain(context.Context, string) error { return nil }

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
// The question is asked about dir — the directory the loader was pointed at, not
// wherever the process happens to be running. A version manager resolves the
// toolchain from a version file in the tree it is invoked in, so a probe asked
// from the caller's own working directory can report a usable toolchain for a
// load that had none, and the run's failure is then filed as the module's
// property and cached forever.
//
// This is the classification the ticket for this axis calls "at the boundary,
// where the go/packages error is still a value rather than prose": the decision
// is made here, once, at the moment of failure, and travels on the record. No
// later reader re-derives it from a string.
func (a *Analyser) classifyLoadFailure(ctx context.Context, dir string) domain.FailureCause {
	// A cancelled or expired context is environmental on its own terms, and would
	// also make the probe fail for a reason that says nothing about the toolchain.
	if ctx.Err() != nil {
		return domain.FailureCauseEnvironment
	}
	if err := toolchainProbe(ctx, dir); err != nil {
		a.logger.WarnContext(ctx, "callgraph_toolchain_unusable",
			slog.String("dir", dir),
			slog.String("error", err.Error()),
		)
		return domain.FailureCauseEnvironment
	}
	return domain.FailureCauseModule
}
