package staticcha

import (
	"context"
	"log/slog"
	"strings"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

// ToolchainProbe asks the Go toolchain the analysis is about to use — or has
// just failed to use — to name itself. A nil error means it answered, and the
// string is its `go env GOVERSION`.
//
// One question answers two: whether the environment can run the toolchain at all
// (which classifies a load failure) and which toolchain it is (which the record
// states). Asking them separately would be two subprocesses answering about one
// environment, and nothing would hold them to the same answer.
//
// dir is the directory the load it is being asked about ran in. A toolchain is
// resolved per directory — a version manager reads a version file from the tree
// it is invoked in — so a probe that answered from anywhere else would be
// answering about a different toolchain from the one that ran.
//
// env is the environment the load itself was given, and passing it is not
// optional. Every analysis environment pins GOTOOLCHAIN=local; a probe left to
// inherit the process environment auto-switches to whatever the tree's go
// directive asks for and names a toolchain the loader never ran. Measured: an
// analysis that failed with "requires go >= 1.26.6 (running go 1.26.5)" recorded
// go1.26.6, which is the fabrication this whole axis exists to stop.
type ToolchainProbe func(ctx context.Context, dir string, env []string) (string, error)

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
// It names no version: a seam that invented one would put a toolchain on every
// record written by a suite that never ran a toolchain at all.
func assumeUsableToolchain(context.Context, string, []string) (string, error) { return "", nil }

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
func (a *Analyser) classifyLoadFailure(ctx context.Context, dir string, env []string) domain.FailureCause {
	// A cancelled or expired context is environmental on its own terms, and would
	// also make the probe fail for a reason that says nothing about the toolchain.
	if ctx.Err() != nil {
		return domain.FailureCauseEnvironment
	}
	if _, err := toolchainProbe(ctx, dir, env); err != nil {
		a.logger.WarnContext(ctx, "callgraph_toolchain_unusable",
			slog.String("dir", dir),
			slog.String("error", err.Error()),
		)
		return domain.FailureCauseEnvironment
	}
	return domain.FailureCauseModule
}

// offlineLookupMarker is what the go command says when a module it needs is
// absent from the local cache and it is not permitted to fetch one.
const offlineLookupMarker = "module lookup disabled by GOPROXY=off"

// isOfflineCacheMiss reports whether a load failure is the analyser's own
// offline posture meeting a cold module cache.
//
// A pinned synthesis runs with GOPROXY=off so a version nobody chose can never
// enter the graph. That guarantee has a cost the record must attribute
// correctly: minimal version selection reads the go.mod of every module in the
// transitive requirement graph, and one absent from GOMODCACHE fails the load
// with this marker. The bytes are fine and the module is fine; the HOST is
// missing a file. Filing it as the module's fault would make it cacheable, and a
// warm cache tomorrow would never get the chance to answer.
//
// It matches on the go command's own sentence because that is the only place the
// distinction exists: go/packages returns the driver's stderr as prose, and the
// classification has to be made here, at the boundary, rather than re-derived by
// a later reader.
func isOfflineCacheMiss(detail string) bool {
	return strings.Contains(detail, offlineLookupMarker)
}

// isToolchainTooOld reports whether a load failed because the module asks for a
// newer Go than the one running: "go.mod requires go >= X (running go Y)".
//
// The probe cannot see it — the go command runs, reads the directive and
// refuses — so unmatched it files as the module's fault, which is cacheable.
// Both halves are required so a module quoting the phrase cannot match.
func isToolchainTooOld(detail string) bool {
	return strings.Contains(detail, " requires go >= ") && strings.Contains(detail, "(running go ")
}

// probeToolchainVersion names the toolchain this analysis is running under, or
// the zero value when it could not be established.
//
// A failure is not reported: the analysis itself is what is being run, and a
// record that cannot say which toolchain built it is a record that says so. The
// classification path asks the same question again on the failure route, where
// the error is the answer being sought.
func probeToolchainVersion(ctx context.Context, dir string, env []string) gotoolchain.Version {
	v, err := toolchainProbe(ctx, dir, env)
	if err != nil {
		return gotoolchain.Unrecorded
	}
	return gotoolchain.Version(strings.TrimSpace(v))
}
